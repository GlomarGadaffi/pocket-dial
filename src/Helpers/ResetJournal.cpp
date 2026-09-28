#include "ResetJournal.hpp"

#include <atomic>
#include <cstddef>
#include <cstring>
#include <mutex>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "PsramTask.hpp"   // PD_ASSERT_NOT_PSRAM_STACK: #277/#480, see load()/store()
#else
#include <iostream>
#endif

namespace resetjournal
{
namespace
{
	constexpr uint32_t kMagic   = 0x4A524450u;   // "PDRJ"
	constexpr uint8_t  kVersion = 1;

	// 16 bytes, CRC over the first 12.
	struct Record
	{
		uint32_t magic;
		uint8_t  version;
		uint8_t  stage;
		uint8_t  failedMask;
		uint8_t  reserved;
		uint32_t seq;
		uint32_t crc;
	};
	static_assert(sizeof(Record) == 16, "Record is a fixed on-flash layout");

	uint32_t crc32(const uint8_t* p, size_t n)
	{
		uint32_t c = 0xFFFFFFFFu;
		for (size_t i = 0; i < n; ++i)
		{
			c ^= p[i];
			for (int k = 0; k < 8; ++k) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
		}
		return ~c;
	}

	Record make(Stage stage, uint8_t mask, uint32_t seq)
	{
		Record r{};
		r.magic = kMagic;
		r.version = kVersion;
		r.stage = static_cast<uint8_t>(stage);
		r.failedMask = mask;
		r.seq = seq;
		r.crc = crc32(reinterpret_cast<const uint8_t*>(&r), offsetof(Record, crc));
		return r;
	}

	enum class Read { Absent, Valid, Garbage };

	Read decode(const Record& r)
	{
		const uint8_t* b = reinterpret_cast<const uint8_t*>(&r);
		bool allFF = true;
		for (size_t i = 0; i < sizeof(r); ++i) allFF = allFF && b[i] == 0xFF;
		if (allFF) return Read::Absent;   // erased flash
		if (r.magic != kMagic || r.version != kVersion ||
			r.crc != crc32(b, offsetof(Record, crc)))
			return Read::Garbage;
		if (r.stage != static_cast<uint8_t>(Stage::Begun) && r.stage != static_cast<uint8_t>(Stage::Failed))
			return Read::Garbage;
		return Read::Valid;
	}

	std::atomic<uint8_t>& ramMask()
	{
		static std::atomic<uint8_t> m{0};
		return m;
	}

	// Journal writes that failed (begin/finish), for /api/status.
	std::atomic<uint32_t>& writeFailures()
	{
		static std::atomic<uint32_t> n{0};
		return n;
	}

	// ── Backends ─────────────────────────────────────────────────────────────
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	constexpr const char* TAG = "ResetJournal";
	constexpr size_t kSector = 0x1000;

	RTC_NOINIT_ATTR Record s_rtcRecord;

	// The last sector of `prompts`, or nullptr if this layout has none.
	const esp_partition_t* journalPartition(size_t& offset)
	{
		static const esp_partition_t* p = esp_partition_find_first(
			ESP_PARTITION_TYPE_DATA, static_cast<esp_partition_subtype_t>(0x40), "prompts");
		if (p && p->size >= kSector) offset = p->size - kSector;
		return (p && p->size >= kSector) ? p : nullptr;
	}

	Storage backend()
	{
		size_t off = 0;
		return journalPartition(off) ? Storage::Flash : Storage::Rtc;
	}

	// Flash backend primitives: slot i of the journal sector (see loadSlots()).
	bool slotRead(size_t i, Record& out)
	{
		size_t off = 0;
		const esp_partition_t* p = journalPartition(off);
		return p && esp_partition_read(p, off + i * sizeof(Record), &out, sizeof(out)) == ESP_OK;
	}
	bool slotWrite(size_t i, const Record& r)
	{
		size_t off = 0;
		const esp_partition_t* p = journalPartition(off);
		return p && esp_partition_write(p, off + i * sizeof(Record), &r, sizeof(r)) == ESP_OK;
	}
	bool sectorErase()
	{
		size_t off = 0;
		const esp_partition_t* p = journalPartition(off);
		return p && esp_partition_erase_range(p, off, kSector) == ESP_OK;
	}

	Read loadSlots(Record& out);
	bool storeSlots(const Record* r);

	Read load(Record& out)
	{
		// #481 review: a flash op from a PSRAM-stacked task is the #273 panic,
		// and #480 is moving tasks to PSRAM -- fail loudly here instead.
		PD_ASSERT_NOT_PSRAM_STACK();
		if (backend() == Storage::Flash) return loadSlots(out);
		out = s_rtcRecord;
		// Uninitialised RTC memory after a power cycle is random: for this
		// backend anything that does not validate is simply "no record".
		const Read r = decode(out);
		return r == Read::Valid ? Read::Valid : Read::Absent;
	}

	bool store(const Record* r)   // nullptr = erase
	{
		PD_ASSERT_NOT_PSRAM_STACK();   // see load()
		if (backend() == Storage::Flash) return storeSlots(r);
		if (r) s_rtcRecord = *r;
		else std::memset(&s_rtcRecord, 0, sizeof(s_rtcRecord));
		return true;
	}

	void warn(const char* msg) { ESP_LOGW(TAG, "%s", msg); }
#else
	// The host models the flash sector: kSlots records, 0xFF when erased.
	Record s_hostSlots[0x1000 / sizeof(Record)];
	bool   s_hostErased = false;   // lazily: static init order vs. first use
	bool   s_hostFailNextWrite = false;

	Storage backend() { return Storage::Flash; }   // host models the flash backend

	bool sectorErase()
	{
		std::memset(s_hostSlots, 0xFF, sizeof(s_hostSlots));
		s_hostErased = true;
		return true;
	}
	bool slotRead(size_t i, Record& out)
	{
		if (!s_hostErased) sectorErase();
		out = s_hostSlots[i];
		return true;
	}
	bool slotWrite(size_t i, const Record& r)
	{
		if (s_hostFailNextWrite) { s_hostFailNextWrite = false; return false; }
		if (!s_hostErased) sectorErase();
		s_hostSlots[i] = r;
		return true;
	}

	Read loadSlots(Record& out);
	bool storeSlots(const Record* r);
	Read load(Record& out) { return loadSlots(out); }
	bool store(const Record* r) { return storeSlots(r); }

	void warn(const char* msg) { std::cerr << "[W] ResetJournal: " << msg << std::endl; }

	void (*s_loadHook)() = nullptr;
#endif

	// #595 item 2: the flash journal is APPEND-ONLY within its sector. A write
	// goes to the first erased 16-byte slot and the newest record is the last
	// written slot, so a record is never erased before the one replacing it is
	// on flash -- a crash mid-write leaves the previous record (or a torn,
	// Unreadable one), never "clean". Only a clean finish() erases the sector.
	constexpr size_t kSlots = 0x1000 / sizeof(Record);   // 256

	// Index of the first erased slot (kSlots if the sector is full), or -1 on a
	// read error.
	long firstFreeSlot()
	{
		Record r{};
		for (size_t i = 0; i < kSlots; ++i)
		{
			if (!slotRead(i, r)) return -1;
			if (decode(r) == Read::Absent) return static_cast<long>(i);
		}
		return static_cast<long>(kSlots);
	}

	Read loadSlots(Record& out)
	{
		const long n = firstFreeSlot();
		if (n < 0) return Read::Garbage;
		if (n == 0) { std::memset(&out, 0xFF, sizeof(out)); return Read::Absent; }
		if (!slotRead(static_cast<size_t>(n - 1), out)) return Read::Garbage;
		return decode(out);
	}

	bool storeSlots(const Record* r)   // nullptr = erase
	{
		if (r == nullptr) return sectorErase();
		long n = firstFreeSlot();
		if (n < 0) return false;
		if (n == static_cast<long>(kSlots))
		{
			// ponytail: the sector is full only after 256 records with no clean
			// reset between them; then the old erase-then-write window returns
			// for this one write. Upgrade path: a second sector, ping-ponged.
			if (!sectorErase()) return false;
			n = 0;
		}
		return slotWrite(static_cast<size_t>(n), *r);
	}

	struct Cache
	{
		bool       loaded = false;
		BootStatus status;
		uint32_t   seq = 0;   // of the record found at boot; the next write is +1
	};
	Cache& cache()
	{
		static Cache c;
		return c;
	}

	// #481 review: the first GET /api/status can arrive on two http_conn threads
	// at once. `loaded` used to be set BEFORE the record was read, so the second
	// thread returned the default ("complete") status for an interrupted reset.
	// The load now runs under a mutex and `loaded` is set only after `status` is
	// filled; a racing caller waits for it. No heap: a function-local std::mutex.
	// #481 review (BLOCKING): a std::mutex on ESP-IDF allocates its FreeRTOS
	// mutex lazily, on first lock -- on the HTTP path. The ESP arm uses a
	// statically allocated mutex (the SmtpClient.cpp precedent), and
	// HttpServer::acceptLoop() primes the load before its first accept, so no
	// request ever pays for it. The host keeps std::mutex.
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	class LoadLock
	{
	public:
		LoadLock()
		{
			const BaseType_t taken = xSemaphoreTake(handle(), portMAX_DELAY);
			configASSERT(taken == pdTRUE);   // #595: portMAX_DELAY never times out; a failure is a bug
			(void)taken;
		}
		~LoadLock() { xSemaphoreGive(handle()); }
	private:
		static SemaphoreHandle_t handle()
		{
			static StaticSemaphore_t buf;
			static SemaphoreHandle_t h = xSemaphoreCreateMutexStatic(&buf);   // no heap
			return h;
		}
	};
#else
	class LoadLock
	{
	public:
		LoadLock() : _g(mutex()) {}
	private:
		static std::mutex& mutex() { static std::mutex m; return m; }
		std::lock_guard<std::mutex> _g;
	};
#endif

	void ensureLoaded()
	{
		LoadLock lock;
		Cache& c = cache();
		if (c.loaded) return;
		c.status.storage = backend();
#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
		if (s_loadHook) s_loadHook();
#endif
		Record r{};
		switch (load(r))
		{
			case Read::Absent:
				break;
			case Read::Garbage:
				// A torn write of the journal itself, most likely during a reset:
				// treat as incomplete rather than clean.
				c.status.stage = Stage::Unreadable;
				break;
			case Read::Valid:
				c.status.stage = static_cast<Stage>(r.stage);
				c.status.failedMask = r.failedMask;
				c.seq = r.seq;
				break;
		}
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		// No silent downgrade (#481 review): the flash backend needs the
		// `prompts` partition, and esp_partition_find_first() can also come back
		// empty under memory pressure. Say so whenever the journal ends up in RTC
		// memory, which a power cut clears.
		if (c.status.storage == Storage::Rtc)
		{
			warn("no 'prompts' partition found (or the lookup failed); the reset journal is in RTC "
			     "memory, so an interrupted reset is NOT reported after a power cut");
		}
#endif
		if (c.status.incomplete())
		{
			warn(c.status.stage == Stage::Begun
				? "the last factory reset was INTERRUPTED (power cut, crash or hang after it began); "
				  "stored secrets may still be in flash -- run the factory reset again"
				: c.status.stage == Stage::Failed
				? "the last factory reset FAILED to erase one or more stores (see /api/status); "
				  "run the factory reset again"
				: "the factory-reset journal is unreadable (torn write); treat the last reset as incomplete");
		}
		c.loaded = true;   // last: a racing caller waits on the mutex, never sees a half-loaded cache
	}

	// #595 item 4: the sequence number is bumped under the same lock as the load.
	uint32_t nextSeq()
	{
		ensureLoaded();
		LoadLock lock;
		return ++cache().seq;
	}
}

bool begin()
{
	ensureLoaded();   // capture what THIS boot found before overwriting it
	ramMask().store(0);
	const Record r = make(Stage::Begun, 0, nextSeq());
	if (store(&r)) return true;
	// The reset still proceeds -- refusing to wipe secrets because the journal
	// could not be written would be the worse failure. It is logged and counted.
	writeFailures().fetch_add(1);
	warn("could not record the reset start; an interrupted reset will not be reported");
	return false;
}

void noteFailure(uint8_t mask)
{
	ramMask().fetch_or(mask);
}

void finish(uint8_t extraMask)
{
	ensureLoaded();
	const uint8_t mask = static_cast<uint8_t>(ramMask().load() | extraMask);
	if (mask == 0)
	{
		if (!store(nullptr))
		{
			writeFailures().fetch_add(1);
			warn("could not clear the reset journal; the next boot may report a stale incomplete reset");
		}
		return;
	}
	const Record r = make(Stage::Failed, mask, nextSeq());
	if (!store(&r))
	{
		writeFailures().fetch_add(1);
		warn("could not record the failed reset");
	}
}

uint32_t writeFailureCount()
{
	return writeFailures().load();
}

BootStatus bootStatus()
{
	ensureLoaded();
	return cache().status;
}

Storage storage()
{
	return backend();
}

const char* stageName(Stage s)
{
	switch (s)
	{
		case Stage::Begun:      return "interrupted";
		case Stage::Failed:     return "failed";
		case Stage::Unreadable: return "unreadable";
		default:                return "none";
	}
}

const char* storageName(Storage s)
{
	switch (s)
	{
		case Storage::Flash: return "flash";
		case Storage::Rtc:   return "rtc";
		default:             return "none";
	}
}

#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
void simulateRebootForTest()
{
	cache() = Cache{};
	ramMask().store(0);
}

void resetForTest()
{
	simulateRebootForTest();
	sectorErase();
	s_hostFailNextWrite = false;
	writeFailures().store(0);
}

Stage storedStageForTest()
{
	Record r{};
	switch (loadSlots(r))
	{
		case Read::Valid:   return static_cast<Stage>(r.stage);
		case Read::Garbage: return Stage::Unreadable;
		default:            return Stage::None;
	}
}

void setLoadHookForTest(void (*hook)())
{
	s_loadHook = hook;
}

void failNextWriteForTest()
{
	s_hostFailNextWrite = true;
}

void corruptRecordForTest()
{
	// Over the newest record, or slot 0 on an empty sector.
	const long n = firstFreeSlot();
	Record junk;
	std::memset(&junk, 0x5A, sizeof(junk));
	slotWrite(n > 0 ? static_cast<size_t>(n - 1) : 0, junk);
}
#endif
}

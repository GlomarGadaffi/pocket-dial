#include "ResetJournal.hpp"

#include <atomic>
#include <cstddef>
#include <cstring>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_partition.h"
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

	Read load(Record& out)
	{
		size_t off = 0;
		if (const esp_partition_t* p = journalPartition(off))
		{
			if (esp_partition_read(p, off, &out, sizeof(out)) != ESP_OK) return Read::Garbage;
			return decode(out);
		}
		out = s_rtcRecord;
		// Uninitialised RTC memory after a power cycle is random: for this
		// backend anything that does not validate is simply "no record".
		const Read r = decode(out);
		return r == Read::Valid ? Read::Valid : Read::Absent;
	}

	bool store(const Record* r)   // nullptr = erase
	{
		size_t off = 0;
		if (const esp_partition_t* p = journalPartition(off))
		{
			// Raw partition discipline (partitions.csv): erase before write.
			if (esp_partition_erase_range(p, off, kSector) != ESP_OK) return false;
			return r == nullptr || esp_partition_write(p, off, r, sizeof(*r)) == ESP_OK;
		}
		if (r) s_rtcRecord = *r;
		else std::memset(&s_rtcRecord, 0, sizeof(s_rtcRecord));
		return true;
	}

	void warn(const char* msg) { ESP_LOGW(TAG, "%s", msg); }
#else
	Record s_hostRecord;
	bool   s_hostHasRecord = false;

	Storage backend() { return Storage::Flash; }   // host models the flash backend

	Read load(Record& out)
	{
		if (!s_hostHasRecord)
		{
			std::memset(&out, 0xFF, sizeof(out));
			return Read::Absent;
		}
		out = s_hostRecord;
		return decode(out);
	}

	bool store(const Record* r)
	{
		if (r) { s_hostRecord = *r; s_hostHasRecord = true; }
		else   { s_hostHasRecord = false; }
		return true;
	}

	void warn(const char* msg) { std::cerr << "[W] ResetJournal: " << msg << std::endl; }
#endif

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

	void ensureLoaded()
	{
		Cache& c = cache();
		if (c.loaded) return;
		c.loaded = true;
		c.status.storage = backend();
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
	}
}

void begin()
{
	ensureLoaded();   // capture what THIS boot found before overwriting it
	ramMask().store(0);
	const Record r = make(Stage::Begun, 0, ++cache().seq);
	if (!store(&r)) warn("could not record the reset start; an interrupted reset will not be reported");
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
		if (!store(nullptr)) warn("could not clear the reset journal; the next boot may report a stale incomplete reset");
		return;
	}
	const Record r = make(Stage::Failed, mask, ++cache().seq);
	if (!store(&r)) warn("could not record the failed reset");
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
	s_hostHasRecord = false;
}

void corruptRecordForTest()
{
	std::memset(&s_hostRecord, 0x5A, sizeof(s_hostRecord));
	s_hostHasRecord = true;
}
#endif
}

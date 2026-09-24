#include "CoreDumpStore.hpp"

#include <cstdio>
#include <cstring>

namespace CoreDumpStore
{
	bool looksLikeDump(const uint8_t* head, size_t headLen, uint32_t storedSize,
		uint32_t partitionSize)
	{
		static const uint8_t kElfMagic[4] = { 0x7F, 'E', 'L', 'F' };
		if (!head || headLen < 16) return false;
		if (storedSize < 16 || storedSize > partitionSize) return false;
		return std::memcmp(head + 12, kElfMagic, sizeof(kElfMagic)) == 0;
	}
}

#if defined(ESP_PLATFORM)
#include "sdkconfig.h"
#endif

#if defined(ESP_PLATFORM) && CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH

#include <cstdio>
#include <mutex>

#include "esp_core_dump.h"
#include "esp_flash.h"
#include "esp_partition.h"

namespace CoreDumpStore
{
	namespace
	{
		// image_get's address/size, but only when looksLikeDump() agrees.
		bool locate(size_t& addr, size_t& size)
		{
			// ESP_ERR_NOT_FOUND on an erased partition or when the board's
			// partition table predates #382 -- both simply mean "no dump".
			if (esp_core_dump_image_get(&addr, &size) != ESP_OK) return false;
			const esp_partition_t* part = esp_partition_find_first(
				ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_COREDUMP, nullptr);
			uint8_t head[16] = {};
			if (!part || esp_flash_read(nullptr, head, static_cast<uint32_t>(addr), sizeof(head)) != ESP_OK)
				return false;
			return looksLikeDump(head, sizeof(head), static_cast<uint32_t>(size),
				static_cast<uint32_t>(part->size));
		}
	}

	namespace
	{
		// The flash probe: image_get + partition_find (which heap-allocates an
		// iterator) + a 16-byte flash_read. Deep stack, so only prime() and the
		// pre-prime fallback in query() ever run it (#405).
		Info probe(size_t& addr)
		{
			Info info;
			info.supported = true;
			size_t size = 0;
			if (locate(addr, size))
			{
				info.present = true;
				info.size = static_cast<uint32_t>(size);
			}
			return info;
		}

		std::mutex g_summaryMutex;   // guards everything below
		Summary g_summary;   // valid only while g_summaryPrimed
		bool g_summaryPrimed = false;
		Info g_info;         // valid only while g_infoPrimed
		size_t g_addr = 0;   // flash address of the dump, when g_info.present
		bool g_infoPrimed = false;
	}

	Info query()
	{
		{
			std::lock_guard<std::mutex> lock(g_summaryMutex);
			if (g_infoPrimed) return g_info;
		}
		size_t addr = 0;
		return probe(addr);
	}

	void prime()
	{
		// Runs once from HttpServer::acceptLoop (8 KB pthread stack) before the
		// first accept, NEVER on a 4 KB per-connection thread: the checksum walk
		// holds a SHA-256 context and a read cache on the stack, get_summary()
		// adds a few hundred bytes more, and those connection threads have
		// measured as little as 472 bytes free (#405). A dump cannot change
		// while the app runs (only a panic writes one), so once per boot loses
		// nothing. Nothing here allocates except inside IDF's get_summary(),
		// which maps the partition -- init-time, before the server serves.
		size_t addr = 0;
		const Info info = probe(addr);
		Summary out;
		if (info.present)
		{
			out.valid = (esp_core_dump_image_check() == ESP_OK);

			esp_core_dump_summary_t s{};
			if (esp_core_dump_get_summary(&s) == ESP_OK)
			{
				std::snprintf(out.task, sizeof(out.task), "%.*s",
					static_cast<int>(sizeof(s.exc_task)), s.exc_task);
				out.pc = s.exc_pc;
				std::snprintf(out.elfSha, sizeof(out.elfSha), "%.*s",
					static_cast<int>(sizeof(s.app_elf_sha256)),
					reinterpret_cast<const char*>(s.app_elf_sha256));
			}
			if (esp_core_dump_get_panic_reason(out.reason, sizeof(out.reason)) != ESP_OK)
				out.reason[0] = '\0';
			out.reason[sizeof(out.reason) - 1] = '\0';
		}
		std::lock_guard<std::mutex> lock(g_summaryMutex);
		g_summary = out;
		g_summaryPrimed = true;
		g_info = info;
		g_addr = addr;
		g_infoPrimed = true;
	}

	Summary summary()
	{
		// Copies the boot-time result; does no flash or checksum work itself.
		std::lock_guard<std::mutex> lock(g_summaryMutex);
		return g_summaryPrimed ? g_summary : Summary{};
	}

	bool read(uint32_t offset, uint8_t* out, size_t len)
	{
		if (!out) return false;
		size_t addr = 0;
		size_t size = 0;
		bool primed = false;
		{
			std::lock_guard<std::mutex> lock(g_summaryMutex);
			if (g_infoPrimed)
			{
				primed = true;
				if (!g_info.present) return false;
				addr = g_addr;
				size = g_info.size;
			}
		}
		if (!primed && !locate(addr, size)) return false;
		if (offset > size || len > size - offset) return false;
		return esp_flash_read(nullptr, out, static_cast<uint32_t>(addr + offset),
			static_cast<uint32_t>(len)) == ESP_OK;
	}

	bool erase()
	{
		const bool ok = esp_core_dump_image_erase() == ESP_OK;
		if (ok)
		{
			std::lock_guard<std::mutex> lock(g_summaryMutex);
			g_summary = Summary{};
			g_info.supported = true;
			g_info.present = false;
			g_info.size = 0;
			g_addr = 0;
			g_infoPrimed = true;
		}
		return ok;
	}
}

#elif defined(ESP_PLATFORM)

// Built without coredump-to-flash: nothing to report, read or erase.
namespace CoreDumpStore
{
	Info query() { return Info{}; }
	void prime() {}
	Summary summary() { return Summary{}; }
	bool read(uint32_t, uint8_t*, size_t) { return false; }
	bool erase() { return false; }
}

#else

#include <cstring>
#include <mutex>

namespace CoreDumpStore
{
	namespace
	{
		std::mutex g_mutex;
		std::vector<uint8_t> g_image;   // stands in for the coredump partition
		Info g_info;                    // the cached result, as on the board (#405)
		bool g_infoPrimed = false;
		uint32_t g_flashAccesses = 0;   // probes + reads of g_image
	}

	// Host stand-in for the 16MB table's 128KB partition.
	constexpr uint32_t kFakePartitionSize = 0x20000;

	bool presentLocked()
	{
		return looksLikeDump(g_image.data(), g_image.size(),
			static_cast<uint32_t>(g_image.size()), kFakePartitionSize);
	}

	// The host's "flash probe": counted, so a test can prove a route never
	// reaches it.
	Info probeLocked()
	{
		++g_flashAccesses;
		Info info;
		info.supported = !g_image.empty();
		info.present = presentLocked();
		info.size = info.present ? static_cast<uint32_t>(g_image.size()) : 0;
		return info;
	}

	void setImageForTest(std::vector<uint8_t> image)
	{
		std::lock_guard<std::mutex> lock(g_mutex);
		g_image = std::move(image);
		g_info = probeLocked();   // a panic + reboot: the next boot's prime()
		g_infoPrimed = true;
	}

	uint32_t flashAccessCountForTest()
	{
		std::lock_guard<std::mutex> lock(g_mutex);
		return g_flashAccesses;
	}

	// Caches Info exactly as the board does. The summary needs no checksum walk
	// on the host (summary() below computes it directly), so only Info is cached.
	void prime()
	{
		std::lock_guard<std::mutex> lock(g_mutex);
		g_info = probeLocked();
		g_infoPrimed = true;
	}

	Info query()
	{
		std::lock_guard<std::mutex> lock(g_mutex);
		return g_infoPrimed ? g_info : probeLocked();
	}

	Summary summary()
	{
		std::lock_guard<std::mutex> lock(g_mutex);
		Summary out;
		if (!presentLocked()) return out;
		out.valid = true;
		std::snprintf(out.task, sizeof(out.task), "%s", "host_test");
		return out;
	}

	bool read(uint32_t offset, uint8_t* out, size_t len)
	{
		std::lock_guard<std::mutex> lock(g_mutex);
		++g_flashAccesses;
		if (!out || !presentLocked()) return false;
		if (offset > g_image.size() || len > g_image.size() - offset) return false;
		std::memcpy(out, g_image.data() + offset, len);
		return true;
	}

	bool erase()
	{
		std::lock_guard<std::mutex> lock(g_mutex);
		g_image.clear();
		// As on the board: erase() itself keeps the cache truthful.
		g_info.present = false;
		g_info.size = 0;
		g_infoPrimed = true;
		return true;
	}
}

#endif

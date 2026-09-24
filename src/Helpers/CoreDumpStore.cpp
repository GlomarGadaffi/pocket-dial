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

	Info query()
	{
		Info info;
		info.supported = true;
		size_t addr = 0;
		size_t size = 0;
		if (locate(addr, size))
		{
			info.present = true;
			info.size = static_cast<uint32_t>(size);
		}
		return info;
	}

	namespace
	{
		std::mutex g_summaryMutex;
		Summary g_summary;   // valid only while g_summaryPrimed
		bool g_summaryPrimed = false;
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
		Summary out;
		if (query().present)
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
	}

	Summary summary()
	{
		// Copies the boot-time result; does no flash or checksum work itself.
		std::lock_guard<std::mutex> lock(g_summaryMutex);
		return g_summaryPrimed ? g_summary : Summary{};
	}

	bool read(uint32_t offset, uint8_t* out, size_t len)
	{
		size_t addr = 0;
		size_t size = 0;
		if (!out || !locate(addr, size)) return false;
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
		std::vector<uint8_t> g_image;
	}

	void setImageForTest(std::vector<uint8_t> image)
	{
		std::lock_guard<std::mutex> lock(g_mutex);
		g_image = std::move(image);
	}

	// Host threads have MB-sized stacks and the fake needs no checksum walk, so
	// summary() below computes directly; there is nothing to cache.
	void prime() {}

	// Host stand-in for the 16MB table's 128KB partition.
	constexpr uint32_t kFakePartitionSize = 0x20000;

	bool presentLocked()
	{
		return looksLikeDump(g_image.data(), g_image.size(),
			static_cast<uint32_t>(g_image.size()), kFakePartitionSize);
	}

	Info query()
	{
		std::lock_guard<std::mutex> lock(g_mutex);
		Info info;
		info.supported = !g_image.empty();
		info.present = presentLocked();
		info.size = info.present ? static_cast<uint32_t>(g_image.size()) : 0;
		return info;
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
		if (!out || !presentLocked()) return false;
		if (offset > g_image.size() || len > g_image.size() - offset) return false;
		std::memcpy(out, g_image.data() + offset, len);
		return true;
	}

	bool erase()
	{
		std::lock_guard<std::mutex> lock(g_mutex);
		g_image.clear();
		return true;
	}
}

#endif

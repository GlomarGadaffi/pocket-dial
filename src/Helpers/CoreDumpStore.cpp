#include "CoreDumpStore.hpp"

#if defined(ESP_PLATFORM)
#include "sdkconfig.h"
#endif

#if defined(ESP_PLATFORM) && CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH

#include <cstdio>

#include "esp_core_dump.h"
#include "esp_flash.h"

namespace CoreDumpStore
{
	Info query()
	{
		Info info;
		info.supported = true;
		size_t addr = 0;
		size_t size = 0;
		// ESP_ERR_INVALID_SIZE on an erased partition, ESP_ERR_NOT_FOUND when the
		// board's partition table predates #382 -- both simply mean "no dump".
		if (esp_core_dump_image_get(&addr, &size) == ESP_OK && size > 0)
		{
			info.present = true;
			info.size = static_cast<uint32_t>(size);
		}
		return info;
	}

	Summary summary()
	{
		Summary out;
		if (!query().present) return out;
		out.valid = (esp_core_dump_image_check() == ESP_OK);

		esp_core_dump_summary_t s{};
		if (esp_core_dump_get_summary(&s) == ESP_OK)
		{
			s.exc_task[sizeof(s.exc_task) - 1] = '\0';
			out.task = s.exc_task;
			out.pc = s.exc_pc;
			s.app_elf_sha256[sizeof(s.app_elf_sha256) - 1] = '\0';
			out.elfSha = reinterpret_cast<const char*>(s.app_elf_sha256);
		}
		char reason[128] = {};
		if (esp_core_dump_get_panic_reason(reason, sizeof(reason)) == ESP_OK)
		{
			reason[sizeof(reason) - 1] = '\0';
			out.reason = reason;
		}
		return out;
	}

	bool read(uint32_t offset, uint8_t* out, size_t len)
	{
		size_t addr = 0;
		size_t size = 0;
		if (!out || esp_core_dump_image_get(&addr, &size) != ESP_OK) return false;
		if (offset > size || len > size - offset) return false;
		return esp_flash_read(nullptr, out, static_cast<uint32_t>(addr + offset),
			static_cast<uint32_t>(len)) == ESP_OK;
	}

	bool erase()
	{
		return esp_core_dump_image_erase() == ESP_OK;
	}
}

#elif defined(ESP_PLATFORM)

// Built without coredump-to-flash: nothing to report, read or erase.
namespace CoreDumpStore
{
	Info query() { return Info{}; }
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

	Info query()
	{
		std::lock_guard<std::mutex> lock(g_mutex);
		Info info;
		info.supported = !g_image.empty();
		info.present = !g_image.empty();
		info.size = static_cast<uint32_t>(g_image.size());
		return info;
	}

	Summary summary()
	{
		std::lock_guard<std::mutex> lock(g_mutex);
		Summary out;
		if (g_image.empty()) return out;
		out.valid = true;
		out.task = "host_test";
		return out;
	}

	bool read(uint32_t offset, uint8_t* out, size_t len)
	{
		std::lock_guard<std::mutex> lock(g_mutex);
		if (!out || offset > g_image.size() || len > g_image.size() - offset) return false;
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

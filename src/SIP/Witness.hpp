#ifndef POCKETDIAL_WITNESS_HPP
#define POCKETDIAL_WITNESS_HPP

// One-line path witnesses for hardware runs. On the board they are esp_log
// lines, the only lines syslog carries (queueLog() goes to stdout, #533/#603),
// so tests/load/anchor_scenarios.py can pre-register one as a path counter
// (LOG_COUNTERS). On the host the same formatted text goes to a fixed ring a
// test can read, so the format string is compiled and checked here too. The
// ring is static storage: a witness never allocates, so a per-call heap
// baseline (PerCallHeap_test) is not moved by one.
// Never put a number, a URI user or a credential in a witness.

#if defined(ESP_PLATFORM)

#include "esp_log.h"
#define PD_WITNESS_W(tag, ...) ESP_LOGW(tag, __VA_ARGS__)
#define PD_WITNESS_I(tag, ...) ESP_LOGI(tag, __VA_ARGS__)

#else

#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace pdwitness
{
	constexpr std::size_t kRingLines = 512;
	constexpr std::size_t kLineBytes = 320;

	struct Sink
	{
		std::mutex  m;
		char        ring[kRingLines][kLineBytes];
		std::size_t total = 0;   // lines ever recorded; the newest kRingLines are kept
	};

	inline Sink& sink()
	{
		static Sink s;
		return s;
	}

#if defined(__GNUC__)
	__attribute__((format(printf, 2, 3)))
#endif
	inline void record(const char* tag, const char* fmt, ...)
	{
		char body[kLineBytes];
		va_list ap;
		va_start(ap, fmt);
		(void)std::vsnprintf(body, sizeof body, fmt, ap);
		va_end(ap);
		Sink& s = sink();
		std::lock_guard<std::mutex> g(s.m);
		(void)std::snprintf(s.ring[s.total % kRingLines], kLineBytes, "%s: %s", tag, body);
		++s.total;
	}

	inline void clear()
	{
		Sink& s = sink();
		std::lock_guard<std::mutex> g(s.m);
		s.total = 0;
	}

	inline std::vector<std::string> lines()
	{
		Sink& s = sink();
		std::lock_guard<std::mutex> g(s.m);
		std::vector<std::string> out;
		const std::size_t kept = s.total < kRingLines ? s.total : kRingLines;
		for (std::size_t i = s.total - kept; i < s.total; ++i) out.emplace_back(s.ring[i % kRingLines]);
		return out;
	}

	// Lines holding `needle`.
	inline std::size_t count(const std::string& needle)
	{
		Sink& s = sink();
		std::lock_guard<std::mutex> g(s.m);
		std::size_t n = 0;
		const std::size_t kept = s.total < kRingLines ? s.total : kRingLines;
		for (std::size_t i = s.total - kept; i < s.total; ++i)
			if (std::strstr(s.ring[i % kRingLines], needle.c_str()) != nullptr) ++n;
		return n;
	}
}

#define PD_WITNESS_W(tag, ...) ::pdwitness::record(tag, __VA_ARGS__)
#define PD_WITNESS_I(tag, ...) ::pdwitness::record(tag, __VA_ARGS__)

#endif

#endif

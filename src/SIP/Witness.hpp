#ifndef POCKETDIAL_WITNESS_HPP
#define POCKETDIAL_WITNESS_HPP

// One-line path witnesses for hardware runs. On the board they are esp_log
// lines, the only lines syslog carries (queueLog() goes to stdout, #533/#603),
// so tests/load/anchor_scenarios.py can pre-register one as a path counter
// (LOG_COUNTERS). On the host the same formatted text goes to a bounded list
// a test can read, so the format string is compiled and checked here too.
// Never put a number, a URI user or a credential in a witness.

#if defined(ESP_PLATFORM)

#include "esp_log.h"
#define PD_WITNESS_W(tag, ...) ESP_LOGW(tag, __VA_ARGS__)
#define PD_WITNESS_I(tag, ...) ESP_LOGI(tag, __VA_ARGS__)

#else

#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace pdwitness
{
	struct Sink
	{
		std::mutex               m;
		std::vector<std::string> lines;
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
		char buf[320];
		va_list ap;
		va_start(ap, fmt);
		std::vsnprintf(buf, sizeof buf, fmt, ap);
		va_end(ap);
		Sink& s = sink();
		std::lock_guard<std::mutex> g(s.m);
		if (s.lines.size() >= 4096) s.lines.erase(s.lines.begin());
		s.lines.push_back(std::string(tag) + ": " + buf);
	}

	inline void clear()
	{
		Sink& s = sink();
		std::lock_guard<std::mutex> g(s.m);
		s.lines.clear();
	}

	inline std::vector<std::string> lines()
	{
		Sink& s = sink();
		std::lock_guard<std::mutex> g(s.m);
		return s.lines;
	}

	// Lines holding `needle`.
	inline std::size_t count(const std::string& needle)
	{
		std::size_t n = 0;
		for (const std::string& l : lines())
			if (l.find(needle) != std::string::npos) ++n;
		return n;
	}
}

#define PD_WITNESS_W(tag, ...) ::pdwitness::record(tag, __VA_ARGS__)
#define PD_WITNESS_I(tag, ...) ::pdwitness::record(tag, __VA_ARGS__)

#endif

#endif

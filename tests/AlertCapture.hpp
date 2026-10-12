#ifndef TESTS_ALERT_CAPTURE_HPP
#define TESTS_ALERT_CAPTURE_HPP

// #986: a host test's view of the pbx-911 Alert. Syslog::send() emits nothing off
// the board, so this installs Syslog's host sink and keeps every pbx-911 frame it
// would have put on the wire. Construct it AFTER the bench has registered its
// phones: a REGISTER pass ends in flushPass() too.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "RequestsHandler.hpp"
#include "Syslog.hpp"
#include "Witness.hpp"

struct AlertCapture
{
	static std::vector<std::string>& frames()
	{
		static std::vector<std::string> v;
		return v;
	}
	// Runs inside the sink, i.e. at the moment a frame goes out.
	static std::function<void()>& onSend()
	{
		static std::function<void()> f;
		return f;
	}

	static void sink(const char* frame, size_t len)
	{
		std::string f(frame, len);
		if (f.find(" pbx-911 ") == std::string::npos) return;
		frames().push_back(std::move(f));
		if (onSend()) onSend()();
	}

	AlertCapture()
	{
		frames().clear();
		onSend() = nullptr;
		EXPECT_TRUE(Syslog::configure("192.0.2.1"));
		Syslog::setHostSink(&sink);
		pdwitness::clear();
	}
	~AlertCapture()
	{
		Syslog::setHostSink(nullptr);
		Syslog::configure("");
		onSend() = nullptr;
	}
	AlertCapture(const AlertCapture&) = delete;
	AlertCapture& operator=(const AlertCapture&) = delete;
};

// Whether `handler`'s engine lock is free at the moment run() is called. The
// question is asked from a second thread, so a caller that holds the lock makes
// the answer wait, and the wait is what fails. run() never blocks for good: it
// gives up after 500 ms, and the destructor joins once the pass has ended.
class EngineLockProbe
{
public:
	explicit EngineLockProbe(RequestsHandler& handler) : _handler(handler) {}
	~EngineLockProbe()
	{
		if (_thread.joinable()) _thread.join();
	}
	EngineLockProbe(const EngineLockProbe&) = delete;
	EngineLockProbe& operator=(const EngineLockProbe&) = delete;

	void run()
	{
		if (_thread.joinable()) return;
		_thread = std::thread([this] {
			(void)_handler.hasLiveEmergencyCall();   // takes the engine lock
			_done.store(true);
		});
		for (int i = 0; i < 250 && !_done.load(); ++i)
			std::this_thread::sleep_for(std::chrono::milliseconds(2));
		_freeAtRun = _done.load();
	}
	bool freeAtRun() const { return _freeAtRun; }

private:
	RequestsHandler&  _handler;
	std::thread       _thread;
	std::atomic<bool> _done{false};
	bool              _freeAtRun = false;
};

#endif // TESTS_ALERT_CAPTURE_HPP

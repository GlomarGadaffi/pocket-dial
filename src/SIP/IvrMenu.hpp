#ifndef IVR_MENU_HPP
#define IVR_MENU_HPP

// IvrMenu -- Issue #168 (IVR / auto-attendant digit routing), host-only slice.
//
// Pure digit-to-target menu state machine: digits and timeouts in, one Result
// out per event. No RequestsHandler, no RTP, no prompt playback, no routing.
// Nothing includes this header yet, so no call path can reach it. Depth 1:
// one menu, no submenus.
//
// A future caller must place this after the 911/933 classifier
// (classifyEmergencyDial) and must never let a menu intercept an emergency
// call.
//
// A digit with no binding and a timeout are both failed attempts. The first
// kMaxFailures-1 failures ask the caller to replay the prompt; the
// kMaxFailures-th gives up and the caller applies its own fallback. Once the
// menu has routed or given up, every event is a no-op until reset(). reset()
// revives a menu that routed or gave up, and keeps the bound table. An empty
// table never routes.

#include <cstdint>

class IvrMenu
{
public:
	static constexpr int kDigits = 10;
	static constexpr int kMaxFailures = 3;

	enum class Command : uint8_t
	{
		None,    // ignored: the menu has already routed or given up
		Route,   // route the call to Result::target
		Replay,  // failed attempt with retries left: replay the prompt and wait again
		GiveUp,  // retry limit reached: nothing is routed, the caller applies its fallback
	};

	struct Result
	{
		Command command = Command::None;
		int target = -1;
	};

	// Binds '0'..'9' to a target id >= 0. Refused input leaves the table as it was.
	bool bind(char digit, int target)
	{
		if (!isDigit(digit) || target < 0)
		{
			return false;
		}
		_entries[digit - '0'] = {true, target};
		return true;
	}

	Result onDigit(char digit)
	{
		if (_done)
		{
			return {};
		}
		if (isDigit(digit) && _entries[digit - '0'].bound)
		{
			_done = true;
			return {Command::Route, _entries[digit - '0'].target};
		}
		return fail();
	}

	Result onTimeout()
	{
		return _done ? Result{} : fail();
	}

	void reset()
	{
		_failures = 0;
		_done = false;
	}

	bool isDone() const { return _done; }

private:
	struct Entry
	{
		bool bound = false;
		int target = -1;
	};

	static bool isDigit(char c) { return c >= '0' && c <= '9'; }

	Result fail()
	{
		if (++_failures >= kMaxFailures)
		{
			_done = true;
			return {Command::GiveUp, -1};
		}
		return {Command::Replay, -1};
	}

	Entry _entries[kDigits];
	int _failures = 0;
	bool _done = false;
};

#endif

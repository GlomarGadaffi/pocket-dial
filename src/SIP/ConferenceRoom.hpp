#ifndef CONFERENCE_ROOM_HPP
#define CONFERENCE_ROOM_HPP

// ── ConferenceRoom — the meet-me bridge that turns MixBus into a dialable feature ──
//
// MixBus (src/SIP/MixBus.hpp, docs/CONFERENCE_MIXER.md) is the summing junction and
// nothing else: ports, rings, and one tick. ConferenceRoom is the thing that owns ONE
// such bus, the per-leg transport around it, and — critically — the SINGLE periodic
// driver that calls MixBus::tick(). Issue #75.
//
// One leg == one dialed-in handset == { RtpReceiver, RtpSender, MediaBridge, MixBus
// port }. RtpReceiver/RtpSender each enforce a one-stream cap internally, so a leg
// gets its OWN pair rather than sharing the server's 440 tone sender. MediaBridge in
// BUS mode does the µ-law rim companding and pumps the bus:
//
//     handset --µ-law RTP--> RtpReceiver -> MediaBridge::onHandsetRtp
//                                             -> MixBus::inputFrame(port)
//     handset <--µ-law RTP-- RtpSender   <- MediaBridge::fillHandsetTx
//                                             <- MixBus::outputFrame(port)
//
// THE TICK IS THE MASTER CLOCK, AND THERE IS EXACTLY ONE OF IT (§3). Every leg's
// RtpSender runs its own 20 ms cadence, so hanging the mix tick off a sender would
// give N competing clocks that drain the bus N times per frame and starve each other.
// startDriver() instead stands up one dedicated 20 ms driver for the whole room; a
// leg's sender only ever calls outputFrame(). tickOnce() exists so the host suite can
// step the clock deterministically without a driver running at all.
//
// Lifetime: legs come and go under _mutex; the bus and the driver outlive them. A leg
// leaving only marks its port Draining — the next tick reclaims the rings — so the
// other legs are never disturbed (§5).

#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>

#include "MediaBridge.hpp"
#include "MixBus.hpp"
#include "PoolConfig.hpp"
#include "RtpReceiver.hpp"
#include "RtpSender.hpp"

#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
#include <thread>
#endif

class ConferenceRoom
{
public:
	// The virtual extension that dials into the room. Sits alongside 777 (echo),
	// 999 (all-page), 440 (media beachhead) and 700–709 (park) in RequestsHandler's
	// onInvite intercept chain.
	static constexpr const char* EXT = "888";

	// Legs the room accepts. Bounded by the bus's port count; each leg also costs a
	// Session slot, an RTP receive task and an RTP send task on the device.
	static constexpr int MAX_LEGS = POCKETDIAL_CONF_LEGS;
	static_assert(MAX_LEGS > 0 && MAX_LEGS <= MixBus::MAX_PORTS,
		"POCKETDIAL_CONF_LEGS must fit MixBus::MAX_PORTS");

	// The mix tick period — MUST equal the RTP ptime the legs run at, or the bus
	// drains at a different rate than the wire delivers (§8 trap 5).
	static constexpr int TICK_MS = RtpSender::PTIME_MS;

	ConferenceRoom();
	~ConferenceRoom();

	ConferenceRoom(const ConferenceRoom&) = delete;
	ConferenceRoom& operator=(const ConferenceRoom&) = delete;

	// Add a leg for `callID`: attach a MixBus port, bind an RTP receiver, and start an
	// RTP sender toward handsetIp:handsetPort. Returns the leg index (>= 0), or -1 if
	// the room is full, the Call-ID is already in the room, or the media failed to
	// start (nothing is left half-joined on failure).
	// `dtmfPt` is the RFC 4733 telephone-event payload type this handset offered
	// (-1 when it offered none). A conference is exactly where in-call keypresses
	// matter -- PIN entry and in-call controls are pressed on a leg the server
	// terminates -- so the leg's receiver is armed for it at join time.
	int join(const std::string& callID, const std::string& ext,
		const std::string& handsetIp, uint16_t handsetPort, int dtmfPt = -1);

	// Where an RFC 4733 key press decoded off ANY leg goes. Invoked on that leg's
	// RTP receive task, so it must be thread-safe and non-blocking; see
	// MediaBridge::DigitSink. Applied to every leg's bridge, so it must be set
	// before the first join -- RequestsHandler does so at room construction.
	void setDigitSink(MediaBridge::DigitSink sink);

	// Drop the leg holding `callID`. Idempotent — safe for an unknown Call-ID, which
	// is what lets RequestsHandler::endCall() call it unconditionally on every teardown.
	// Returns true if a leg was actually released.
	bool leave(const std::string& callID);

	// The UDP port that leg's RTP receiver is bound on — the value that MUST go into
	// the 200 OK SDP answer, since that is where the handset sends its audio. Returns
	// 0 for an unknown Call-ID (and on host builds, where RtpReceiver never binds).
	int rtpPortFor(const std::string& callID) const;

	bool hasLeg(const std::string& callID) const;
	int  legCount() const;

	// The extension dialed in on each occupied leg, for the dashboard / logs.
	std::array<std::string, MAX_LEGS> legExtensions() const;

	// ── The single mix-tick driver ───────────────────────────────────────────────
	// Idempotent; safe to call again on an already-running room. Started by the owner
	// (RequestsHandler) when the room is created, NOT by the constructor, so tests can
	// build a room and step it by hand with tickOnce().
	void startDriver();
	void stopDriver();
	bool driverRunning() const { return _driverRunning.load(std::memory_order_acquire); }

	// Advance the bus exactly one 20 ms frame. This is what the driver calls; tests
	// call it directly. Do NOT call it while a driver is running — that is the second
	// competing tick path this class exists to prevent.
	void tickOnce() { _bus.tick(); }

	// Test/inspection access to the shared bus and a leg's bridge.
	MixBus& bus() { return _bus; }
	MediaBridge* bridgeForCall(const std::string& callID);

	// Test access to a leg's RtpSender. On a Linux host RtpSender::start() is NOT the
	// inert stub the host build is often assumed to get: RtpSender.cpp's
	// "#elif defined(__linux__)" branch (issue #82) spawns a real 20 ms pacer thread
	// whose frame provider is MediaBridge::fillHandsetTx -- i.e. a DESTRUCTIVE
	// MixBus::outputFrame() pop of this port's out ring (PlayoutBuffer::read advances
	// the read pointer and decrements _count). A test that steps the bus with
	// tickOnce() and then drains a leg by hand is therefore a SECOND consumer of that
	// ring, and must stop the pacer first or it can lose the very frame it is about to
	// assert on (issue #135). Production never needs this: the pacer is the only caller
	// of fillHandsetTx.
	RtpSender* senderForCall(const std::string& callID);

private:
	struct Leg
	{
		RtpReceiver rx;
		RtpSender   tx;
		MediaBridge bridge;
		std::string callID;
		std::string ext;
		bool        inUse = false;
	};

	// Kept so setDigitSink() can reach legs that already exist, and so a leg
	// created later still gets it — join() re-applies it below.
	MediaBridge::DigitSink _digitSink;

	int indexOfLocked(const std::string& callID) const;
	void runDriver();

	MixBus                    _bus;
	std::array<Leg, MAX_LEGS> _legs;
	mutable std::mutex        _mutex;

	// Driver control. Same ownership shape as RtpSender's media task: the owner asks
	// the driver to stop, the driver clears _driverRunning as its last act.
	std::atomic<bool> _stopRequested{false};
	std::atomic<bool> _driverRunning{false};

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	static void taskTrampoline(void* arg);
#else
	std::thread _driverThread;
#endif
};

#endif // CONFERENCE_ROOM_HPP

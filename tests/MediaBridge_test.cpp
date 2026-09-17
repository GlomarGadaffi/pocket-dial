// MediaBridge_test.cpp — unit coverage for MediaBridge, the RTP<->AnchorClient
// glue. On host RtpReceiver::start() is a no-op stub, but RtpSender is NOT: its
// "#elif defined(__linux__)" branch (issue #82) spawns a real 20 ms pacer thread
// whose provider is MediaBridge::fillHandsetTx, which pops the very playout buffer
// these tests assert on (PlayoutBuffer::read is destructive). Any test that reads
// getPlayoutBuffer() must stop that sender right after startBridge() first -- see
// issue #135. Otherwise these tests exercise the parts that are real on host: the
// lifecycle/identity bookkeeping and the feedRx -> PlayoutBuffer path, including
// an end-to-end run through a real LoopbackAnchorClient wired the way
// RequestsHandler would wire any AnchorClient's single rx callback.

#include <gtest/gtest.h>
#include "MediaBridge.hpp"
#include "RtpReceiver.hpp"
#include "RtpSender.hpp"
#include "AnchorClient.hpp"
#include "LoopbackAnchorClient.hpp"
#include "HoldMusic.hpp"

#include <fstream>
#include <vector>

namespace
{
	struct Fixture
	{
		RtpReceiver receiver;
		RtpSender sender;
		LoopbackAnchorClient anchor;
		MediaBridge bridge;

		Fixture()
		{
			anchor.init("", "", "", "100");
			anchor.start();
			bridge.init(&receiver, &sender, &anchor);
		}
	};
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

TEST(MediaBridge, NotActiveInitially) {
	Fixture f;
	EXPECT_FALSE(f.bridge.isActive());
	EXPECT_EQ(f.bridge.participantId(), "");
	EXPECT_EQ(f.bridge.callId(), "");
}

TEST(MediaBridge, StartBridgeFailsWithoutInit) {
	RtpReceiver receiver;
	RtpSender sender;
	LoopbackAnchorClient anchor;
	MediaBridge bridge;   // init() never called -> all deps null

	EXPECT_FALSE(bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
}

TEST(MediaBridge, StartBridgeActivatesAndRecordsIdentity) {
	Fixture f;
	EXPECT_TRUE(f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
	EXPECT_TRUE(f.bridge.isActive());
	EXPECT_TRUE(f.bridge.isFor("part-1"));
	EXPECT_TRUE(f.bridge.isForCallId("call-1"));
	EXPECT_EQ(f.bridge.participantId(), "part-1");
	EXPECT_EQ(f.bridge.callId(), "call-1");
}

TEST(MediaBridge, IsForRejectsWrongParticipantOrCall) {
	Fixture f;
	f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1");
	EXPECT_FALSE(f.bridge.isFor("part-2"));
	EXPECT_FALSE(f.bridge.isForCallId("call-2"));
}

TEST(MediaBridge, SecondStartBridgeFailsWhileActive) {
	Fixture f;
	EXPECT_TRUE(f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
	EXPECT_FALSE(f.bridge.startBridge("127.0.0.1", 5005, "call-2", "part-2"));
	// The original bridge is untouched by the rejected second start.
	EXPECT_TRUE(f.bridge.isFor("part-1"));
}

TEST(MediaBridge, StopBridgeClearsState) {
	Fixture f;
	f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1");
	f.bridge.stopBridge();
	EXPECT_FALSE(f.bridge.isActive());
	EXPECT_EQ(f.bridge.participantId(), "");
	EXPECT_EQ(f.bridge.callId(), "");
}

TEST(MediaBridge, StopBridgeIsIdempotentWhenIdle) {
	Fixture f;
	f.bridge.stopBridge();   // never started
	EXPECT_FALSE(f.bridge.isActive());
}

// ── feedRx -> PlayoutBuffer ────────────────────────────────────────────────────

TEST(MediaBridge, FeedRxRejectedWhileIdle) {
	Fixture f;
	const int16_t samples[] = {1, 2, 3};
	EXPECT_FALSE(f.bridge.feedRx("part-1", samples, 3));
}

TEST(MediaBridge, FeedRxRejectedForWrongParticipant) {
	Fixture f;
	f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1");
	const int16_t samples[] = {1, 2, 3};
	EXPECT_FALSE(f.bridge.feedRx("someone-else", samples, 3));
}

TEST(MediaBridge, FeedRxWritesIntoPlayoutBuffer) {
	Fixture f;
	ASSERT_TRUE(f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
	// Halt the Linux pacer thread before asserting on the playout buffer it also
	// drains via fillHandsetTx -> PlayoutBuffer::read() (issue #135).
	ASSERT_TRUE(f.sender.stop("call-1"));

	const int16_t in[] = {111, 222, 333};
	EXPECT_TRUE(f.bridge.feedRx("part-1", in, 3));
	EXPECT_EQ(f.bridge.getPlayoutBuffer().getLength(), 3u);

	int16_t out[3] = {};
	EXPECT_TRUE(f.bridge.getPlayoutBuffer().read(out, 3));
	EXPECT_EQ(out[0], 111);
	EXPECT_EQ(out[1], 222);
	EXPECT_EQ(out[2], 333);
}

// ── End-to-end through a real AnchorClient ────────────────────────────────────
// Mirrors the wiring a caller (e.g. RequestsHandler) would do: register the
// anchor's single rx callback once, fan out to feedRx() on the bridge owning
// the participant. Proves the AnchorClient -> MediaBridge -> PlayoutBuffer
// chain end-to-end without any real socket.

TEST(MediaBridge, AnchorAudioReachesPlayoutBufferThroughRxFanout) {
	Fixture f;
	ASSERT_TRUE(f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
	// Same pacer-thread hazard as above (issue #135).
	ASSERT_TRUE(f.sender.stop("call-1"));

	// #284: AudioRxCallback's participant id is now a string_view, so this
	// mirrors RequestsHandler's actual fan-out (RequestsHandler.cpp:337-344)
	// exactly -- feedRx() itself is the participant-match gate, not a
	// separate isFor() check the production wiring never makes either.
	f.anchor.registerAudioRxCallback([&f](std::string_view participantId,
	                                       const int16_t* samples, size_t count) {
		f.bridge.feedRx(participantId, samples, count);
	});

	const int16_t input[] = {10, 20, 30, 40};
	// LoopbackAnchorClient::writeAudio echoes synchronously through the
	// registered AudioRxCallback (see AnchorClient_test.cpp).
	EXPECT_TRUE(f.anchor.writeAudio("part-1", input, 4));

	EXPECT_EQ(f.bridge.getPlayoutBuffer().getLength(), 4u);
	int16_t out[4] = {};
	EXPECT_TRUE(f.bridge.getPlayoutBuffer().read(out, 4));
	std::vector<int16_t> got(out, out + 4);
	EXPECT_EQ(got, (std::vector<int16_t>{10, 20, 30, 40}));
}

// ── Held mode (issue #218: MoH on an anchored/trunk hold) ────────────────────
//
// Same loopback-echo trick as AnchorAudioReachesPlayoutBufferThroughRxFanout
// above: LoopbackAnchorClient::writeAudio() calls back through the registered
// rx callback synchronously, so wiring that callback to feedRx() turns "did
// the bridge call writeAudio()" into "did PlayoutBuffer receive something" --
// no socket, no thread, no new test infrastructure.

namespace
{
	// Wires the loopback echo the same way RequestsHandler does for every
	// bridge (see the constructor's registerAudioRxCallback wiring).
	void wireLoopbackEcho(Fixture& f)
	{
		f.anchor.registerAudioRxCallback([&f](std::string_view participantId,
		                                       const int16_t* samples, size_t count) {
			f.bridge.feedRx(participantId, samples, count);
		});
	}

	// A WAV byte's worth of raw mu-law payload for feedMohTick()'s input --
	// no HoldMusic instance is needed to build one, since feedMohTick() only
	// cares about the bytes, not where they came from.
	std::vector<uint8_t> ulawTick(uint8_t fill, size_t n = HoldMusic::BYTES_PER_TICK)
	{
		return std::vector<uint8_t>(n, fill);
	}
}

TEST(MediaBridge, SetHeldTogglesIsHeldAndIsIdempotent) {
	Fixture f;
	ASSERT_TRUE(f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
	EXPECT_FALSE(f.bridge.isHeld());

	f.bridge.setHeld(true);
	EXPECT_TRUE(f.bridge.isHeld());
	f.bridge.setHeld(true);   // no-op, must not crash or double-register
	EXPECT_TRUE(f.bridge.isHeld());

	f.bridge.setHeld(false);
	EXPECT_FALSE(f.bridge.isHeld());
	f.bridge.setHeld(false);   // no-op the other direction too
	EXPECT_FALSE(f.bridge.isHeld());
}

TEST(MediaBridge, OnHandsetRtpForwardsNormallyWhenNotHeld) {
	Fixture f;
	ASSERT_TRUE(f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
	ASSERT_TRUE(f.sender.stop("call-1"));   // issue #135
	wireLoopbackEcho(f);

	const auto tick = ulawTick(0xFF);   // mu-law silence -> PCM16 0
	f.bridge.onHandsetRtp(tick.data(), tick.size());

	// Not held: the handset's real audio reaches the anchor, which echoes it
	// straight back through feedRx() into the playout buffer.
	EXPECT_EQ(f.bridge.getPlayoutBuffer().getLength(), HoldMusic::BYTES_PER_TICK);
}

TEST(MediaBridge, OnHandsetRtpDiscardsAudioWhileHeldInAnchorMode) {
	Fixture f;
	ASSERT_TRUE(f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
	ASSERT_TRUE(f.sender.stop("call-1"));   // issue #135
	wireLoopbackEcho(f);

	f.bridge.setHeld(true);
	const auto tick = ulawTick(0xFF);
	f.bridge.onHandsetRtp(tick.data(), tick.size());

	// Issue #218: while held, the handset's real audio must NOT reach the
	// anchor -- feedMohTick() (tested below) is what feeds the anchor now.
	// A held handset that still got through would mean the far end hears
	// the muted/comfort-noise handset instead of hold music, or worse, both
	// interleaved.
	EXPECT_EQ(f.bridge.getPlayoutBuffer().getLength(), 0u);

	// Resuming restores the normal path immediately.
	f.bridge.setHeld(false);
	f.bridge.onHandsetRtp(tick.data(), tick.size());
	EXPECT_EQ(f.bridge.getPlayoutBuffer().getLength(), HoldMusic::BYTES_PER_TICK);
}

TEST(MediaBridge, FeedMohTickForwardsDecodedAudioToAnchorWhenHeldAndActive) {
	Fixture f;
	ASSERT_TRUE(f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
	ASSERT_TRUE(f.sender.stop("call-1"));   // issue #135
	wireLoopbackEcho(f);
	f.bridge.setHeld(true);

	// 0xAA, not 0xFF (silence) -- so a non-zero decode proves the tick was
	// actually decoded, not just that some default-initialised buffer landed
	// in the playout buffer.
	const auto tick = ulawTick(0xAA);
	f.bridge.feedMohTick(tick.data(), tick.size());

	ASSERT_EQ(f.bridge.getPlayoutBuffer().getLength(), HoldMusic::BYTES_PER_TICK);
	std::vector<int16_t> out(HoldMusic::BYTES_PER_TICK);
	ASSERT_TRUE(f.bridge.getPlayoutBuffer().read(out.data(), out.size()));

	const int16_t expected = RtpReceiver::mulawDecode(0xAA);
	EXPECT_NE(expected, 0);   // sanity: 0xAA is not the silence code
	for (int16_t v : out) EXPECT_EQ(v, expected);
}

TEST(MediaBridge, FeedMohTickIsANoOpWhenNotHeld) {
	Fixture f;
	ASSERT_TRUE(f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
	ASSERT_TRUE(f.sender.stop("call-1"));   // issue #135
	wireLoopbackEcho(f);

	const auto tick = ulawTick(0xAA);
	f.bridge.feedMohTick(tick.data(), tick.size());   // isHeld() == false

	EXPECT_EQ(f.bridge.getPlayoutBuffer().getLength(), 0u);
}

TEST(MediaBridge, FeedMohTickIsANoOpWhenInactive) {
	Fixture f;
	// Never started -- setHeld() itself doesn't require an active bridge (it
	// only gates the HoldMusic tap registration), but feedMohTick() must
	// still refuse to write into an anchor no bridge is actually serving.
	f.bridge.setHeld(true);
	const auto tick = ulawTick(0xAA);
	f.bridge.feedMohTick(tick.data(), tick.size());   // must not crash
	EXPECT_EQ(f.bridge.getPlayoutBuffer().getLength(), 0u);
}

TEST(MediaBridge, StopBridgeResetsHeldState) {
	Fixture f;
	ASSERT_TRUE(f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
	f.bridge.setHeld(true);
	ASSERT_TRUE(f.bridge.isHeld());

	f.bridge.stopBridge();
	EXPECT_FALSE(f.bridge.isHeld());
}

TEST(MediaBridge, FeedMohTickAfterStopBridgeIsANoOp) {
	// Issue #218 follow-up (PD-Opus's vet of PR #239): HoldMusic snapshots a
	// tap's {fn, ctx} under its OWN _mutex, then invokes it only AFTER
	// releasing that lock (see HoldMusic::tickLocked()'s doc comment -- the
	// whole point of the fix this test guards is that a tap invocation must
	// never happen while HoldMusic::_mutex is held, since a tap can block on
	// a real network write). That means a snapshotted invocation can still be
	// in flight after stopBridge() has already torn this bridge down. This is
	// the direct regression test for the guard that makes that safe: even
	// with no timing games, calling feedMohTick() straight after
	// stopBridge() must be a clean no-op, not a write into a torn-down (or,
	// in the fixed-size bridge pool, potentially already-reused) slot.
	Fixture f;
	ASSERT_TRUE(f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
	ASSERT_TRUE(f.sender.stop("call-1"));   // issue #135
	wireLoopbackEcho(f);
	f.bridge.setHeld(true);

	f.bridge.stopBridge();

	const auto tick = ulawTick(0xAA);
	f.bridge.feedMohTick(tick.data(), tick.size());   // must not crash or deliver

	EXPECT_EQ(f.bridge.getPlayoutBuffer().getLength(), 0u);
}

TEST(MediaBridge, StopBridgeReleasesTheHeldTapSoItDoesNotLeakIntoTheNextCall) {
	// Needs a real, running HoldMusic (not just Fixture's LoopbackAnchorClient)
	// to exercise setHeld()'s actual addTap()/removeTap() calls, not just the
	// _held flag -- same temp-file pattern HoldMusic_test.cpp uses.
	HoldMusic moh;
	{
		// Minimal mu-law WAV, inlined rather than pulled from HoldMusic_test.cpp
		// (different translation unit, no shared header for it).
		auto put32 = [](std::vector<uint8_t>& v, uint32_t x) {
			v.push_back(uint8_t(x)); v.push_back(uint8_t(x >> 8));
			v.push_back(uint8_t(x >> 16)); v.push_back(uint8_t(x >> 24));
		};
		auto put16 = [](std::vector<uint8_t>& v, uint16_t x) {
			v.push_back(uint8_t(x)); v.push_back(uint8_t(x >> 8));
		};
		auto putTag = [](std::vector<uint8_t>& v, const char* t) { v.insert(v.end(), t, t + 4); };
		const size_t dataBytes = HoldMusic::BYTES_PER_TICK;
		std::vector<uint8_t> body;
		putTag(body, "WAVE");
		putTag(body, "fmt "); put32(body, 18);
		put16(body, 7); put16(body, 1); put32(body, 8000); put32(body, 8000);
		put16(body, 1); put16(body, 8); put16(body, 0);
		putTag(body, "fact"); put32(body, 4); put32(body, uint32_t(dataBytes));
		putTag(body, "data"); put32(body, uint32_t(dataBytes));
		body.insert(body.end(), dataBytes, 0xFF);
		std::vector<uint8_t> file;
		putTag(file, "RIFF"); put32(file, uint32_t(body.size()));
		file.insert(file.end(), body.begin(), body.end());

		const std::string path = std::string(::testing::TempDir()) + "pd_mediabridge_moh_test.wav";
		std::ofstream out(path, std::ios::binary | std::ios::trunc);
		out.write(reinterpret_cast<const char*>(file.data()), std::streamsize(file.size()));
		out.close();
		ASSERT_TRUE(moh.loadClip(path));
	}
	ASSERT_TRUE(moh.start());

	Fixture f;
	f.bridge.setHoldMusic(&moh);
	ASSERT_TRUE(f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
	f.bridge.setHeld(true);
	// One tap slot now held by this bridge -- fill the rest so a leaked tap
	// would be the only thing standing between "full" and "one free slot".
	for (int i = 1; i < POCKETDIAL_MAX_ANCHOR_CALLS; ++i)
	{
		EXPECT_GE(moh.addTap([](void*, const uint8_t*, size_t) {}, nullptr), 0)
			<< "slot " << i;
	}

	f.bridge.stopBridge();

	// If stopBridge() had not released the tap, the table would still read
	// as full (this bridge's slot plus the POCKETDIAL_MAX_ANCHOR_CALLS-1
	// filled above) and this would return -1.
	EXPECT_GE(moh.addTap([](void*, const uint8_t*, size_t) {}, nullptr), 0)
		<< "stopBridge() must have released its tap";
}

// ── Issue #280: writeAudio() failure propagation ──────────────────────────────
// LoopbackAnchorClient (the Fixture above) always succeeds, so it cannot drive
// isAudioDegraded() -- these tests need an AnchorClient whose writeAudio()
// outcome the test controls directly.

namespace
{
	class ControllableAnchorClient : public AnchorClient
	{
	public:
		bool init(const std::string&, const std::string&, const std::string&, const std::string&) override { return true; }
		bool start() override { return true; }
		void stop() override {}
		bool isConnected() const override { return true; }
		bool makeCall(const std::string&, std::string* = nullptr) override { return true; }
		bool answerCall(const std::string&) override { return true; }
		bool dropCall(const std::string&) override { return true; }
		void setEventCallback(EventCallback) override {}
		bool writeAudio(std::string_view, const int16_t*, size_t) override { return writeSucceeds; }
		void registerAudioRxCallback(AudioRxCallback) override {}
		void tick() override {}

		bool writeSucceeds = true;
	};

	struct DegradeFixture
	{
		RtpReceiver receiver;
		RtpSender sender;
		ControllableAnchorClient anchor;
		MediaBridge bridge;

		DegradeFixture()
		{
			bridge.init(&receiver, &sender, &anchor);
		}

		// Drives onHandsetRtp() `n` times with the anchor's current writeSucceeds
		// value -- one call per (simulated) 20 ms handset RTP frame.
		void pumpHandsetFrames(int n)
		{
			const auto tick = ulawTick(0xFF, HoldMusic::BYTES_PER_TICK);
			for (int i = 0; i < n; ++i)
			{
				bridge.onHandsetRtp(tick.data(), tick.size());
			}
		}
	};
}

TEST(MediaBridgeWriteAudioFailure, NeverDegradedIfItHasNeverSucceededYet) {
	// Advisor caught this before it shipped, verified against the real
	// call-setup ordering rather than taken on faith: the INBOUND anchor path
	// pre-warms the POST stream during local ringing so it's normally live by
	// the time the handset answers, but answerCall()'s own fallback re-opens
	// it AFTER the ACK already went to the handset if that pre-warm didn't
	// take -- a real ~1s TLS-handshake window in which the handset can
	// legitimately be sending RTP into a socket that isn't live yet. A
	// connection that has NEVER worked is "still starting," not "degraded" --
	// only a connection that WAS working and then broke is what #280 means by
	// that word. Without this gate, tick()'s sweep would tear down a healthy
	// call during ordinary (if slow) connection setup.
	DegradeFixture f;
	ASSERT_TRUE(f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
	ASSERT_TRUE(f.sender.stop("call-1"));   // issue #135

	f.anchor.writeSucceeds = false;
	f.pumpHandsetFrames(100);   // far past kMaxConsecutiveWriteFailures (25)

	EXPECT_FALSE(f.bridge.isAudioDegraded())
		<< "a connection that has never had a single successful write must "
		   "never be reported degraded, no matter how many failures pile up "
		   "while it's still starting";

	// The moment it actually comes up, normal degrade-on-failure behavior
	// applies again.
	f.anchor.writeSucceeds = true;
	f.pumpHandsetFrames(1);
	f.anchor.writeSucceeds = false;
	f.pumpHandsetFrames(25);
	EXPECT_TRUE(f.bridge.isAudioDegraded())
		<< "once it has genuinely worked at least once, it can degrade normally";
}

TEST(MediaBridgeWriteAudioFailure, NotDegradedBelowThreshold) {
	DegradeFixture f;
	ASSERT_TRUE(f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
	ASSERT_TRUE(f.sender.stop("call-1"));   // issue #135

	f.pumpHandsetFrames(1);   // establish "has worked at least once"
	f.anchor.writeSucceeds = false;
	f.pumpHandsetFrames(24);   // one short of MediaBridge::kMaxConsecutiveWriteFailures (25)

	EXPECT_FALSE(f.bridge.isAudioDegraded())
		<< "24 consecutive failures must not yet trip the threshold";
}

TEST(MediaBridgeWriteAudioFailure, DegradedAtThreshold) {
	DegradeFixture f;
	ASSERT_TRUE(f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
	ASSERT_TRUE(f.sender.stop("call-1"));   // issue #135

	f.pumpHandsetFrames(1);   // establish "has worked at least once"
	f.anchor.writeSucceeds = false;
	f.pumpHandsetFrames(25);

	EXPECT_TRUE(f.bridge.isAudioDegraded())
		<< "25 consecutive failures (~500ms at 20ms/frame) must trip the threshold";
}

TEST(MediaBridgeWriteAudioFailure, ASingleSuccessResetsTheStreak) {
	DegradeFixture f;
	ASSERT_TRUE(f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
	ASSERT_TRUE(f.sender.stop("call-1"));   // issue #135

	f.pumpHandsetFrames(1);   // establish "has worked at least once"
	f.anchor.writeSucceeds = false;
	f.pumpHandsetFrames(24);
	f.anchor.writeSucceeds = true;
	f.pumpHandsetFrames(1);
	f.anchor.writeSucceeds = false;
	f.pumpHandsetFrames(24);   // would be 49 straight if the streak weren't reset

	EXPECT_FALSE(f.bridge.isAudioDegraded())
		<< "one successful write between two failure runs must reset the streak, "
		   "not just delay tripping it";
}

TEST(MediaBridgeWriteAudioFailure, DegradedThroughFeedMohTickToo) {
	// feedMohTick() is the OTHER writer (the bridge is held) -- same counter,
	// same threshold, no separate accounting.
	DegradeFixture f;
	ASSERT_TRUE(f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
	ASSERT_TRUE(f.sender.stop("call-1"));   // issue #135
	f.bridge.setHeld(true);

	const auto tick = ulawTick(0xFF, HoldMusic::BYTES_PER_TICK);
	f.bridge.feedMohTick(tick.data(), tick.size());   // establish "has worked at least once"
	f.anchor.writeSucceeds = false;
	for (int i = 0; i < 25; ++i)
	{
		f.bridge.feedMohTick(tick.data(), tick.size());
	}

	EXPECT_TRUE(f.bridge.isAudioDegraded());
}

TEST(MediaBridgeWriteAudioFailure, NotDegradedWhenInactive) {
	DegradeFixture f;
	EXPECT_FALSE(f.bridge.isAudioDegraded())
		<< "an idle bridge (never started) must never report degraded";
}

TEST(MediaBridgeWriteAudioFailure, StoppingAndRestartingClearsThePreviousCallsStreak) {
	// MediaBridge instances are pooled (POCKETDIAL_MAX_ANCHOR_CALLS-sized
	// array) and reused across calls -- a fresh call on a previously-degraded
	// slot must start clean, not inherit the last caller's failure history
	// (including its "has this ever worked" flag).
	DegradeFixture f;
	ASSERT_TRUE(f.bridge.startBridge("127.0.0.1", 5004, "call-1", "part-1"));
	ASSERT_TRUE(f.sender.stop("call-1"));   // issue #135
	f.pumpHandsetFrames(1);   // establish "has worked at least once"
	f.anchor.writeSucceeds = false;
	f.pumpHandsetFrames(25);
	ASSERT_TRUE(f.bridge.isAudioDegraded());

	f.bridge.stopBridge();
	f.anchor.writeSucceeds = true;
	ASSERT_TRUE(f.bridge.startBridge("127.0.0.1", 5006, "call-2", "part-2"));
	ASSERT_TRUE(f.sender.stop("call-2"));   // issue #135

	EXPECT_FALSE(f.bridge.isAudioDegraded())
		<< "a brand new call on a reused bridge slot must not start pre-degraded";

	// And the new call still degrades normally on its own merits, once it has
	// worked at least once.
	f.pumpHandsetFrames(1);
	f.anchor.writeSucceeds = false;
	f.pumpHandsetFrames(25);
	EXPECT_TRUE(f.bridge.isAudioDegraded());
}

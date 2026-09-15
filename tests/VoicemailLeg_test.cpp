// VoicemailLeg_test.cpp — Issue #246 (voicemail Stage 3 of #194).
//
// Pure-logic core: append/bounds/force-finalize for recording, cursor fill
// for playback, and the state-machine guards that prevent an in-progress
// recording from being silently abandoned. No socket, no FreeRTOS -- this
// class holds none itself (see the class comment in VoicemailLeg.hpp).

#include <gtest/gtest.h>

#include "HoldMusic.hpp"
#include "VoicemailLeg.hpp"

TEST(VoicemailLeg, StartsIdle)
{
	VoicemailLeg leg;
	EXPECT_TRUE(leg.isIdle());
	EXPECT_EQ(leg.state(), VoicemailLeg::State::Idle);
}

TEST(VoicemailLeg, StartRecordingRefusesAZeroOrOversizedMaxBytes)
{
	VoicemailLeg leg;
	uint8_t buf[16];
	EXPECT_FALSE(leg.startRecording(buf, sizeof(buf), 0, "301", "call-1"));
	EXPECT_TRUE(leg.isIdle());
	EXPECT_FALSE(leg.startRecording(buf, sizeof(buf), sizeof(buf) + 1, "301", "call-1"));
	EXPECT_TRUE(leg.isIdle());
}

TEST(VoicemailLeg, StartRecordingRefusesANullBuffer)
{
	VoicemailLeg leg;
	EXPECT_FALSE(leg.startRecording(nullptr, 16, 16, "301", "call-1"));
	EXPECT_TRUE(leg.isIdle());
}

TEST(VoicemailLeg, OnCallerRtpAppendsAndAdvances)
{
	VoicemailLeg leg;
	uint8_t buf[16] = {};
	ASSERT_TRUE(leg.startRecording(buf, sizeof(buf), sizeof(buf), "301", "call-1"));
	EXPECT_EQ(leg.state(), VoicemailLeg::State::Recording);

	const uint8_t frame1[] = {1, 2, 3, 4};
	EXPECT_TRUE(leg.onCallerRtp(frame1, sizeof(frame1)));
	const uint8_t frame2[] = {5, 6};
	EXPECT_TRUE(leg.onCallerRtp(frame2, sizeof(frame2)));

	leg.stopRecording();
	ASSERT_EQ(leg.state(), VoicemailLeg::State::Finalizing);
	ASSERT_EQ(leg.recordedLength(), 6u);
	const uint8_t* data = leg.recordedData();
	EXPECT_EQ(data[0], 1); EXPECT_EQ(data[1], 2); EXPECT_EQ(data[2], 3); EXPECT_EQ(data[3], 4);
	EXPECT_EQ(data[4], 5); EXPECT_EQ(data[5], 6);
}

TEST(VoicemailLeg, OnCallerRtpForceFinalizesOnOverrunInsteadOfCorrupting)
{
	VoicemailLeg leg;
	uint8_t buf[8] = {};
	ASSERT_TRUE(leg.startRecording(buf, sizeof(buf), 5, "301", "call-1"));

	const uint8_t frame1[] = {1, 2, 3};
	EXPECT_TRUE(leg.onCallerRtp(frame1, sizeof(frame1)));
	EXPECT_EQ(leg.state(), VoicemailLeg::State::Recording);

	// This frame would push recordedLength to 7, past the 5-byte maxBytes cap.
	const uint8_t frame2[] = {4, 5, 6, 7};
	EXPECT_FALSE(leg.onCallerRtp(frame2, sizeof(frame2)))
		<< "the frame that would overrun the cap must be refused, not partially accepted";
	EXPECT_EQ(leg.state(), VoicemailLeg::State::Finalizing)
		<< "hitting the cap force-finalizes rather than silently dropping the frame and continuing";
	EXPECT_EQ(leg.recordedLength(), 3u) << "only the frames that fit are kept";

	// The buffer past what was actually written must be untouched -- proves the
	// refused frame was never memcpy'd in.
	EXPECT_EQ(buf[3], 0);
	EXPECT_EQ(buf[4], 0);
	EXPECT_EQ(buf[5], 0);
	EXPECT_EQ(buf[6], 0);
	EXPECT_EQ(buf[7], 0);
}

TEST(VoicemailLeg, OnCallerRtpIsANoOpWhenNotRecording)
{
	VoicemailLeg leg;
	const uint8_t frame[] = {1, 2, 3};
	EXPECT_FALSE(leg.onCallerRtp(frame, sizeof(frame)));
	EXPECT_TRUE(leg.isIdle());
}

TEST(VoicemailLeg, StopRecordingIsANoOpWhenNotRecording)
{
	VoicemailLeg leg;
	leg.stopRecording();
	EXPECT_TRUE(leg.isIdle());
}

TEST(VoicemailLeg, RecordedDataAndLengthAreEmptyOutsideFinalizing)
{
	VoicemailLeg leg;
	uint8_t buf[8] = {};
	EXPECT_EQ(leg.recordedData(), nullptr);
	EXPECT_EQ(leg.recordedLength(), 0u);

	ASSERT_TRUE(leg.startRecording(buf, sizeof(buf), sizeof(buf), "301", "call-1"));
	const uint8_t frame[] = {9};
	leg.onCallerRtp(frame, sizeof(frame));
	// Still Recording, not yet finalized -- must not expose partial data.
	EXPECT_EQ(leg.recordedData(), nullptr);
	EXPECT_EQ(leg.recordedLength(), 0u);
}

TEST(VoicemailLeg, StartRecordingRefusedWhileAlreadyRecording)
{
	VoicemailLeg leg;
	uint8_t bufA[8] = {}, bufB[8] = {};
	ASSERT_TRUE(leg.startRecording(bufA, sizeof(bufA), sizeof(bufA), "301", "call-1"));
	const uint8_t frame[] = {1, 2, 3};
	leg.onCallerRtp(frame, sizeof(frame));

	EXPECT_FALSE(leg.startRecording(bufB, sizeof(bufB), sizeof(bufB), "302", "call-2"))
		<< "must never silently abandon an in-progress, not-yet-finalized recording";
	EXPECT_EQ(leg.state(), VoicemailLeg::State::Recording);
	EXPECT_EQ(leg.extension(), "301");
}

TEST(VoicemailLeg, ResetReturnsToIdleFromAnyState)
{
	VoicemailLeg leg;
	uint8_t buf[8] = {};
	ASSERT_TRUE(leg.startRecording(buf, sizeof(buf), sizeof(buf), "301", "call-1"));
	leg.reset();
	EXPECT_TRUE(leg.isIdle());
	EXPECT_EQ(leg.extension(), "");
	EXPECT_EQ(leg.callId(), "");
}

TEST(VoicemailLeg, StartPlayingFillsFromClipSequentially)
{
	VoicemailLeg leg;
	const uint8_t clip[] = {10, 20, 30, 40, 50, 60};
	ASSERT_TRUE(leg.startPlaying(clip, sizeof(clip), "301", "call-1"));
	EXPECT_EQ(leg.state(), VoicemailLeg::State::Playing);

	uint8_t out[3] = {};
	EXPECT_TRUE(leg.fillTx(out, sizeof(out)));
	EXPECT_EQ(out[0], 10); EXPECT_EQ(out[1], 20); EXPECT_EQ(out[2], 30);
	EXPECT_EQ(leg.state(), VoicemailLeg::State::Playing) << "clip not exhausted yet";

	EXPECT_TRUE(leg.fillTx(out, sizeof(out)));
	EXPECT_EQ(out[0], 40); EXPECT_EQ(out[1], 50); EXPECT_EQ(out[2], 60);
}

TEST(VoicemailLeg, PlaybackIsOneShotNotALoop)
{
	// Found in review: HoldMusic::advanceCursor() wraps (it's a looping radio
	// station); voicemail playback must play ONCE and signal done, or a "press
	// 1 to delete" menu can never be driven off it.
	VoicemailLeg leg;
	const uint8_t clip[] = {1, 2, 3};
	ASSERT_TRUE(leg.startPlaying(clip, sizeof(clip), "301", "call-1"));

	uint8_t out[3] = {};
	EXPECT_TRUE(leg.fillTx(out, sizeof(out)));
	EXPECT_EQ(leg.state(), VoicemailLeg::State::PlaybackDone);
	EXPECT_TRUE(leg.playbackDone());

	// No more real audio comes out -- must not wrap back to the start.
	EXPECT_FALSE(leg.fillTx(out, sizeof(out)))
		<< "fillTx must refuse (silence) once the clip is fully delivered, not loop";
}

TEST(VoicemailLeg, PlaybackPadsTheFinalPartialFrameWithSilenceAndSignalsDone)
{
	VoicemailLeg leg;
	const uint8_t clip[] = {7, 8, 9};  // 3 bytes, requested in a 5-byte frame
	ASSERT_TRUE(leg.startPlaying(clip, sizeof(clip), "301", "call-1"));

	uint8_t out[5] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
	EXPECT_TRUE(leg.fillTx(out, sizeof(out)));
	EXPECT_EQ(out[0], 7); EXPECT_EQ(out[1], 8); EXPECT_EQ(out[2], 9);
	EXPECT_EQ(out[3], HoldMusic::kUlawSilence);
	EXPECT_EQ(out[4], HoldMusic::kUlawSilence);
	EXPECT_EQ(leg.state(), VoicemailLeg::State::PlaybackDone);
}

TEST(VoicemailLeg, PlaybackDoneIsFalseOutsidePlaybackDoneState)
{
	VoicemailLeg leg;
	EXPECT_FALSE(leg.playbackDone());
	uint8_t buf[4] = {};
	ASSERT_TRUE(leg.startRecording(buf, sizeof(buf), sizeof(buf), "301", "call-1"));
	EXPECT_FALSE(leg.playbackDone());
}

TEST(VoicemailLeg, StartRecordingRefusedWhileFinalizing)
{
	VoicemailLeg leg;
	uint8_t bufA[8] = {}, bufB[8] = {};
	ASSERT_TRUE(leg.startRecording(bufA, sizeof(bufA), sizeof(bufA), "301", "call-1"));
	const uint8_t frame[] = {1, 2, 3};
	leg.onCallerRtp(frame, sizeof(frame));
	leg.stopRecording();
	ASSERT_EQ(leg.state(), VoicemailLeg::State::Finalizing);

	EXPECT_FALSE(leg.startRecording(bufB, sizeof(bufB), sizeof(bufB), "302", "call-2"))
		<< "a Finalizing recording must not be silently discarded by a new one -- reset() first";
	EXPECT_EQ(leg.state(), VoicemailLeg::State::Finalizing);
	EXPECT_EQ(leg.recordedLength(), 3u) << "the not-yet-handed-off recording must still be intact";
}

TEST(VoicemailLeg, StartPlayingRefusedWhileFinalizing)
{
	VoicemailLeg leg;
	uint8_t buf[8] = {};
	ASSERT_TRUE(leg.startRecording(buf, sizeof(buf), sizeof(buf), "301", "call-1"));
	leg.stopRecording();
	ASSERT_EQ(leg.state(), VoicemailLeg::State::Finalizing);

	const uint8_t clip[] = {1, 2, 3};
	EXPECT_FALSE(leg.startPlaying(clip, sizeof(clip), "301", "call-1"))
		<< "a Finalizing recording must not be silently discarded by starting playback -- reset() first";
	EXPECT_EQ(leg.state(), VoicemailLeg::State::Finalizing);
}

TEST(VoicemailLeg, StartRecordingAllowedAfterPlaybackDone)
{
	// The intended deposit-call flow: play the greeting to completion, then
	// record -- PlaybackDone must not block this the way Finalizing does.
	VoicemailLeg leg;
	const uint8_t clip[] = {1, 2, 3};
	ASSERT_TRUE(leg.startPlaying(clip, sizeof(clip), "301", "call-1"));
	uint8_t discard[3];
	leg.fillTx(discard, sizeof(discard));
	ASSERT_EQ(leg.state(), VoicemailLeg::State::PlaybackDone);

	uint8_t buf[8] = {};
	EXPECT_TRUE(leg.startRecording(buf, sizeof(buf), sizeof(buf), "301", "call-1"));
	EXPECT_EQ(leg.state(), VoicemailLeg::State::Recording);
}

TEST(VoicemailLeg, FillTxReturnsFalseWhenNotPlaying)
{
	VoicemailLeg leg;
	uint8_t out[4] = {};
	EXPECT_FALSE(leg.fillTx(out, sizeof(out)));
}

TEST(VoicemailLeg, StartPlayingRefusesAnEmptyClip)
{
	// Found in review: without this guard, a null or zero-length clip enters
	// Playing, fillTx() then returns false forever, and the leg never reaches
	// PlaybackDone -- an empty/failed-to-load greeting would hang the leg in
	// Playing until an explicit reset().
	VoicemailLeg leg;
	const uint8_t clip[] = {1};
	EXPECT_FALSE(leg.startPlaying(nullptr, 0, "301", "call-1"));
	EXPECT_TRUE(leg.isIdle());
	EXPECT_FALSE(leg.startPlaying(nullptr, 4, "301", "call-1"));
	EXPECT_TRUE(leg.isIdle());
	EXPECT_FALSE(leg.startPlaying(clip, 0, "301", "call-1"));
	EXPECT_TRUE(leg.isIdle());
}

TEST(VoicemailLeg, StartPlayingRefusedWhileRecording)
{
	VoicemailLeg leg;
	uint8_t buf[8] = {};
	ASSERT_TRUE(leg.startRecording(buf, sizeof(buf), sizeof(buf), "301", "call-1"));
	const uint8_t clip[] = {1, 2, 3};
	EXPECT_FALSE(leg.startPlaying(clip, sizeof(clip), "301", "call-1"))
		<< "must never silently abandon an in-progress, not-yet-finalized recording";
	EXPECT_EQ(leg.state(), VoicemailLeg::State::Recording);
}

TEST(VoicemailLeg, StartPlayingThenStartRecordingIsAllowed)
{
	// The intended deposit-call flow: play the greeting, then record.
	VoicemailLeg leg;
	const uint8_t clip[] = {1, 2, 3};
	ASSERT_TRUE(leg.startPlaying(clip, sizeof(clip), "301", "call-1"));

	uint8_t buf[8] = {};
	EXPECT_TRUE(leg.startRecording(buf, sizeof(buf), sizeof(buf), "301", "call-1"));
	EXPECT_EQ(leg.state(), VoicemailLeg::State::Recording);
}

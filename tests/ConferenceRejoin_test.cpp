// ConferenceRejoin_test.cpp — Issue #513: a quick 888 re-dial must not be 486.
//
// On ESP, ConferenceRoom::leave() marks a leg free at once, but its RTP tasks take
// a few ticks to exit, and RtpSender/RtpReceiver::start() refuse while they do. join()
// used to take the FIRST free slot, which after a leave is that same slot, so
// startBridge() failed and onConferenceInvite answered 486 "room full". On the bench
// (#451 C4) that was every second call re-dialed within ~0.3 s of a BYE.
//
// The host build never shows the state on its own: its stop() joins synchronously.
// RtpSender::holdTeardownForTest() puts a leg's sender into exactly the ESP state
// (canStart() false, start() refused), and ConferenceRoom::legSenderForTest() reaches
// a leg that has already left. With the old join() these tests fail the same way the
// board did: join() returns -1.

#include <gtest/gtest.h>

#include <string>

#include "ConferenceRoom.hpp"
#include "RtpSender.hpp"

namespace
{
	// Fill the room, then empty it, so every leg has been used once and is free.
	void fillAndEmpty(ConferenceRoom& room, uint16_t basePort)
	{
		for (int i = 0; i < ConferenceRoom::MAX_LEGS; ++i)
		{
			ASSERT_EQ(room.join("fill-" + std::to_string(i), "10" + std::to_string(i),
				"127.0.0.1", static_cast<uint16_t>(basePort + i)), i);
		}
		for (int i = 0; i < ConferenceRoom::MAX_LEGS; ++i)
		{
			ASSERT_TRUE(room.leave("fill-" + std::to_string(i)));
		}
		// No driver runs here: one tick returns the Draining bus ports to Free, so
		// a refusal below can only come from the legs, not from a full bus.
		room.tickOnce();
		ASSERT_EQ(room.legCount(), 0);
	}

	void holdStopping(ConferenceRoom& room, int leg, bool stopping)
	{
		RtpSender* tx = room.legSenderForTest(leg);
		ASSERT_NE(tx, nullptr);
		tx->holdTeardownForTest(stopping);
	}
}

TEST(ConferenceRejoin, AQuickRedialSkipsTheLegThatIsStillStopping)
{
	ConferenceRoom room;
	ASSERT_EQ(room.join("call-1", "101", "127.0.0.1", 16001), 0);
	ASSERT_TRUE(room.leave("call-1"));

	// The re-dial arrives while leg 0's media is still winding down.
	holdStopping(room, 0, true);
	EXPECT_EQ(room.join("call-2", "101", "127.0.0.1", 16002), 1)
		<< "a free leg that cannot start yet must be skipped, not answered 486";
	EXPECT_EQ(room.legCount(), 1);
	EXPECT_TRUE(room.hasLeg("call-2"));

	holdStopping(room, 0, false);
	EXPECT_TRUE(room.leave("call-2"));
}

TEST(ConferenceRejoin, JoinIsRefusedOnlyWhenNoFreeLegCanStart)
{
	ConferenceRoom room;
	ASSERT_NO_FATAL_FAILURE(fillAndEmpty(room, 16100));

	for (int i = 0; i < ConferenceRoom::MAX_LEGS; ++i) holdStopping(room, i, true);
	EXPECT_LT(room.join("call-x", "101", "127.0.0.1", 16110), 0)
		<< "every free leg is still stopping: nothing can start, so refuse";
	EXPECT_EQ(room.legCount(), 0);

	// One leg finishes stopping: the join lands exactly there.
	const int last = ConferenceRoom::MAX_LEGS - 1;
	holdStopping(room, last, false);
	EXPECT_EQ(room.join("call-x", "101", "127.0.0.1", 16110), last);

	for (int i = 0; i < ConferenceRoom::MAX_LEGS; ++i) holdStopping(room, i, false);
	EXPECT_TRUE(room.leave("call-x"));
}

TEST(ConferenceRejoin, ALegThatHasFinishedStoppingIsReusedAgain)
{
	// Skipping is only for as long as the leg is stopping: once it can start, the
	// first free slot is used again, as before #513.
	ConferenceRoom room;
	ASSERT_EQ(room.join("call-1", "101", "127.0.0.1", 16201), 0);
	ASSERT_TRUE(room.leave("call-1"));
	holdStopping(room, 0, true);
	holdStopping(room, 0, false);
	EXPECT_EQ(room.join("call-2", "101", "127.0.0.1", 16202), 0);
	EXPECT_TRUE(room.leave("call-2"));
}

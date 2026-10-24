// OutboundLegStatus_test.cpp -- #949 item 1 (Rule 5): the tel_wsw worker's status read for an
// outbound leg. TelephonyAnchorClient.cpp is ESP-only, so these drive src/SIP/SosStatusGet.hpp,
// the code the worker calls. Owner ruling (#949, 2026-10-20): on an emergency slot an empty or
// failed read is UNKNOWN, not "not Connected" and not answered.

#include <gtest/gtest.h>

#include <string>

#include "SosStatusGet.hpp"

namespace
{
using namespace telephony;

// A scripted status source. The shared lane is "held by another caller": it reads "" (the GET
// cannot be had in time). sosReplies are handed out one per read on the sos lane; past the end, "".
struct Source
{
	std::string sharedReply;
	std::string sosReplies[4];
	int sharedReads = 0;
	int sosReads = 0;
	int pauses = 0;

	std::string read(bool sosLane)
	{
		if (!sosLane) { ++sharedReads; return sharedReply; }
		const int i = sosReads++;
		return i < 4 ? sosReplies[i] : std::string();
	}
	std::string run(bool emergency)
	{
		return readOutboundLegStatus(emergency, [this](bool lane) { return read(lane); }, [this] { ++pauses; });
	}
};

TEST(OutboundLegStatus, AnEmergencySlotReadsTheSosLaneSoASharedLockHolderCannotDelayAnswered)
{
	Source src;
	src.sharedReply = "";                 // another caller holds the shared status lock
	src.sosReplies[0] = "Connected";
	const std::string st = src.run(true);
	EXPECT_EQ(st, "Connected");
	EXPECT_EQ(src.sharedReads, 0) << "an emergency slot never touches the shared lane";
	EXPECT_EQ(src.sosReads, 1);
	EXPECT_EQ(outboundStep(st, true), OutboundStep::Answered);
}

TEST(OutboundLegStatus, AnEmptyReadOnAnEmergencySlotIsUnknownNotAnsweredNotDialing)
{
	Source src;
	const std::string st = src.run(true);     // every read empty
	EXPECT_TRUE(st.empty());
	EXPECT_EQ(outboundStep(st, true), OutboundStep::Unknown);
	EXPECT_NE(outboundStep(st, true), OutboundStep::Answered);
	EXPECT_NE(outboundStep(st, true), OutboundStep::Dialing);
}

TEST(OutboundLegStatus, AnEmergencySlotReAsksAFewTimesAndAnswersOnTheFirstGoodRead)
{
	Source src;
	src.sosReplies[2] = "Connected";         // claim held twice, then free
	const std::string st = src.run(true);
	EXPECT_EQ(st, "Connected");
	EXPECT_EQ(src.sosReads, 3);
	EXPECT_EQ(src.pauses, 2);
	EXPECT_EQ(outboundStep(st, true), OutboundStep::Answered);
}

TEST(OutboundLegStatus, TheReAskIsBoundedAtThreeReadsWithTwoPauses)
{
	Source src;
	(void)src.run(true);
	EXPECT_EQ(src.sosReads, kEmergencyStatusReads);
	EXPECT_EQ(kEmergencyStatusReads, 3);
	EXPECT_EQ(src.pauses, kEmergencyStatusReads - 1);
}

TEST(OutboundLegStatus, ANonEmptyNonConnectedReadOnAnEmergencySlotIsDialingAndIsNotReAsked)
{
	Source src;
	src.sosReplies[0] = "Dialing";
	const std::string st = src.run(true);
	EXPECT_EQ(st, "Dialing");
	EXPECT_EQ(src.sosReads, 1);
	EXPECT_EQ(src.pauses, 0);
	EXPECT_EQ(outboundStep(st, true), OutboundStep::Dialing);
}

TEST(OutboundLegStatus, ControlANonEmergencySlotIsUnchanged)
{
	Source src;
	src.sharedReply = "Connected";
	src.sosReplies[0] = "Dialing";            // must never be consulted
	EXPECT_EQ(src.run(false), "Connected");
	EXPECT_EQ(src.sharedReads, 1);
	EXPECT_EQ(src.sosReads, 0);
	EXPECT_EQ(outboundStep("Connected", false), OutboundStep::Answered);

	Source empty;                             // one shot, no re-ask, empty is Dialing as before
	EXPECT_TRUE(empty.run(false).empty());
	EXPECT_EQ(empty.sharedReads, 1);
	EXPECT_EQ(empty.pauses, 0);
	EXPECT_EQ(outboundStep("", false), OutboundStep::Dialing);
	EXPECT_EQ(outboundStep("Dialing", false), OutboundStep::Dialing);
}

}  // namespace

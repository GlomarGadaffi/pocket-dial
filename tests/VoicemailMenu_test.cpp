// VoicemailMenu_test.cpp -- Issue #246 (voicemail Stage 3 of #194), retrieval
// slice 2 of 3. Pure state-machine tests: no RequestsHandler, no RTP, no
// filesystem -- just digits/playbackDone in, Command out.

#include <gtest/gtest.h>

#include "VoicemailMenu.hpp"

TEST(VoicemailMenu, EmptyBoxPlaysThePromptThenHangsUpWhenItFinishes)
{
	VoicemailMenu menu;
	auto r = menu.start(0);
	EXPECT_EQ(r.command, VoicemailMenu::Command::PlayPrompt);
	EXPECT_EQ(r.playIndex, -1);
	EXPECT_EQ(r.deleteIndex, -1);

	r = menu.onPlaybackDone();
	EXPECT_EQ(r.command, VoicemailMenu::Command::Hangup);
	EXPECT_TRUE(menu.isDone());
}

TEST(VoicemailMenu, AnyDigitDuringThePromptHangsUpImmediately)
{
	VoicemailMenu menu;
	menu.start(0);
	auto r = menu.onDigit('5');
	EXPECT_EQ(r.command, VoicemailMenu::Command::Hangup);
	EXPECT_TRUE(menu.isDone());
}

TEST(VoicemailMenu, StartWithMessagesPlaysTheFirstOneImmediately)
{
	VoicemailMenu menu;
	auto r = menu.start(3);
	EXPECT_EQ(r.command, VoicemailMenu::Command::PlayMessage);
	EXPECT_EQ(r.playIndex, 0);
	EXPECT_EQ(r.deleteIndex, -1);
}

TEST(VoicemailMenu, PlaybackDoneAdvancesToTheNextMessage)
{
	VoicemailMenu menu;
	menu.start(2);
	auto r = menu.onPlaybackDone();
	EXPECT_EQ(r.command, VoicemailMenu::Command::PlayMessage);
	EXPECT_EQ(r.playIndex, 1);
}

TEST(VoicemailMenu, PlaybackDoneOnTheLastMessageHangsUp)
{
	VoicemailMenu menu;
	menu.start(1);
	auto r = menu.onPlaybackDone();
	EXPECT_EQ(r.command, VoicemailMenu::Command::Hangup);
	EXPECT_TRUE(menu.isDone());
}

TEST(VoicemailMenu, HashSkipsToTheNextMessageWithoutDeleting)
{
	VoicemailMenu menu;
	menu.start(2);
	auto r = menu.onDigit('#');
	EXPECT_EQ(r.command, VoicemailMenu::Command::PlayMessage);
	EXPECT_EQ(r.playIndex, 1);
	EXPECT_EQ(r.deleteIndex, -1) << "skip must not also delete";
}

TEST(VoicemailMenu, SevenDeletesTheCurrentMessageAndPlaysTheNext)
{
	VoicemailMenu menu;
	menu.start(2);
	auto r = menu.onDigit('7');
	EXPECT_EQ(r.command, VoicemailMenu::Command::PlayMessage);
	EXPECT_EQ(r.playIndex, 1);
	EXPECT_EQ(r.deleteIndex, 0) << "must delete the message that WAS playing, index 0";
}

TEST(VoicemailMenu, SevenOnTheLastMessageDeletesAndHangsUp)
{
	VoicemailMenu menu;
	menu.start(1);
	auto r = menu.onDigit('7');
	EXPECT_EQ(r.command, VoicemailMenu::Command::Hangup);
	EXPECT_EQ(r.deleteIndex, 0)
		<< "the wiring layer must check deleteIndex even when command is Hangup";
	EXPECT_TRUE(menu.isDone());
}

TEST(VoicemailMenu, StarHangsUpImmediatelyMidMessageWithNoDelete)
{
	VoicemailMenu menu;
	menu.start(3);
	auto r = menu.onDigit('*');
	EXPECT_EQ(r.command, VoicemailMenu::Command::Hangup);
	EXPECT_EQ(r.deleteIndex, -1) << "* must never delete";
	EXPECT_TRUE(menu.isDone());
}

TEST(VoicemailMenu, AnUnrecognizedDigitIsIgnored)
{
	VoicemailMenu menu;
	menu.start(2);
	auto r = menu.onDigit('4');
	EXPECT_EQ(r.command, VoicemailMenu::Command::None);
	EXPECT_FALSE(menu.isDone());

	// State must be unaffected -- the NEXT playbackDone still advances from
	// message 0, not message 1.
	r = menu.onPlaybackDone();
	EXPECT_EQ(r.command, VoicemailMenu::Command::PlayMessage);
	EXPECT_EQ(r.playIndex, 1);
}

TEST(VoicemailMenu, EventsAfterDoneAreAllNoOps)
{
	VoicemailMenu menu;
	menu.start(0);
	menu.onPlaybackDone();
	ASSERT_TRUE(menu.isDone());

	EXPECT_EQ(menu.onDigit('7').command, VoicemailMenu::Command::None);
	EXPECT_EQ(menu.onPlaybackDone().command, VoicemailMenu::Command::None);
}

TEST(VoicemailMenu, EventsBeforeStartAreNoOps)
{
	VoicemailMenu menu;
	EXPECT_EQ(menu.onDigit('7').command, VoicemailMenu::Command::None);
	EXPECT_EQ(menu.onPlaybackDone().command, VoicemailMenu::Command::None);
	EXPECT_FALSE(menu.isDone());
}

// The exact walk from the retrieval design discussion: 3 messages -> play 0
// -> # -> play 1 -> 7 -> play 2 (delete=1) -> done -> hangup.
TEST(VoicemailMenu, FullWalkThroughThreeMessagesWithASkipAndADelete)
{
	VoicemailMenu menu;
	auto r = menu.start(3);
	ASSERT_EQ(r.command, VoicemailMenu::Command::PlayMessage);
	ASSERT_EQ(r.playIndex, 0);

	r = menu.onDigit('#');
	ASSERT_EQ(r.command, VoicemailMenu::Command::PlayMessage);
	ASSERT_EQ(r.playIndex, 1);
	ASSERT_EQ(r.deleteIndex, -1);

	r = menu.onDigit('7');
	ASSERT_EQ(r.command, VoicemailMenu::Command::PlayMessage);
	ASSERT_EQ(r.playIndex, 2);
	ASSERT_EQ(r.deleteIndex, 1);

	r = menu.onPlaybackDone();
	EXPECT_EQ(r.command, VoicemailMenu::Command::Hangup);
	EXPECT_TRUE(menu.isDone());
}

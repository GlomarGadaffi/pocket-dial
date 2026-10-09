// IvrMenu_test.cpp -- Issue #168 (IVR / auto-attendant digit routing), host-only
// digit-menu slice. Pure state-machine tests: digits and timeouts in, Result out.

#include <gtest/gtest.h>

#include "IvrMenu.hpp"

TEST(IvrMenu, ValidDigitRoutesToItsBoundTarget)
{
	IvrMenu menu;
	ASSERT_TRUE(menu.bind('1', 2001));
	ASSERT_TRUE(menu.bind('2', 3001));

	auto r = menu.onDigit('2');
	EXPECT_EQ(r.command, IvrMenu::Command::Route);
	EXPECT_EQ(r.target, 3001);
	EXPECT_TRUE(menu.isDone());
	EXPECT_EQ(menu.onDigit('1').command, IvrMenu::Command::None) << "a routed menu is finished";
}

TEST(IvrMenu, UnknownDigitReplaysThePromptAndDoesNotRoute)
{
	IvrMenu menu;
	ASSERT_TRUE(menu.bind('1', 2001));

	auto r = menu.onDigit('9');
	EXPECT_EQ(r.command, IvrMenu::Command::Replay);
	EXPECT_EQ(r.target, -1);
	EXPECT_FALSE(menu.isDone());
}

TEST(IvrMenu, TimeoutIsAFailedAttemptAndAValidDigitStillRoutes)
{
	IvrMenu menu;
	ASSERT_TRUE(menu.bind('1', 2001));

	EXPECT_EQ(menu.onTimeout().command, IvrMenu::Command::Replay);
	auto r = menu.onDigit('1');
	EXPECT_EQ(r.command, IvrMenu::Command::Route);
	EXPECT_EQ(r.target, 2001);
}

TEST(IvrMenu, ValidDigitOnTheLastAllowedAttemptStillRoutes)
{
	IvrMenu menu;
	ASSERT_TRUE(menu.bind('1', 2001));

	for (int i = 0; i < IvrMenu::kMaxFailures - 1; ++i)
	{
		EXPECT_EQ(menu.onTimeout().command, IvrMenu::Command::Replay) << "failure " << i + 1;
	}
	auto r = menu.onDigit('1');
	EXPECT_EQ(r.command, IvrMenu::Command::Route);
	EXPECT_EQ(r.target, 2001);
}

TEST(IvrMenu, RetryLimitGivesUpAndLaterEventsAreNoOps)
{
	IvrMenu menu;
	ASSERT_TRUE(menu.bind('1', 2001));

	for (int i = 0; i < IvrMenu::kMaxFailures - 1; ++i)
	{
		EXPECT_EQ(menu.onDigit('x').command, IvrMenu::Command::Replay) << "failure " << i + 1;
	}
	auto r = menu.onDigit('x');
	EXPECT_EQ(r.command, IvrMenu::Command::GiveUp);
	EXPECT_EQ(r.target, -1);
	EXPECT_TRUE(menu.isDone());

	EXPECT_EQ(menu.onDigit('1').command, IvrMenu::Command::None) << "a given-up menu never routes";
	EXPECT_EQ(menu.onTimeout().command, IvrMenu::Command::None);
}

TEST(IvrMenu, ResetRevivesAMenuThatGaveUpAndKeepsTheTable)
{
	IvrMenu menu;
	ASSERT_TRUE(menu.bind('1', 2001));
	for (int i = 0; i < IvrMenu::kMaxFailures; ++i)
	{
		menu.onTimeout();
	}
	ASSERT_TRUE(menu.isDone());

	menu.reset();
	EXPECT_FALSE(menu.isDone());
	auto r = menu.onDigit('1');
	EXPECT_EQ(r.command, IvrMenu::Command::Route);
	EXPECT_EQ(r.target, 2001);
}

TEST(IvrMenu, ResetClearsTheFailureCount)
{
	IvrMenu menu;
	ASSERT_TRUE(menu.bind('1', 2001));
	for (int i = 0; i < IvrMenu::kMaxFailures - 1; ++i)
	{
		menu.onTimeout();
	}

	menu.reset();
	for (int i = 0; i < IvrMenu::kMaxFailures - 1; ++i)
	{
		EXPECT_EQ(menu.onTimeout().command, IvrMenu::Command::Replay) << "post-reset failure " << i + 1;
	}
	EXPECT_EQ(menu.onDigit('1').command, IvrMenu::Command::Route);
}

TEST(IvrMenu, EmptyTableNeverRoutes)
{
	for (char digit = '0'; digit <= '9'; ++digit)
	{
		IvrMenu menu;
		EXPECT_NE(menu.onDigit(digit).command, IvrMenu::Command::Route) << "digit " << digit;
	}

	IvrMenu menu;
	IvrMenu::Result r;
	for (int i = 0; i < IvrMenu::kMaxFailures; ++i)
	{
		r = menu.onTimeout();
	}
	EXPECT_EQ(r.command, IvrMenu::Command::GiveUp) << "an empty menu still gives up on timeouts";
	EXPECT_TRUE(menu.isDone());
}

TEST(IvrMenu, BindRefusesNonDigitsAndNegativeTargetsAndLeavesTheTableAlone)
{
	IvrMenu menu;
	EXPECT_FALSE(menu.bind('*', 1));
	EXPECT_FALSE(menu.bind('#', 1));
	EXPECT_FALSE(menu.bind('a', 1));
	EXPECT_FALSE(menu.bind('1', -1));
	EXPECT_EQ(menu.onDigit('1').command, IvrMenu::Command::Replay) << "a refused bind must not route";
}

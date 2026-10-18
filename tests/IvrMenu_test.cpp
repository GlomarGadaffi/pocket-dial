// IvrMenu_test.cpp -- Issue #168 (IVR / auto-attendant digit routing), host-only
// digit-menu slice. Pure state-machine tests: digits and timeouts in, Result out.

#include <gtest/gtest.h>

#include "IvrMenu.hpp"

TEST(IvrMenu, ValidDigitRoutesToItsBoundTarget)
{
	IvrMenu menu;
	ASSERT_TRUE(menu.bind('1', 2001));
	ASSERT_TRUE(menu.bind('2', 3001));
	ASSERT_TRUE(menu.bind('0', 0)) << "target 0 is a valid id; only a negative one is refused";
	ASSERT_TRUE(menu.bind('9', 9001));
	const IvrMenu table = menu;

	auto r = menu.onDigit('2');
	EXPECT_EQ(r.command, IvrMenu::Command::Route);
	EXPECT_EQ(r.target, 3001);
	EXPECT_TRUE(menu.isDone());
	EXPECT_EQ(menu.onDigit('1').command, IvrMenu::Command::None) << "a routed menu is finished";

	const struct
	{
		char digit;
		int target;
	} edges[] = {{'0', 0}, {'1', 2001}, {'9', 9001}};
	for (const auto& e : edges)
	{
		IvrMenu fresh = table;
		auto er = fresh.onDigit(e.digit);
		EXPECT_EQ(er.command, IvrMenu::Command::Route) << "digit " << e.digit;
		EXPECT_EQ(er.target, e.target) << "digit " << e.digit;
	}
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

TEST(IvrMenu, ResetRevivesAMenuThatGaveUpOrRoutedAndKeepsTheTable)
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

	menu.reset();
	EXPECT_FALSE(menu.isDone()) << "reset revives a menu that routed";
	r = menu.onDigit('1');
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
		EXPECT_EQ(menu.onDigit(digit).command, IvrMenu::Command::Replay) << "digit " << digit;
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
	ASSERT_TRUE(menu.bind('1', 5));
	EXPECT_FALSE(menu.bind('*', 1));
	EXPECT_FALSE(menu.bind('#', 1));
	EXPECT_FALSE(menu.bind('a', 1));
	EXPECT_FALSE(menu.bind('1', -1));
	EXPECT_FALSE(menu.bind('2', -1));
	EXPECT_EQ(menu.onDigit('2').command, IvrMenu::Command::Replay) << "a refused bind must not route";
	auto r = menu.onDigit('1');
	EXPECT_EQ(r.command, IvrMenu::Command::Route) << "a refused rebind must not unbind the digit";
	EXPECT_EQ(r.target, 5) << "a refused rebind must not change the target";
}

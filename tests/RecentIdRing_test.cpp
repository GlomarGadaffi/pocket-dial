// RecentIdRing_test.cpp -- issue #554 (b): the anchor client's ring of recently
// dropped participant ids (src/SIP/RecentIdRing.hpp). A late upsert for a leg
// in the ring must not re-prime it.

#include <gtest/gtest.h>

#include <string>

#include "RecentIdRing.hpp"

TEST(RecentIdRing, RemembersWhatWasDroppedAndNothingElse)
{
	RecentIdRing<8, 64> ring;
	EXPECT_FALSE(ring.contains("46"));
	ring.add("46");
	EXPECT_TRUE(ring.contains("46"));
	EXPECT_FALSE(ring.contains("4")) << "no prefix matches";
	EXPECT_FALSE(ring.contains("460"));
	EXPECT_FALSE(ring.contains(""));
}

TEST(RecentIdRing, TheOldestEntryIsForgottenOnceTheRingIsFull)
{
	RecentIdRing<3, 64> ring;
	ring.add("a");
	ring.add("b");
	ring.add("c");
	EXPECT_TRUE(ring.contains("a"));
	ring.add("d");
	EXPECT_FALSE(ring.contains("a")) << "bounded: the oldest is overwritten";
	EXPECT_TRUE(ring.contains("b"));
	EXPECT_TRUE(ring.contains("d"));
}

TEST(RecentIdRing, AnIdTooLongToStoreIsNeverMatchedByAPrefix)
{
	RecentIdRing<4, 8> ring;
	const std::string longId = "12345678901";
	ring.add(longId);
	EXPECT_FALSE(ring.contains(longId)) << "not recorded rather than truncated";
	EXPECT_FALSE(ring.contains("1234567"));
}

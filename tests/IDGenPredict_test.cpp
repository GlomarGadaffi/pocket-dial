// IDGenPredict_test.cpp — issue #385: IDGen::GenerateID() used to draw every
// Call-ID, tag and Via branch from a thread_local std::minstd_rand, whose 31-bit
// state is recoverable from ONE observed ID by brute force. These tests run that
// attack for real.
//
// "The IDs differ" cannot tell a CSPRNG from the LCG -- both pass it. What can
// is the attack itself: recover the engine state from one ID, predict the next,
// and check the prediction.
//
//   * OracleRecoversAKnownLcgState proves the attack works, against a local copy
//     of the OLD generator. If it ever fails, the real test below is vacuous.
//   * SLOW_ProductionIdsAreNotPredictableFromOneObservedId runs the same attack
//     against the real IDGen and asserts it fails. It was red before the fix.
//
// Each test is a full 2^31-state search (seconds, multi-threaded), so both are
// DISABLED_ by default: run with --gtest_also_run_disabled_tests
// --gtest_filter='IDGenPredict.*'. The always-on guard is IDGen_test.cpp's
// seam test.

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "IDGen.hpp"

namespace
{
	// IDGen's alphabet, duplicated here because it is private there.
	constexpr char kAlphabet[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	// The pre-#385 generator, call for call: same engine, same distribution,
	// same stdlib -- the attack must consume engine output exactly as it did.
	std::string legacyDraw(std::minstd_rand& rng, int len)
	{
		std::uniform_int_distribution<int> dist{0, static_cast<int>(sizeof(kAlphabet) - 2)};
		std::string id;
		for (int i = 0; i < len; ++i) id += kAlphabet[dist(rng)];
		return id;
	}

	// Every engine state from which the legacy generator would emit `id`.
	// Seeding minstd_rand with s (1 <= s < 2^31-1) sets its state to exactly s,
	// so the search space is the whole state space.
	std::vector<uint32_t> recoverStates(const std::string& id)
	{
		const uint32_t kModulus = std::minstd_rand::modulus;   // 2^31 - 1
		unsigned threads = std::max(1u, std::thread::hardware_concurrency());
		std::mutex m;
		std::vector<uint32_t> found;
		std::vector<std::thread> pool;
		for (unsigned t = 0; t < threads; ++t)
		{
			pool.emplace_back([&, t] {
				std::uniform_int_distribution<int> dist{0, static_cast<int>(sizeof(kAlphabet) - 2)};
				const uint64_t span = (kModulus - 1 + threads - 1) / threads;
				const uint64_t lo = 1 + t * span;
				const uint64_t hi = std::min<uint64_t>(lo + span, kModulus);
				for (uint64_t s = lo; s < hi; ++s)
				{
					std::minstd_rand r(static_cast<uint32_t>(s));
					size_t i = 0;
					while (i < id.size() && kAlphabet[dist(r)] == id[i]) ++i;
					if (i == id.size())
					{
						std::lock_guard<std::mutex> lock(m);
						found.push_back(static_cast<uint32_t>(s));
					}
				}
			});
		}
		for (auto& th : pool) th.join();
		return found;
	}

	std::string predictNext(uint32_t state, int observedLen, int nextLen)
	{
		std::minstd_rand r(state);
		legacyDraw(r, observedLen);        // replay the observed ID
		return legacyDraw(r, nextLen);     // then what it would say next
	}
}

TEST(IDGenPredict, DISABLED_OracleRecoversAKnownLcgState)
{
	std::minstd_rand victim(1234567891u % std::minstd_rand::modulus);
	const std::string observed = legacyDraw(victim, 16);   // a Call-ID
	const std::string next = legacyDraw(victim, 9);        // the tag after it

	const auto t0 = std::chrono::steady_clock::now();
	const std::vector<uint32_t> states = recoverStates(observed);
	const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now() - t0).count();
	std::printf("[ IDGenPredict ] full 2^31 search: %lld ms\n", static_cast<long long>(ms));

	ASSERT_EQ(states.size(), 1u) << "16 chars over 62 symbols should pin the 31-bit state uniquely";
	EXPECT_EQ(predictNext(states[0], 16, 9), next)
		<< "the attack must work against the legacy generator, or the test below proves nothing";
}

TEST(IDGenPredict, DISABLED_SLOW_ProductionIdsAreNotPredictableFromOneObservedId)
{
	// Same thread, back to back: exactly what an attacker exploits -- one
	// observed Call-ID, then the next identifier the same task mints.
	const std::string observed = IDGen::GenerateID(16);
	const std::string next = IDGen::GenerateID(9);

	const std::vector<uint32_t> states = recoverStates(observed);
	for (uint32_t s : states)
	{
		EXPECT_NE(predictNext(s, 16, 9), next)
			<< "one observed Call-ID predicted the next identifier: IDGen is still an LCG (#385)";
	}
}

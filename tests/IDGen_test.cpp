// IDGen_test.cpp — issue #385: always-on guards for the identifier generator.
//
// The expensive proof that IDGen is no longer predictable is the real attack in
// IDGenPredict_test.cpp (DISABLED_ by default: a 2^31 search). These are the
// cheap tests that run every time. The one that matters most is the seam test:
// it pins that GenerateID draws its bytes from fillRandom() -- the
// CSPRNG/seeded source -- and maps them by rejection sampling, so a later
// "optimisation" back to a local engine (the #385 bug) fails here immediately.

#include <gtest/gtest.h>

#include <atomic>
#include <cctype>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "IDGen.hpp"

namespace
{
	// Replays a fixed byte script, cycling.
	std::vector<uint8_t> g_script;
	std::atomic<size_t> g_cursor{0};

	void scriptedSource(uint8_t* buf, size_t len)
	{
		for (size_t i = 0; i < len; ++i) buf[i] = g_script[g_cursor++ % g_script.size()];
	}

	struct ScriptedBytes
	{
		explicit ScriptedBytes(std::vector<uint8_t> bytes)
		{
			g_script = std::move(bytes);
			g_cursor = 0;
			IDGen::setByteSourceForTest(&scriptedSource);
		}
		~ScriptedBytes() { IDGen::setByteSourceForTest(nullptr); }
	};
}

TEST(IDGen, DrawsEveryCharacterFromTheRandomSourceByRejectionSampling)
{
	// Low 6 bits pick the symbol: 0..9 digits, 10..35 upper, 36..61 lower.
	// 62 and 63 are REJECTED and redrawn (no modulo bias), and the top two
	// bits are ignored.
	ScriptedBytes bytes({
		0,               // '0'
		61,              // 'z'
		62, 63,          // rejected, consumed without output
		10,              // 'A'
		0x40 | 36,       // high bits ignored -> 'a'
		0xFF,            // & 0x3F = 63 -> rejected
		9,               // '9'
	});
	EXPECT_EQ(IDGen::GenerateID(5), "0zAa9")
		<< "GenerateID must be a pure function of fillRandom()'s bytes; anything else "
		   "means it is drawing from somewhere unaudited again (#385)";
}

TEST(IDGen, EveryCallDrawsFreshBytes)
{
	// Two calls must not reuse a block: the second continues the byte stream.
	ScriptedBytes bytes({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	                     17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32});
	const std::string a = IDGen::GenerateID(3);
	const std::string b = IDGen::GenerateID(3);
	EXPECT_EQ(a, "123");
	EXPECT_NE(a, b) << "a second call replayed the first call's bytes";
}

TEST(IDGen, RealSourceProducesTheRequestedLengthFromTheAlphabet)
{
	for (int len : {9, 12, 16, 64})
	{
		const std::string id = IDGen::GenerateID(len);
		ASSERT_EQ(id.size(), static_cast<size_t>(len));
		for (char c : id) EXPECT_TRUE(std::isalnum(static_cast<unsigned char>(c))) << id;
	}
	EXPECT_EQ(IDGen::GenerateID(0), "");
}

TEST(IDGen, RealSourceReachesTheWholeAlphabet)
{
	// Not a randomness test (IDGenPredict_test.cpp is) -- a mapping test: every
	// one of the 62 symbols must be reachable, which a bad mask or an off-by-one
	// in the rejection bound would break. 62 * ~40 draws makes a miss
	// astronomically unlikely (P < 62 * (61/62)^2500).
	std::set<char> seen;
	for (int i = 0; i < 40; ++i)
		for (char c : IDGen::GenerateID(64)) seen.insert(c);
	EXPECT_EQ(seen.size(), 62u);
}

// E164_test.cpp — E.164 normalization and equivalence (Issue #165), plus the
// DidMapping lookup that is the reason it exists.
//
// The defect this closes is a SILENT one. DidMapping::findIndex() compared DIDs
// with a raw std::string ==, so a DID configured as "(202) 555-0123" never
// matched a carrier reporting "+12025550123". Nothing errored: routeInbound-
// AnchorCall() reads "no mapping" as "fall back to ring-all", so the call still
// rang phones — just not the one the operator had configured. These tests pin
// both the new matching and, importantly, the cases it must still REFUSE to
// match, since a false positive here routes a stranger's call to the wrong desk.
//
// Every number below is from NANP's reserved fictional range (555-0100 through
// 555-0199) so no test can ever name a real line.

#include <gtest/gtest.h>

#include "E164.hpp"
#include "DidMapping.hpp"
#include "PoolConfig.hpp"

#include <cstdio>
#include <string>

using pbx::e164Normalize;
using pbx::e164SameNumber;

// ─────────────────────────────────────────────────────────────────────────────
// Normalization
// ─────────────────────────────────────────────────────────────────────────────

TEST(E164Normalize, StripsTheWaysHumansDecorateANumber)
{
	EXPECT_EQ(e164Normalize("(202) 555-0123"), "2025550123");
	EXPECT_EQ(e164Normalize("202.555.0123"), "2025550123");
	EXPECT_EQ(e164Normalize("202-555-0123"), "2025550123");
	EXPECT_EQ(e164Normalize("  202 555 0123  "), "2025550123");
	EXPECT_EQ(e164Normalize("1/202/555/0123"), "12025550123");
}

TEST(E164Normalize, KeepsTheLeadingPlusBecauseItIsTheOnlyUnambiguousCountryMarker)
{
	EXPECT_EQ(e164Normalize("+12025550123"), "+12025550123");
	EXPECT_EQ(e164Normalize("+1 (202) 555-0123"), "+12025550123");
	// Separators BEFORE the '+' are still just decoration.
	EXPECT_EQ(e164Normalize("  +1 202 555 0123"), "+12025550123");
}

TEST(E164Normalize, IsIdempotentSoCallersCanStoreTheCanonicalForm)
{
	for (const char* raw : {"(202) 555-0123", "+1 202-555-0123", "2025550123"})
	{
		const std::string once = e164Normalize(raw);
		EXPECT_EQ(e164Normalize(once), once) << "input: " << raw;
	}
}

TEST(E164Normalize, RefusesFeatureCodesAndVanityNumbersRatherThanManglingThem)
{
	// '*' and '#' are REAL dialable symbols in this PBX (*8 is group pickup,
	// **<ext> is directed pickup). Stripping them the way a separator is
	// stripped would turn a feature code into a plausible-looking number.
	EXPECT_EQ(e164Normalize("*8"), "");
	EXPECT_EQ(e164Normalize("**1001"), "");
	EXPECT_EQ(e164Normalize("#"), "");
	EXPECT_EQ(e164Normalize("1-800-FLOWERS"), "");
	EXPECT_EQ(e164Normalize("2025550123,,123"), "") << "a pause/DTMF suffix is not part of the number";
}

TEST(E164Normalize, RefusesAPlusThatIsNotTheFirstSignificantCharacter)
{
	// Silently dropping an interior '+' would turn garbage into a routable
	// number.
	EXPECT_EQ(e164Normalize("202+5550123"), "");
	EXPECT_EQ(e164Normalize("2025550123+"), "");
	EXPECT_EQ(e164Normalize("++12025550123"), "");
}

TEST(E164Normalize, RefusesInputWithNoDigitsAtAll)
{
	EXPECT_EQ(e164Normalize(""), "");
	EXPECT_EQ(e164Normalize("+"), "") << "a '+' with no digits is not a number";
	EXPECT_EQ(e164Normalize("() - "), "");
	EXPECT_EQ(e164Normalize("+ () -"), "");
}

TEST(E164Normalize, EnforcesTheITUFifteenDigitCeilingByRefusingNotTruncating)
{
	const std::string fifteen = "123456789012345";
	ASSERT_EQ(fifteen.size(), pbx::kE164MaxDigits);
	EXPECT_EQ(e164Normalize(fifteen), fifteen);
	EXPECT_EQ(e164Normalize("+" + fifteen), "+" + fifteen);

	// A truncated number is a DIFFERENT number, and possibly a valid one, so
	// over-length input must fail rather than be silently shortened.
	const std::string sixteen = fifteen + "6";
	EXPECT_EQ(e164Normalize(sixteen), "");
	EXPECT_EQ(e164Normalize("+" + sixteen), "");
	EXPECT_EQ(e164Normalize("1-2345-6789-0123-456"), "")
		<< "the ceiling counts DIGITS, so separators must not let a long number slip through";
}

// ─────────────────────────────────────────────────────────────────────────────
// Equivalence — what must match
// ─────────────────────────────────────────────────────────────────────────────

TEST(E164SameNumber, FormattingNeverChangesTheAnswer)
{
	EXPECT_TRUE(e164SameNumber("(202) 555-0123", "2025550123"));
	EXPECT_TRUE(e164SameNumber("+1 202 555 0123", "+12025550123"));
	EXPECT_TRUE(e164SameNumber("202.555.0123", "202-555-0123"));
}

TEST(E164SameNumber, ThePlusMarkerAloneDoesNotMakeADifferentNumber)
{
	EXPECT_TRUE(e164SameNumber("+12025550123", "12025550123"));
}

TEST(E164SameNumber, ANationalNumberMatchesItsInternationalRendering)
{
	// THE case this whole module exists for: the operator types the 10-digit
	// DID they know, the carrier reports E.164.
	EXPECT_TRUE(e164SameNumber("2025550123", "+12025550123"));
	EXPECT_TRUE(e164SameNumber("+12025550123", "2025550123"));
	EXPECT_TRUE(e164SameNumber("(202) 555-0123", "+1 202-555-0123"));
	// Same relaxation without any '+' at all: with and without the trunk digit.
	EXPECT_TRUE(e164SameNumber("2025550123", "12025550123"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Equivalence — what must NOT match. These are the tests that matter: a false
// positive routes an inbound call to the wrong extension.
// ─────────────────────────────────────────────────────────────────────────────

TEST(E164SameNumber, AShortExtensionCannotTailMatchItsWayIntoADid)
{
	// The realistic shape: a 3-4 digit internal extension against a full PSTN
	// number. (Here the country-code bound rejects first -- 7 extra digits is
	// far past 3 -- but both guards independently refuse it.)
	EXPECT_FALSE(e164SameNumber("0123", "+12025550123"));
	EXPECT_FALSE(e164SameNumber("123", "+12025550123"));

	// The floor on its own, isolated: these differ by ONE digit, so the
	// country-code bound is satisfied and only POCKETDIAL_MIN_PSTN_AOR_DIGITS
	// stands between a 6-digit string and a tail match.
	ASSERT_EQ(POCKETDIAL_MIN_PSTN_AOR_DIGITS, 7);
	EXPECT_FALSE(e164SameNumber("550123", "0550123")) << "6 digits is under the floor";

	// Exactly at the floor a genuine tail IS allowed through, pinning the
	// boundary from the other side so it cannot silently drift.
	EXPECT_TRUE(e164SameNumber("5550123", "2025550123"));
}

TEST(E164SameNumber, TwoFullyQualifiedInternationalNumbersMustMatchExactly)
{
	// Both sides declare their own country code, so neither is ambiguous and
	// the relaxation must not apply. Letting these match would merge a UK line
	// and a US line.
	EXPECT_FALSE(e164SameNumber("+12025550123", "+442025550123"));
	EXPECT_FALSE(e164SameNumber("+442025550123", "+12025550123"));
	EXPECT_FALSE(e164SameNumber("+12025550123", "+2025550123"));
}

TEST(E164SameNumber, APrefixLongerThanACountryCodeIsNotACountryCode)
{
	// ITU country codes are 1-3 digits. Four or more extra leading digits is
	// not "the same line with a country code", it is a different number that
	// happens to end the same way.
	EXPECT_FALSE(e164SameNumber("2025550123", "98762025550123"));  // 4 extra
	EXPECT_FALSE(e164SameNumber("2025550123", "1234567892025550123"))
		<< "and this one is over the 15-digit ceiling besides";

	// Three extra digits is still within a country code and does match.
	EXPECT_TRUE(e164SameNumber("2025550123", "3582025550123"));
}

TEST(E164SameNumber, SameLengthDifferentDigitsNeverMatch)
{
	EXPECT_FALSE(e164SameNumber("2025550123", "2025550124"));
	EXPECT_FALSE(e164SameNumber("+12025550123", "+12025550124"));
}

TEST(E164SameNumber, UnNormalizableInputIsNeverEqualToAnythingIncludingItself)
{
	// This is the property DidMapping::sameDid() compensates for with its own
	// exact-match line -- if that line were ever deleted, a non-numeric DID
	// would become unremovable, so the behaviour is pinned on both sides.
	EXPECT_FALSE(e164SameNumber("not-a-number", "not-a-number"));
	EXPECT_FALSE(e164SameNumber("*8", "*8"));
	EXPECT_FALSE(e164SameNumber("", ""));
	EXPECT_FALSE(e164SameNumber("2025550123", ""));
}

TEST(E164SameNumber, TheAcceptedFalsePositiveIsPinnedSoItCannotChangeUnnoticed)
{
	// E164.hpp documents this as a knowingly accepted false positive: a bare
	// national number and a foreign number that ends in the same digits are
	// reported equal, because the alternative is failing the common case every
	// time. If a future change makes this FALSE that is an improvement, not a
	// regression -- but it should be a deliberate, reviewed change, not a
	// silent side effect. Update this test and E164.hpp's boundary note
	// together.
	EXPECT_TRUE(e164SameNumber("+442025550123", "2025550123"));
}

// ─────────────────────────────────────────────────────────────────────────────
// The actual reason all of the above exists: DID lookup.
// ─────────────────────────────────────────────────────────────────────────────

namespace
{
	class DidE164Test : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			_path = std::string("test_did_e164_") +
			        ::testing::UnitTest::GetInstance()->current_test_info()->name() + ".cfg";
			std::remove(_path.c_str());
			_map.setStorePath(_path);
			_map.load();
		}
		void TearDown() override { std::remove(_path.c_str()); }

		DidMapping _map;
		std::string _path;
	};
}

TEST_F(DidE164Test, AnOperatorTypedDidMatchesTheCarriersE164Rendering)
{
	// The regression in one test: before #165 this returned "" and the call
	// fell through to ring-all with no error anywhere.
	ASSERT_EQ(_map.setMapping("(202) 555-0123", "1001"), "");
	EXPECT_EQ(_map.extensionForDid("+12025550123"), "1001");
	EXPECT_EQ(_map.extensionForDid("12025550123"), "1001");
	EXPECT_EQ(_map.extensionForDid("2025550123"), "1001");
}

TEST_F(DidE164Test, AnE164ConfiguredDidMatchesALocalFormLookup)
{
	ASSERT_EQ(_map.setMapping("+12025550123", "1002"), "");
	EXPECT_EQ(_map.extensionForDid("2025550123"), "1002");
	EXPECT_EQ(_map.extensionForDid("(202) 555-0123"), "1002");
}

TEST_F(DidE164Test, ARerenderedDidUpdatesInPlaceInsteadOfCreatingAnAmbiguousSecondRow)
{
	// Two rows that both match one inbound call would make routing depend on
	// table order -- something an operator can neither see nor control.
	ASSERT_EQ(_map.setMapping("2025550123", "1001"), "");
	ASSERT_EQ(_map.setMapping("+1 (202) 555-0123", "1002"), "");

	EXPECT_EQ(_map.size(), 1u) << "the second set must have updated, not added";
	EXPECT_EQ(_map.extensionForDid("2025550123"), "1002") << "and the newer extension wins";
}

TEST_F(DidE164Test, ADidCanBeRemovedByAnyRenderingOfTheSameNumber)
{
	ASSERT_EQ(_map.setMapping("+12025550123", "1001"), "");
	ASSERT_EQ(_map.removeMapping("(202) 555-0123"), "");
	EXPECT_EQ(_map.size(), 0u);
	EXPECT_EQ(_map.extensionForDid("+12025550123"), "");
}

TEST_F(DidE164Test, DistinctDidsStayDistinct)
{
	ASSERT_EQ(_map.setMapping("+12025550123", "1001"), "");
	ASSERT_EQ(_map.setMapping("+12025550124", "1002"), "");
	EXPECT_EQ(_map.size(), 2u);
	EXPECT_EQ(_map.extensionForDid("2025550123"), "1001");
	EXPECT_EQ(_map.extensionForDid("2025550124"), "1002");
}

TEST_F(DidE164Test, AShortDidIsNotTailMatchedByALongOne)
{
	// A 4-digit "DID" is really an internal extension. It must not start
	// answering every PSTN call that happens to end in those digits.
	ASSERT_EQ(_map.setMapping("0123", "1001"), "");
	EXPECT_EQ(_map.extensionForDid("+12025550123"), "")
		<< "a 4-digit mapping must not capture a full PSTN number";
	EXPECT_EQ(_map.extensionForDid("0123"), "1001") << "but it still matches itself exactly";
}

TEST_F(DidE164Test, ANonNumericDidRemainsFindableAndRemovable)
{
	// pbx::e164SameNumber() returns false for anything it cannot normalize, so
	// without DidMapping::sameDid()'s exact-match line such a row would be
	// stranded in the table with no way to list-and-remove it.
	ASSERT_EQ(_map.setMapping("main-line", "1001"), "");
	EXPECT_EQ(_map.extensionForDid("main-line"), "1001");
	ASSERT_EQ(_map.removeMapping("main-line"), "");
	EXPECT_EQ(_map.size(), 0u);
}

TEST_F(DidE164Test, MatchingSurvivesAStoreRoundTrip)
{
	ASSERT_EQ(_map.setMapping("(202) 555-0123", "1001"), "");

	DidMapping reloaded;
	reloaded.setStorePath(_path);
	reloaded.load();

#if defined(_WIN32)
	// Host persistence is in-memory-only on Windows (see DidMapping_test.cpp's
	// note); the round trip is covered on POSIX hosts and on device.
	GTEST_SKIP() << "no host file persistence on _WIN32";
#else
	ASSERT_EQ(reloaded.size(), 1u);
	EXPECT_EQ(reloaded.extensionForDid("+12025550123"), "1001");
#endif
}

#ifndef E164_HPP
#define E164_HPP

// ── E.164 number normalization and equivalence (Issue #165) ──────────────────
//
// The same telephone line is written many ways. A carrier's inbound event may
// report "+15551234567"; the operator may have typed "(555) 123-4567" into the
// dashboard; a dial-plan rule may produce "15551234567". All three name one
// line, and before this file NOTHING in the tree compared them as such —
// DidMapping::findIndex() was a raw std::string ==, so a DID configured in one
// form and reported in another simply never matched.
//
// That failure is SILENT and that is what makes it worth a dedicated module:
// routeInboundAnchorCall() treats "no mapping" as "fall back to ring-all", so a
// mismatched DID does not error, does not log, and does not fail to ring a
// phone. It just quietly ignores the per-DID routing the operator configured
// and rings every extension instead. Nobody files a bug against a PBX that
// rings; they file one months later about the wrong person answering.
//
// ── What "normalize" means here, and what it deliberately does NOT ───────────
//
// e164Normalize() is a FORMATTER, not a resolver. It removes the ways humans
// decorate a number and it validates the result against E.164's own bounds. It
// never invents information:
//
//   * Visual separators (space, tab, '-', '.', '(', ')', '/') are dropped.
//     These carry no dialing meaning in any numbering plan.
//   * A single leading '+' is PRESERVED. It is the only thing in a bare number
//     string that makes the country code unambiguous, so discarding it would
//     destroy the one fact worth keeping.
//   * Any other character — a letter, '*', '#', ',' — makes the whole input
//     un-normalizable and yields "". A vanity number or a feature code is not
//     an E.164 number and must not be silently mangled into one.
//   * NO country code is ever added. "5551234567" normalizes to "5551234567",
//     never to "+15551234567". Guessing a country from a bare national number
//     requires knowing the deployment's country, which this module is not told
//     and must not assume. See e164SameNumber() for how the two are related
//     WITHOUT that guess being baked into either one's canonical form.
//
// ── Why "00" is not treated as an international prefix ───────────────────────
//
// Much of the world dials international as 00<country><number>, and a generic
// E.164 library would map a leading "00" to "+". This one does not, on purpose.
// This board's emergency handling is NANP-specific (911, its 933 test number,
// Kari's Law), and in NANP the international access prefix is 011 — "00" is an
// operator code, not an IDD prefix. Mapping "00" to "+" here would therefore be
// wrong in exactly the numbering plan this firmware is built for. It is also
// unnecessary: the inputs this module actually sees are carrier-reported DIDs
// and operator-typed DIDs, and neither arrives 00-prefixed. Adding the rule
// would buy a case that does not occur at the price of one that does.
//
// ── E.164 length ─────────────────────────────────────────────────────────────
//
// ITU-T E.164 §6.2.1 caps an international number at 15 digits (country code
// plus national significant number), and country codes are 1-3 digits. Both
// bounds are protocol facts rather than deployment policy, so they live here as
// constants rather than in PoolConfig.hpp alongside the tunable knobs.

#include "PoolConfig.hpp"

#include <cstddef>
#include <string>
#include <string_view>

namespace pbx
{

// ITU-T E.164 §6.2.1: an international number is at most 15 digits.
inline constexpr std::size_t kE164MaxDigits = 15;

// ITU-T E.164: a country code is 1-3 digits. Used as the bound on how much
// prefix e164SameNumber() will tolerate between a national and an
// international rendering of one line.
inline constexpr std::size_t kE164MaxCountryCodeDigits = 3;

// Canonical form of `raw`, or "" when `raw` cannot be a telephone number.
//
// The result is a digit string, optionally preceded by a single '+'. Returns ""
// for: an empty/all-separator input, any character that is not a digit or a
// leading '+', a '+' anywhere but the first position, and a digit count outside
// 1..kE164MaxDigits.
//
// Normalizing an already-normalized string returns it unchanged (idempotent),
// which is what lets callers store the canonical form and keep comparing.
std::string e164Normalize(std::string_view raw);

// True iff `a` and `b` name the same telephone line.
//
// Both sides are normalized first, so formatting never affects the answer:
// "(555) 123-4567" and "5551234567" are the same number. Beyond formatting,
// two renderings are treated as equal when they differ ONLY by an
// international prefix:
//
//     "+15551234567"  ==  "15551234567"   (the '+' marker alone)
//     "+15551234567"  ==  "5551234567"    (country code present vs absent)
//
// ── The boundary, stated plainly ─────────────────────────────────────────────
//
// That second case is a POLICY judgement, not a protocol fact, and it is the
// one place this module can be wrong. A bare national number carries no
// country, so deciding that "5551234567" is the same line as "+15551234567"
// means assuming both belong to the same country — which nothing here knows.
//
// The rule is therefore bounded on both ends rather than being a plain suffix
// test:
//
//   * the shorter number must be at least POCKETDIAL_MIN_PSTN_AOR_DIGITS long
//     (7 — see PoolConfig.hpp, where the same threshold already separates
//     "PSTN-shaped" from "internal extension", for the NANP reasoning), so a
//     3-digit extension can never suffix-match a full PSTN number; and
//   * the digits they differ by must be at most kE164MaxCountryCodeDigits (3),
//     the actual ITU bound on a country code, so the relaxation can only ever
//     absorb a country code and not an arbitrary prefix.
//
// FALSE POSITIVE, accepted knowingly: "+445551234567" and "5551234567" satisfy
// both bounds and compare equal, though one is a UK number and the other is a
// bare national string that, in this deployment, means a US line. Reaching that
// case requires an operator to configure a bare national DID that is a digit-
// exact tail of a foreign number their carrier also delivers, inside a table of
// at most POCKETDIAL_MAX_DID_MAPPINGS entries. The alternative — refusing the
// relaxation entirely — fails the common case (an operator typing the 10-digit
// DID they know) every single time, in exchange for a collision that requires a
// deliberate coincidence. If a deployment ever needs the strict behaviour, the
// fix is a configured default country code that makes the comparison exact,
// not a tighter heuristic here.
bool e164SameNumber(std::string_view a, std::string_view b);

} // namespace pbx

#endif // E164_HPP

#include "E164.hpp"

#include <cctype>

namespace pbx
{

namespace
{

// Characters humans use to make a number readable. None of them carries any
// dialing meaning in any numbering plan, so all are dropped before parsing.
// Note that '*' and '#' are NOT here: they are real dialable symbols (feature
// codes), so a string containing one is refused rather than stripped down into
// a number it was never meant to be.
bool isSeparator(char c)
{
	return c == ' ' || c == '\t' || c == '-' || c == '.' ||
		c == '(' || c == ')' || c == '/';
}

// The digits of a normalized number, without the '+' marker. The marker says
// "a country code is present"; it is not itself part of the number's identity,
// so every comparison below is done on this view.
std::string_view digitsOf(const std::string& normalized)
{
	std::string_view v = normalized;
	if (!v.empty() && v.front() == '+')
	{
		v.remove_prefix(1);
	}
	return v;
}

} // namespace

std::string e164Normalize(std::string_view raw)
{
	std::string out;
	out.reserve(raw.size() + 1);

	bool seenSignificant = false; // a '+' or a digit has been consumed
	std::size_t digits = 0;

	for (const char c : raw)
	{
		if (isSeparator(c))
		{
			continue;
		}

		if (c == '+')
		{
			// Only ever valid as the FIRST significant character. A '+' in the
			// middle ("555+1234") is not a decorated number, it is garbage, and
			// silently dropping it would turn garbage into a plausible-looking
			// number that routes somewhere.
			if (seenSignificant)
			{
				return "";
			}
			seenSignificant = true;
			out.push_back('+');
			continue;
		}

		if (!std::isdigit(static_cast<unsigned char>(c)))
		{
			// A letter, '*', '#', ',' or anything else: not a telephone number.
			return "";
		}

		seenSignificant = true;
		if (++digits > kE164MaxDigits)
		{
			// Over E.164's own ceiling. Refuse rather than truncate — a
			// truncated number is a DIFFERENT, possibly valid, line.
			return "";
		}
		out.push_back(c);
	}

	if (digits == 0)
	{
		// "", "+", "()-" and friends. A '+' with no digits is not a number.
		return "";
	}

	return out;
}

bool e164SameNumber(std::string_view a, std::string_view b)
{
	const std::string na = e164Normalize(a);
	const std::string nb = e164Normalize(b);
	if (na.empty() || nb.empty())
	{
		// Un-normalizable input is never "the same number" as anything, not
		// even as itself — callers that need raw-string identity must test
		// that separately (DidMapping::sameDid() does exactly this, so a
		// hand-edited non-numeric DID stays findable and removable).
		return false;
	}

	const std::string_view da = digitsOf(na);
	const std::string_view db = digitsOf(nb);

	if (da == db)
	{
		// Identical digits: the only difference was formatting and/or the '+'
		// marker. "+15551234567" == "1 (555) 123-4567".
		return true;
	}

	// Beyond this point the two differ in digit COUNT, so answering "same line"
	// means deciding that the extra leading digits are a country code.
	//
	// If BOTH sides carry '+', neither is ambiguous — each has already declared
	// its own country code — so differing digits mean genuinely different
	// numbers. Relaxing here would let "+15551234567" match "+5551234567",
	// which is two distinct international numbers, for no benefit: the case
	// this relaxation exists to serve is an operator typing a number WITHOUT
	// the country code, and such a number has no '+'.
	const bool bothInternational = na.front() == '+' && nb.front() == '+';
	if (bothInternational)
	{
		return false;
	}

	const std::string_view shorter = (da.size() <= db.size()) ? da : db;
	const std::string_view longer  = (da.size() <= db.size()) ? db : da;

	// At most a country code may separate them (ITU-T E.164: 1-3 digits).
	const std::size_t extra = longer.size() - shorter.size();
	if (extra == 0 || extra > kE164MaxCountryCodeDigits)
	{
		return false;
	}

	// ...and the shorter side must be long enough to be a PSTN number in its
	// own right, so a short internal extension can never tail-match its way
	// into a DID. See POCKETDIAL_MIN_PSTN_AOR_DIGITS in PoolConfig.hpp.
	if (shorter.size() < static_cast<std::size_t>(POCKETDIAL_MIN_PSTN_AOR_DIGITS))
	{
		return false;
	}

	return longer.compare(longer.size() - shorter.size(), shorter.size(), shorter) == 0;
}

} // namespace pbx

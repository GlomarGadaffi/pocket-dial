#ifndef DTMF_CLASS_CODES_HPP
#define DTMF_CLASS_CODES_HPP

#include <string_view>

// The CLASS star codes DtmfFeatureCodes::onDigit() acts on. ONE list, read from two places:
//
//   * onDigit() (DtmfFeatureCodes.cpp, step 6) matches these on the same per-call digit
//     accumulator the *PIN#code admin entry is collected on, and before any '#' has arrived.
//   * AdminAuth::setDtmfPin() refuses a PIN one of them would claim first (#994): keying
//     "*6012#001" fires *60 at the PIN's second digit and clears the accumulator, so a PIN
//     starting 60 can never authenticate. The refusal is made at set time, where the
//     operator can read why, instead of at the keypad, where the entry just dies.
//
// A code added here is both matched and refused. A code matched in onDigit() but missing
// here is exactly the drift #994 was, so onDigit() compares against these names, never a
// literal.
namespace dtmfclass
{
	inline constexpr std::string_view kEchoLoopback = "*11";
	inline constexpr std::string_view kDndOn        = "*60";
	inline constexpr std::string_view kLastCaller   = "*69";
	inline constexpr std::string_view kCfuOn        = "*72";   // *72NNNN: fires once NNNN names a registered extension
	inline constexpr std::string_view kCfuOff       = "*73";
	inline constexpr std::string_view kDndOff       = "*80";

	inline constexpr std::string_view kCodes[] = {
		kEchoLoopback, kDndOn, kLastCaller, kCfuOn, kCfuOff, kDndOff};

	// The star code onDigit() would fire while `pin` is being keyed after the admin entry's
	// leading '*', or empty when none would. No allocation; safe on any thread.
	//
	// *72 counts although it fires only once the digits after it name a registered
	// extension: a 6+-digit PIN starting 72 can, and whether it does would then depend on
	// who is registered that day, which is not a property a PIN may have.
	inline std::string_view claiming(std::string_view pin)
	{
		for (std::string_view code : kCodes)
		{
			const std::string_view digits = code.substr(1);   // without the '*'
			if (pin.size() >= digits.size() && pin.substr(0, digits.size()) == digits)
			{
				return code;
			}
		}
		return {};
	}
}

#endif

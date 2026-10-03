#ifndef SIP_MESSAGE_BUILDER_HPP
#define SIP_MESSAGE_BUILDER_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace sipb
{

// Bounded fixed-buffer wire container for emitted SIP messages (RFC 3261).
// N is the capacity; a builder's output never exceeds N - 1 bytes.
template <size_t N>
struct WireBuf
{
	char bytes[N]{};
	size_t len{0};
};

// Maximum allowed byte length for an OPTIONS keepalive ping (#463: 640 B).
// Sized to its own buffer so the ping costs 640 B of stack, not 1500 (#457
// frame ceiling is 1024 B).
constexpr size_t kMaxOptionsBytes = 640;
using OptionsWire = WireBuf<kMaxOptionsBytes>;

// A server-originated BYE. The longest one the PBX can be asked for is 820 B:
// a 128 B registered Contact (SipClient::kMaxContactUriLen), a dotted-quad
// local ip:port, 200 B From and To values, a 125 B Call-ID (the 127 B
// SipLimits::kMaxCallIdLine less a compact "i:") and a 10-digit CSeq. The
// buffer lives on buildServerBye's stack, under the 1024 B frame ceiling (#457).
constexpr size_t kMaxByeBytes = 832;
using ByeWire = WireBuf<kMaxByeBytes>;

enum class Err : uint8_t
{
	Ok = 0,
	Truncated,
	BadField
};

struct OptionsParams
{
	std::string_view targetAor{};
	std::string_view destIp{};
	uint16_t destPort{5060};
	std::string_view localIp{};
	uint16_t localPort{5060};
	std::string_view fromUser{"server"};
	// Request-URI as registered (#797: a Snom answers 404 without its ;line=).
	// Empty composes sip:<targetAor>@<destIp>:<destPort>. Any byte outside
	// printable ASCII (0x21..0x7e) is refused with Err::BadField.
	std::string_view requestUri{};
};

// Builds a well-formed RFC 3261 OPTIONS keepalive ping into `out`.
// Returns Err::Ok on success, or Err::Truncated (with out.len = 0) if it does
// not fit out.bytes. Allocates zero heap memory.
Err options(OptionsWire& out, const OptionsParams& params);

struct ByeParams
{
	// The Contact the phone registered (#798). Empty composes
	// sip:<targetUser>@<destIp>:<destPort>, the address the BYE is sent to.
	std::string_view requestUri{};
	std::string_view targetUser{};
	std::string_view destIp{};
	uint16_t destPort{5060};
	std::string_view localIp{};
	uint16_t localPort{5060};
	// Each a bare value or a whole "Name: value" line, as a Session stores it.
	std::string_view from{};
	std::string_view to{};
	std::string_view callId{};
	uint32_t cseq{2};
};

// Builds an in-dialog BYE into `out` with no heap. Truncated when the message
// would be kMaxByeBytes or longer. BadField when a field is empty or holds a
// byte that would end its line early: in requestUri, the composed URI's parts,
// localIp or callId anything outside 0x21..0x7e; in from or to a control byte
// other than HTAB (a display name keeps its spaces and UTF-8). Either error
// leaves out.len == 0.
Err bye(ByeWire& out, const ByeParams& params);

} // namespace sipb

#endif // SIP_MESSAGE_BUILDER_HPP

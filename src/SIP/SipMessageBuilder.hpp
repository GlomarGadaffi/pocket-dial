#ifndef SIP_MESSAGE_BUILDER_HPP
#define SIP_MESSAGE_BUILDER_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "PoolConfig.hpp"

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

// A full transmit message (the TransactionLayer's retransmit slot size).
using Wire = WireBuf<POCKETDIAL_TX_MSG_BYTES>;

// Maximum allowed byte length for an OPTIONS keepalive ping (#463: 640 B).
// Sized to its own buffer so the ping costs 640 B of stack, not 1500 (#457
// frame ceiling is 1024 B).
constexpr size_t kMaxOptionsBytes = 640;
using OptionsWire = WireBuf<kMaxOptionsBytes>;

enum class Err : uint8_t
{
	Ok = 0,
	Truncated,
	BadField,
	NoDialog
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

Err options(OptionsWire& out,
            std::string_view targetAor,
            std::string_view destIp,
            uint16_t destPort,
            std::string_view localIp,
            uint16_t localPort,
            std::string_view fromUser = "server");

} // namespace sipb

#endif // SIP_MESSAGE_BUILDER_HPP

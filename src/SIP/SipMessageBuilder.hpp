#ifndef SIP_MESSAGE_BUILDER_HPP
#define SIP_MESSAGE_BUILDER_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "PoolConfig.hpp"

namespace sipb
{

// Bounded fixed-buffer wire container for emitted SIP messages (RFC 3261).
struct Wire
{
	char bytes[POCKETDIAL_TX_MSG_BYTES]{};
	size_t len{0};
};

// Maximum allowed byte length for an OPTIONS keepalive ping (#463: 640 B).
constexpr size_t kMaxOptionsBytes = 640;

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
	// Empty composes sip:<targetAor>@<destIp>:<destPort>.
	std::string_view requestUri{};
};

// Builds a well-formed RFC 3261 OPTIONS keepalive ping into `out`.
// Returns Err::Ok on success, or Err::Truncated (with out.len = 0) if it does
// not fit out.bytes. Allocates zero heap memory.
Err options(Wire& out, const OptionsParams& params);

Err options(Wire& out,
            std::string_view targetAor,
            std::string_view destIp,
            uint16_t destPort,
            std::string_view localIp,
            uint16_t localPort,
            std::string_view fromUser = "server");

} // namespace sipb

#endif // SIP_MESSAGE_BUILDER_HPP

#ifndef PNP_PROFILE_HPP
#define PNP_PROFILE_HPP

// PnpProfile.hpp -- SIP Plug-and-Play wire format (Issue #826). Pure: no
// socket, no clock, no heap.
//
// A factory-fresh phone multicasts
//
//   SUBSCRIBE sip:MAC%3a0004132E08B4@224.0.1.75 SIP/2.0
//   From: <sip:MAC%3a0004132E08B4@224.0.1.75>;tag=...
//   Event: ua-profile;profile-type="device";vendor="snom";model="snom370";version="8.7.5.48"
//
// to 224.0.1.75:5060. A provisioning server answers 200 OK, then sends a NOTIFY
// whose body (Content-Type: application/url) is the URL the phone stores as its
// provisioning server and fetches.
//
// Every string here is a view into the received datagram or a fixed array;
// every loop is bounded by a named constant. Writers fill a caller-owned buffer
// and return 0 when it is too small, never a truncated message.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace pnp
{
	constexpr const char* kGroup = "224.0.1.75";
	constexpr uint16_t kPort = 5060;

	constexpr std::size_t kMaxLines = 48;      // header lines scanned per datagram
	constexpr std::size_t kMaxVias = 4;        // Via header lines echoed in the 200
	constexpr std::size_t kFieldCap = 24;      // vendor / model / version, incl. NUL
	constexpr std::size_t kMacCap = 13;        // 12 lowercase hex + NUL
	constexpr uint32_t kMaxExpires = 30;       // seconds granted in the 200 (RFC 6665: never more than asked)

	enum class Vendor : uint8_t { Generic, Snom, Yealink };

	// What a phone says about itself. Fixed arrays so a copy outlives the datagram.
	struct DeviceId
	{
		std::array<char, kMacCap> mac{};          // 12 lowercase hex, NUL-terminated
		std::array<char, kFieldCap> vendor{};     // sanitized, NUL-terminated
		std::array<char, kFieldCap> model{};
		std::array<char, kFieldCap> version{};
	};

	// A parsed ua-profile SUBSCRIBE. The views point into the datagram and are
	// valid only while it is.
	struct Subscribe
	{
		std::array<std::string_view, kMaxVias> vias{};
		std::size_t viaCount = 0;
		std::string_view from;
		std::string_view to;
		std::string_view callId;
		std::string_view cseq;
		uint32_t expires = kMaxExpires;   // the request's Expires, if it sent one
		DeviceId id;
	};

	// True iff `raw` is a complete (headers end with a blank line, so a
	// datagram cut short by the receive buffer is refused) initial (no To tag)
	// SUBSCRIBE for
	// Event: ua-profile;profile-type="device" whose From (or To) user is a MAC
	// ("MAC%3a<12 hex>" or "MAC:<12 hex>", any case). Fills `out` only then.
	bool parseSubscribe(std::string_view raw, Subscribe& out);

	Vendor vendorOf(const DeviceId& id);

	// The URL the NOTIFY hands this phone, for a board at `serverIp`:
	//   snom    -> http://<ip>/config/snom<mac>.xml   (fetched as given)
	//   others  -> http://<ip>/config/                 (the phone appends its own file name)
	std::size_t writeUrl(const DeviceId& id, std::string_view serverIp, char* buf, std::size_t cap);

	// 200 OK to `sub`, with To tag `toTag`.
	std::size_t writeOk(const Subscribe& sub, std::string_view toTag,
		std::string_view localIp, uint16_t localPort, char* buf, std::size_t cap);

	// The NOTIFY carrying `url`, sent to the SUBSCRIBE's source `destIp:destPort`.
	std::size_t writeNotify(const Subscribe& sub, std::string_view toTag, std::string_view branch,
		std::string_view localIp, uint16_t localPort, std::string_view destIp, uint16_t destPort,
		std::string_view url, char* buf, std::size_t cap);
}

#endif

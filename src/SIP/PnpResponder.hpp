#ifndef PNP_RESPONDER_HPP
#define PNP_RESPONDER_HPP

// PnpResponder -- SIP Plug-and-Play policy and state (Issue #826).
//
// Decides whether a ua-profile SUBSCRIBE (PnpProfile.hpp) gets answered, and
// builds the answer. No socket and no clock of its own: SipServer feeds it
// datagrams from the 224.0.1.75 socket with the current time and sends what it
// returns, which keeps every rule here host-testable.
//
// Rules:
//   - Mode Off (the default): nothing is parsed or recorded. First responder
//     wins on a PnP LAN, so an always-on answer would capture phones meant for
//     another PBX on the same network; the admin turns this on.
//   - Mode Discover: phones are recorded in a fixed table, never answered.
//   - Mode Provision: also answered, but only when `canServe(mac)` says this
//     board has a config for that MAC. Otherwise silence, so another server
//     can still answer.
//   - Only sources on the board's own subnet are recorded or answered.
//   - Replies spend a token (kBurst, one back every kRefillSeconds); a phone
//     gets at most one NOTIFY per kNotifyCooldownSeconds. A retransmitted
//     SUBSCRIBE still gets its 200.
//   - The NOTIFY goes to the datagram's source address only, never to a host
//     named inside the message.
//
// Memory: everything is fixed-size and lives in this object. onDatagram()
// allocates nothing.

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <lwip/sockets.h>
#elif defined(__linux__)
#include <netinet/in.h>
#elif defined _WIN32 || defined _WIN64
#include <WinSock2.h>
#endif

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string_view>

#include "FunctionRef.hpp"
#include "PnpProfile.hpp"

class PnpResponder
{
public:
	enum class Mode : uint8_t { Off = 0, Discover = 1, Provision = 2 };

	static constexpr std::size_t kMaxDevices = 16;
	static constexpr std::size_t kTxCap = 1400;           // one 200 or NOTIFY
	static constexpr uint8_t kBurst = 4;
	static constexpr uint32_t kRefillSeconds = 2;
	static constexpr uint32_t kNotifyCooldownSeconds = 30;

	struct Device
	{
		pnp::DeviceId id;
		uint32_t ip = 0;              // network byte order
		uint32_t lastSeen = 0;        // caller's clock, seconds
		uint32_t lastNotify = 0;
		uint16_t seen = 0;
		bool notified = false;        // a NOTIFY has been sent to it
		bool used = false;
	};

	// Views into this object's buffers, valid until the next onDatagram().
	// Empty means "send nothing".
	struct Reply
	{
		std::string_view ok;
		std::string_view notify;
	};

	// Byte "0" from NVS (or nothing at all) is Off; any value that is not a mode is Off.
	static Mode decodeStored(uint8_t v);

	// The board's own address, netmask (both network byte order) and SIP port.
	// Until this is called, every datagram is ignored.
	void setNetwork(uint32_t ip, uint32_t mask, uint16_t port);

	Mode mode() const { return _mode.load(std::memory_order_relaxed); }
	void setMode(Mode m);    // persists (NVS key pnp_mode) on the board
	void loadMode();         // boot-time NVS read; Off when absent or unreadable

	Reply onDatagram(std::string_view raw, const sockaddr_in& src, uint32_t nowSeconds,
		FunctionRef<bool(std::string_view mac)> canServe);

	// Visits each recorded device under the table lock, in slot order; returns
	// how many it visited. A visitor, not a copy: 16 records do not belong on
	// the http_conn stack (#405). Keep the visitor short and lock-free.
	std::size_t forEachDevice(FunctionRef<void(const Device&)> visit) const;

	static const char* modeName(Mode m);
	// "off" / "discover" / "provision" -> true + `out`; anything else -> false.
	static bool parseMode(std::string_view s, Mode& out);

private:
	bool sameSubnet(uint32_t ip) const;
	bool takeToken(uint32_t now);
	Device& record(const pnp::DeviceId& id, uint32_t ip, uint32_t now);
	Reply answer(const pnp::Subscribe& sub, const sockaddr_in& src, Device& dev, uint32_t now);

	std::atomic<Mode> _mode{Mode::Off};
	uint32_t _ip = 0;
	uint32_t _mask = 0;
	uint16_t _port = 0;
	std::array<char, 16> _ipText{};   // dotted quad, NUL-terminated

	mutable std::mutex _mu;           // guards _devices (the HTTP task snapshots it)
	std::array<Device, kMaxDevices> _devices{};

	uint8_t _tokens = kBurst;
	uint32_t _refillAt = 0;

	std::array<char, kTxCap> _okBuf{};
	std::array<char, kTxCap> _notifyBuf{};
};

#endif

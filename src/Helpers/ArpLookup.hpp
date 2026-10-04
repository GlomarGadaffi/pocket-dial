#ifndef ARP_LOOKUP_HPP
#define ARP_LOOKUP_HPP

// ArpLookup: resolve the link-layer (Ethernet MAC) address of a SIP peer from
// its source IPv4 address.
//
// Why this exists: Learn-mode device adoption (TOFU + MAC-lock) needs a stable
// hardware identity for the registering phone. SIP itself carries no MAC; the
// only place the device's MAC is known on the registrar is the lwIP ARP cache,
// keyed by the peer's IPv4 address. We look it up by the REGISTER source IP.
//
// Caveat (documented in the STAGE-2 ticket): on the VERY FIRST REGISTER from a
// freshly-connected phone the ARP entry may not yet exist (cache miss) — the
// kernel has an L2 frame for the inbound UDP packet but lwIP only populates the
// etharp table lazily. pdLookupMac() returns std::nullopt on a miss; the CALLER
// must treat that as "defer the MAC-lock to the next REGISTER" and NOT hard-fail
// (the server's own 200 OK + register-beep + OPTIONS round-trip populates the
// cache, so the next REGISTER resolves). This function NEVER blocks — it does a
// single non-blocking table probe and returns immediately.
//
// Cross-platform: on ESP the lookup walks the active netif's ARP table via
// etharp_find_addr(). On host (unit tests / non-ESP builds) it is a stub that
// returns std::nullopt (no ARP table), mirroring the RtpSender / SshServer host
// stubs so the host test build and non-display builds stay compilable.

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <lwip/sockets.h>
#elif defined(__linux__)
#include <netinet/in.h>
#elif defined _WIN32 || defined _WIN64
#include <WinSock2.h>
#endif

#include <array>
#include <cstdint>
#include <optional>
#include <string>

namespace ArpLookup
{
	// A resolved 6-byte Ethernet MAC.
	using Mac = std::array<uint8_t, 6>;

	// Resolve the MAC for the IPv4 address in `src` (src.sin_addr is read; the
	// port is ignored). Returns std::nullopt on:
	//   * an ARP cache miss (first-packet race — caller defers/retries),
	//   * no active/usable netif,
	//   * a non-IPv4 address,
	//   * any platform where ARP is unavailable (host stub).
	// Non-blocking: a single table probe, no waiting, no I/O.
	std::optional<Mac> pdLookupMac(const struct sockaddr_in& src);

	// #864: true if `src`'s IPv4 address is a host on the subnet of an up
	// interface (the ones pdLookupMac() probes), so an ARP request can reach it.
	// An off-link source never resolves. Reads the netifs; no I/O.
	bool pdIsOnLink(const struct sockaddr_in& src);

	// #864: broadcast an ARP request for `src`'s IPv4 address on each up interface
	// whose subnet holds it; the reply fills the table for the sender's next
	// packet. True if one went out. Waits for lwIP's tcpip thread to send it, as
	// sendto() does, never for the reply: call it outside the engine lock.
	bool pdSendArpRequest(const struct sockaddr_in& src);

	// Format a Mac as 12 lowercase hex chars (no separators), e.g. "a1b2c3d4e5f6".
	// This is the canonical key form used by the device registry. Pure helper.
	std::string toHex12(const Mac& mac);

#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
	// ── Host test injection helpers ──────────────────────────────────────────
	void setMockMac(const struct sockaddr_in& src, const Mac& mac);
	// #864: `src`'s IP is a host on this subnet that answers an ARP request with
	// `reply` (std::nullopt: it never answers). An ARP request for it lands the
	// reply in the table above, as lwIP's etharp_input() would.
	void setMockOnLink(const struct sockaddr_in& src, std::optional<Mac> reply);
	// ARP requests sent since the last clearMockMacs().
	int mockArpRequestCount();
	void clearMockMacs();   // also forgets the on-link hosts and the request count
#endif
}

#endif // ARP_LOOKUP_HPP

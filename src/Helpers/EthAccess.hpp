#ifndef ETH_ACCESS_HPP
#define ETH_ACCESS_HPP

#include <array>
#include <cstdint>
#include <cstddef>

// EthAccess: provides a tiny abstraction for L2 Ethernet transmission and
// local network info (MAC/IP/Gateway) without exposing ESP-IDF or lwIP headers
// to the rest of the application (particularly the SIP stack).
//
// This is used to bypass the lwIP socket path for performance-critical
// transmissions (e.g., RTP media), avoiding bounce-buffer allocations that
// can exhaust the DMA pool under load (Issue #282).
//
// On non-ESP builds, these functions act as stubs and return false.
namespace EthAccess
{
	// Provide the initialized Ethernet handle (esp_eth_handle_t) to the module.
	// Typically called once during boot (e.g., in app_main).
	void setEthHandle(void* handle);

	// Transmit an L2 frame directly. The frame MUST be placed in internal,
	// DMA-capable memory (e.g., using DMA_ATTR) and appropriately aligned.
	// Returns true if transmission was successfully queued.
	bool transmitL2(void* frame, size_t len);

	// Retrieve the local IP, Gateway, and Netmask (in host byte order).
	// Used for determining whether a destination IP is on-subnet.
	// Returns true if the information is available (link is up).
	bool getLocalIpInfo(uint32_t& ip, uint32_t& gw, uint32_t& netmask);

	// Retrieve the local Ethernet MAC address.
	bool getLocalMac(std::array<uint8_t, 6>& mac);
}

#endif // ETH_ACCESS_HPP

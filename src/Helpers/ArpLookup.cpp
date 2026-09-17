// ArpLookup.cpp — resolve a SIP peer's Ethernet MAC from its source IPv4.
//
// See ArpLookup.hpp for the design rationale and the first-packet cache-miss
// caveat. On ESP this walks the active netif's lwIP ARP table; on host it is a
// stub (no ARP table) so the unit-test / non-display builds stay compilable.

#include "ArpLookup.hpp"

#include <cstdio>
#include <map>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "esp_netif.h"
#include "esp_netif_net_stack.h"   // esp_netif_get_netif_impl()
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/ip4_addr.h"
#endif

namespace ArpLookup
{
	std::string toHex12(const Mac& mac)
	{
		// Fixed 12-char lowercase-hex, no separators. The registry keys on this.
		static const char* hex = "0123456789abcdef";
		std::string out;
		out.reserve(12);
		for (uint8_t b : mac)
		{
			out.push_back(hex[(b >> 4) & 0x0F]);
			out.push_back(hex[b & 0x0F]);
		}
		return out;
	}

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)

	namespace
	{
		// Probe one named netif's ARP table for `ip`. Returns true + fills `out` on
		// a hit; false on a cache miss / no such netif / not yet up. Non-blocking:
		// etharp_find_addr() is a pure in-memory table lookup.
		bool probeIfkey(const char* ifkey, const ip4_addr_t& ip, Mac& out)
		{
			esp_netif_t* netif = esp_netif_get_handle_from_ifkey(ifkey);
			if (netif == nullptr)
			{
				return false;   // that interface isn't instantiated on this transport
			}

			struct netif* impl =
				static_cast<struct netif*>(esp_netif_get_netif_impl(netif));
			if (impl == nullptr)
			{
				return false;
			}

			struct eth_addr* ethRet = nullptr;
			const ip4_addr_t* ipRet = nullptr;
			// Returns the table index (>= 0) on a hit, or a negative value on a miss.
			// Does NOT send an ARP request (that would block / mutate state); a miss
			// just means "not cached yet" → the caller defers the MAC-lock.
			ssize_t idx = etharp_find_addr(impl, &ip, &ethRet, &ipRet);
			if (idx < 0 || ethRet == nullptr)
			{
				return false;
			}

			for (int i = 0; i < 6; ++i)
			{
				out[i] = ethRet->addr[i];
			}
			return true;
		}
	}

	std::optional<Mac> pdLookupMac(const struct sockaddr_in& src)
	{
		if (src.sin_family != AF_INET)
		{
			return std::nullopt;
		}

		// sockaddr_in stores the address in network byte order; lwIP ip4_addr_t is
		// also network-order (the s_addr field), so this is a direct copy.
		ip4_addr_t ip;
		ip.addr = src.sin_addr.s_addr;

		Mac mac{};
		// AP first (the common case: phones associate to the device's SoftAP), then
		// STA (the device is itself a client on an upstream LAN), then Ethernet.
		// First hit wins.
		//
		// ETH_DEF is not optional (issue #103). On an Ethernet build -- the whole
		// SIP_TRANSPORT=eth family, e.g. the LilyGO T-ETH-Elite -- there is no Wi-Fi
		// netif at all, so both Wi-Fi probes get a nullptr handle and this function
		// returned nullopt for EVERY caller, forever. That is a permanent ARP miss,
		// and admitLearn() treats a miss as "accept but defer the MAC-lock to the
		// next REGISTER" -- a next REGISTER that could never resolve either. The
		// device registry therefore stayed empty on every Ethernet board, so no
		// device was ever adopted and GET /config/<mac>.cfg answered 404 for all of
		// them. Silently: the miss path is a deliberate non-error.
		// The key string is ESP-IDF's own (esp_netif_defaults.h,
		// ESP_NETIF_INHERENT_DEFAULT_ETH sets .if_key = "ETH_DEF").
		if (probeIfkey("WIFI_AP_DEF", ip, mac) ||
			probeIfkey("WIFI_STA_DEF", ip, mac) ||
			probeIfkey("ETH_DEF", ip, mac))
		{
			return mac;
		}
		return std::nullopt;   // cache miss → caller defers/retries (do NOT block)
	}

#else  // ── Host stub: no ARP table on the desktop/CI build ──────────────────

	namespace
	{
		std::map<uint32_t, Mac> s_mockArpTable;
	}

	std::optional<Mac> pdLookupMac(const struct sockaddr_in& src)
	{
		if (src.sin_family != AF_INET)
		{
			return std::nullopt;
		}
		auto it = s_mockArpTable.find(src.sin_addr.s_addr);
		if (it != s_mockArpTable.end())
		{
			return it->second;
		}
		// No link layer to inspect off-device. Returning nullopt makes Learn-mode
		// on host behave like a permanent first-packet miss (accept + defer the
		// lock), which is the safe, test-friendly default.
		return std::nullopt;
	}

	void setMockMac(const struct sockaddr_in& src, const Mac& mac)
	{
		s_mockArpTable[src.sin_addr.s_addr] = mac;
	}

	void clearMockMacs()
	{
		s_mockArpTable.clear();
	}

#endif
}

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

	namespace
	{
		// pdLookupMac()'s interfaces, in its order.
		constexpr const char* kIfkeys[] = {"WIFI_AP_DEF", "WIFI_STA_DEF", "ETH_DEF"};

		struct netif* netifOf(const char* ifkey)
		{
			esp_netif_t* netif = esp_netif_get_handle_from_ifkey(ifkey);
			return (netif == nullptr) ? nullptr : static_cast<struct netif*>(esp_netif_get_netif_impl(netif));
		}

		// A unicast host on `n`'s subnet: an ARP request on `n` can reach it.
		bool onLinkOf(const struct netif* n, const ip4_addr_t& ip)
		{
			return n != nullptr && netif_is_up(n) && netif_is_link_up(n) &&
				(n->flags & NETIF_FLAG_ETHARP) != 0 &&
				!ip4_addr_isany_val(*netif_ip4_addr(n)) &&
				ip4_addr_net_eq(&ip, netif_ip4_addr(n), netif_ip4_netmask(n)) &&
				!ip4_addr_isbroadcast(&ip, n);
		}

		struct ArpRequest
		{
			ip4_addr_t ip{};
			bool sent = false;
		};

		// On lwIP's tcpip thread (esp_netif_tcpip_exec): core locking is off on
		// these builds, so etharp_request() cannot run on the caller's task.
		// etharp_request(), not etharp_query(): a host that never answers takes no
		// table slot.
		esp_err_t sendArpRequestInTcpip(void* arg)
		{
			auto* req = static_cast<ArpRequest*>(arg);
			for (const char* key : kIfkeys)
			{
				struct netif* n = netifOf(key);
				if (onLinkOf(n, req->ip) && etharp_request(n, &req->ip) == ERR_OK) req->sent = true;
			}
			return ESP_OK;
		}
	}

	bool pdIsOnLink(const struct sockaddr_in& src)
	{
		if (src.sin_family != AF_INET) return false;
		ip4_addr_t ip;
		ip.addr = src.sin_addr.s_addr;
		for (const char* key : kIfkeys)
		{
			if (onLinkOf(netifOf(key), ip)) return true;
		}
		return false;
	}

	bool pdSendArpRequest(const struct sockaddr_in& src)
	{
		if (src.sin_family != AF_INET) return false;
		ArpRequest req{};
		req.ip.addr = src.sin_addr.s_addr;
		return esp_netif_tcpip_exec(&sendArpRequestInTcpip, &req) == ESP_OK && req.sent;
	}

#else  // ── Host stub: no ARP table on the desktop/CI build ──────────────────

	namespace
	{
		std::map<uint32_t, Mac> s_mockArpTable;
		// #864: hosts on this subnet, each with what it answers to an ARP request.
		std::map<uint32_t, std::optional<Mac>> s_mockOnLink;
		int s_mockArpRequests = 0;
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

	bool pdIsOnLink(const struct sockaddr_in& src)
	{
		return src.sin_family == AF_INET && s_mockOnLink.count(src.sin_addr.s_addr) != 0;
	}

	bool pdSendArpRequest(const struct sockaddr_in& src)
	{
		if (!pdIsOnLink(src)) return false;
		++s_mockArpRequests;
		const std::optional<Mac>& reply = s_mockOnLink[src.sin_addr.s_addr];
		if (reply.has_value()) s_mockArpTable[src.sin_addr.s_addr] = *reply;   // the reply lands
		return true;
	}

	void setMockMac(const struct sockaddr_in& src, const Mac& mac)
	{
		s_mockArpTable[src.sin_addr.s_addr] = mac;
	}

	void setMockOnLink(const struct sockaddr_in& src, std::optional<Mac> reply)
	{
		s_mockOnLink[src.sin_addr.s_addr] = reply;
	}

	int mockArpRequestCount()
	{
		return s_mockArpRequests;
	}

	void clearMockMacs()
	{
		s_mockArpTable.clear();
		s_mockOnLink.clear();
		s_mockArpRequests = 0;
	}

#endif
}

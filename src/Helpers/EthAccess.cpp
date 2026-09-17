#include "EthAccess.hpp"

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "esp_eth.h"
#include "esp_netif.h"
#include "esp_mac.h"
#endif

namespace EthAccess
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	static esp_eth_handle_t s_eth_handle = nullptr;

	void setEthHandle(void* handle)
	{
		s_eth_handle = static_cast<esp_eth_handle_t>(handle);
	}

	bool transmitL2(void* frame, size_t len)
	{
		if (s_eth_handle == nullptr) return false;
		return esp_eth_transmit(s_eth_handle, frame, len) == ESP_OK;
	}

	bool getLocalIpInfo(uint32_t& ip, uint32_t& gw, uint32_t& netmask)
	{
		esp_netif_t* netif = esp_netif_get_handle_from_ifkey("ETH_DEF");
		if (netif == nullptr) return false;

		esp_netif_ip_info_t info;
		if (esp_netif_get_ip_info(netif, &info) != ESP_OK) return false;

		// esp_ip4_addr_t::addr is a raw uint32_t in NETWORK byte order (the
		// same convention as sockaddr_in::sin_addr.s_addr) -- esp_netif_ip4_makeu32
		// is a 4-argument macro that BUILDS an address from four separate octets,
		// not a byte-order converter for an existing one; calling it with a single
		// struct argument doesn't even preprocess. esp_netif_htonl is the actual
		// byte-swap primitive (used the same way in esp_netif_loopback.c).
		ip      = esp_netif_htonl(info.ip.addr);
		gw      = esp_netif_htonl(info.gw.addr);
		netmask = esp_netif_htonl(info.netmask.addr);

		return true;
	}

	bool getLocalMac(std::array<uint8_t, 6>& mac)
	{
		return esp_read_mac(mac.data(), ESP_MAC_ETH) == ESP_OK;
	}
#else
	// Host stubs
	void setEthHandle(void* /*handle*/) {}
	
	bool transmitL2(void* /*frame*/, size_t /*len*/) 
	{ 
		return false; 
	}
	
	bool getLocalIpInfo(uint32_t& /*ip*/, uint32_t& /*gw*/, uint32_t& /*netmask*/) 
	{ 
		return false; 
	}
	
	bool getLocalMac(std::array<uint8_t, 6>& /*mac*/) 
	{ 
		return false; 
	}
#endif
}

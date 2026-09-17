#include "EthAccess.hpp"
#include <vector>

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
	// ── Host stubs & test injection ──────────────────────────────────────────
	namespace
	{
		bool s_mockIpAvailable = false;
		uint32_t s_mockIp = 0;
		uint32_t s_mockGw = 0;
		uint32_t s_mockNetmask = 0;

		bool s_mockMacAvailable = false;
		std::array<uint8_t, 6> s_mockMac{};

		bool s_mockTransmitResult = false;
		size_t s_mockTransmitCount = 0;
		std::vector<uint8_t> s_lastTransmittedFrame{};
	}

	void setEthHandle(void* /*handle*/) {}

	bool transmitL2(void* frame, size_t len)
	{
		if (!s_mockTransmitResult) return false;
		++s_mockTransmitCount;
		if (frame != nullptr && len > 0)
		{
			const uint8_t* p = static_cast<const uint8_t*>(frame);
			s_lastTransmittedFrame.assign(p, p + len);
		}
		return true;
	}

	bool getLocalIpInfo(uint32_t& ip, uint32_t& gw, uint32_t& netmask)
	{
		if (!s_mockIpAvailable) return false;
		ip = s_mockIp;
		gw = s_mockGw;
		netmask = s_mockNetmask;
		return true;
	}

	bool getLocalMac(std::array<uint8_t, 6>& mac)
	{
		if (!s_mockMacAvailable) return false;
		mac = s_mockMac;
		return true;
	}

	void setMockIpInfo(bool available, uint32_t ip, uint32_t gw, uint32_t netmask)
	{
		s_mockIpAvailable = available;
		s_mockIp = ip;
		s_mockGw = gw;
		s_mockNetmask = netmask;
	}

	void setMockMac(bool available, const std::array<uint8_t, 6>& mac)
	{
		s_mockMacAvailable = available;
		s_mockMac = mac;
	}

	void setMockTransmitResult(bool success)
	{
		s_mockTransmitResult = success;
	}

	void resetMocks()
	{
		s_mockIpAvailable = false;
		s_mockIp = 0;
		s_mockGw = 0;
		s_mockNetmask = 0;
		s_mockMacAvailable = false;
		s_mockMac.fill(0);
		s_mockTransmitResult = false;
		s_mockTransmitCount = 0;
		s_lastTransmittedFrame.clear();
	}

	size_t getMockTransmitCount()
	{
		return s_mockTransmitCount;
	}

	const std::vector<uint8_t>& getLastTransmittedFrame()
	{
		return s_lastTransmittedFrame;
	}
#endif
}

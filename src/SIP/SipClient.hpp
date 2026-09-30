#ifndef SIP_CLIENT_HPP
#define SIP_CLIENT_HPP

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <lwip/sockets.h>
#undef INADDR_NONE
#elif defined(__linux__)
#include <netinet/in.h>
#elif defined _WIN32 || defined _WIN64
#include <WinSock2.h>
#endif

#include <iostream>
#include <string>
#include <string_view>
#include <chrono>

class SipClient
{
public:
	SipClient();
	SipClient(std::string number, sockaddr_in address, int expiresSeconds = 3600);

	void reset(std::string number, sockaddr_in address, int expiresSeconds);
	void release();

	bool operator==(const SipClient& other) const;

	const std::string& getNumber() const;
	const sockaddr_in& getAddress() const;

	// ── Registered Contact URI (RFC 3261 §10.2.1) ────────────────────
	// The URI the phone registered, URI parameters included (a Snom refuses a
	// request without its ;line=). Requests the PBX sends to this phone are
	// addressed to it. Empty when none was stored, and callers then fall back to
	// sip:<number>@<ip>:<port>. Bounded by kMaxContactUriLen; one buffer per pool
	// slot that keeps its capacity across re-REGISTERs (#284).
	static constexpr size_t kMaxContactUriLen = 128;
	// A URI that is not sip:/sips:, contains whitespace or angle brackets, or is
	// over kMaxContactUriLen is refused: the stored URI is cleared, not truncated.
	void setContactUri(std::string_view uri);
	const std::string& getContactUri() const;

	// ── Registration lease (RFC 3261 §10.2.1) ────────────────────────
	// True once the lease deadline has passed.
	bool isExpired(std::chrono::steady_clock::time_point now) const;
	// Negotiated lease length echoed back to the client in the 200 OK.
	int getExpiresSeconds() const;

	// ── OPTIONS Keepalive tracking ───────────────────────────────────
	void markActive();
	std::chrono::steady_clock::time_point getLastActiveTime() const;

	void setLastPingTime(std::chrono::steady_clock::time_point t);
	std::chrono::steady_clock::time_point getLastPingTime() const;
#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
	// Test-only (#533): age the keepalive clock without sleeping 15 s.
	void setLastActiveTimeForTest(std::chrono::steady_clock::time_point t) { _lastActiveTime = t; }
	// Test-only (#603 review): expire the registration lease now.
	void expireLeaseForTest() { _expiresAt = std::chrono::steady_clock::now() - std::chrono::seconds(1); }
#endif

private:
	std::string _number;
	std::string _contactUri;
	sockaddr_in _address;
	int _expiresSeconds;
	std::chrono::steady_clock::time_point _expiresAt;

	std::chrono::steady_clock::time_point _lastActiveTime;
	std::chrono::steady_clock::time_point _lastPingTime;
};

#endif

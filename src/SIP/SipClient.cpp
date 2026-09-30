#include "SipClient.hpp"

SipClient::SipClient()
	: _address{}, _expiresSeconds(0)
{
}

SipClient::SipClient(std::string number, sockaddr_in address, int expiresSeconds)
	: _number(std::move(number)), _address(address),
	  _expiresSeconds(expiresSeconds),
	  _expiresAt(std::chrono::steady_clock::now() + std::chrono::seconds(expiresSeconds)),
	  _lastActiveTime(std::chrono::steady_clock::now()),
	  _lastPingTime(std::chrono::steady_clock::now() - std::chrono::seconds(30))
{
}

void SipClient::reset(std::string number, sockaddr_in address, int expiresSeconds)
{
	_number = std::move(number);
	_contactUri.clear();
	_address = address;
	_expiresSeconds = expiresSeconds;
	_expiresAt = std::chrono::steady_clock::now() + std::chrono::seconds(expiresSeconds);
	_lastActiveTime = std::chrono::steady_clock::now();
	_lastPingTime = std::chrono::steady_clock::now() - std::chrono::seconds(30);
}

void SipClient::release()
{
	_number.clear();
	_contactUri.clear();
}

void SipClient::setContactUri(std::string_view uri)
{
	const bool scheme = uri.substr(0, 4) == "sip:" || uri.substr(0, 5) == "sips:";
	bool clean = scheme && uri.size() <= kMaxContactUriLen;
	for (size_t i = 0; clean && i < uri.size(); ++i)
	{
		const unsigned char c = static_cast<unsigned char>(uri[i]);
		clean = c > ' ' && c < 0x7f && c != '<' && c != '>' && c != '"';
	}
	if (clean) _contactUri.assign(uri);
	else _contactUri.clear();
}

const std::string& SipClient::getContactUri() const
{
	return _contactUri;
}

bool SipClient::isExpired(std::chrono::steady_clock::time_point now) const
{
	return now >= _expiresAt;
}

int SipClient::getExpiresSeconds() const
{
	return _expiresSeconds;
}

void SipClient::markActive()
{
	_lastActiveTime = std::chrono::steady_clock::now();
}

std::chrono::steady_clock::time_point SipClient::getLastActiveTime() const
{
	return _lastActiveTime;
}

void SipClient::setLastPingTime(std::chrono::steady_clock::time_point t)
{
	_lastPingTime = t;
}

std::chrono::steady_clock::time_point SipClient::getLastPingTime() const
{
	return _lastPingTime;
}

bool SipClient::operator==(const SipClient& other) const
{
	return _number == other._number;
}

const std::string& SipClient::getNumber() const
{
	return _number;
}

const sockaddr_in& SipClient::getAddress() const
{
	return _address;
}


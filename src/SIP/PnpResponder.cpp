#include "PnpResponder.hpp"

#include <cstring>

#include "PbxPersist.hpp"

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	#include "esp_log.h"
	#include "nvs.h"
#endif

// See PnpResponder.hpp. Power-of-10 rules: no recursion, no heap, bounded
// loops, every input checked before use.

namespace
{
	constexpr const char* kNvsKey = "pnp_mode";
	constexpr std::size_t kTagHex = 8;

	// FNV-1a over the Call-ID: the same SUBSCRIBE (and its retransmissions)
	// always gets the same To tag, so they all belong to one dialog.
	uint32_t hash32(std::string_view s)
	{
		uint32_t h = 2166136261U;
		for (std::size_t i = 0; i < s.size(); ++i)
		{
			h ^= static_cast<uint8_t>(s[i]);
			h *= 16777619U;
		}
		return h;
	}

	// `prefix` + 8 hex digits of `v`, NUL-terminated; returns the view.
	template <std::size_t N>
	std::string_view hexToken(std::string_view prefix, uint32_t v, std::array<char, N>& out)
	{
		static_assert(N > kTagHex, "token buffer too small");
		if (prefix.size() + kTagHex >= N) return {};
		static constexpr char kDigits[] = "0123456789abcdef";
		std::memcpy(out.data(), prefix.data(), prefix.size());
		for (std::size_t i = 0; i < kTagHex; ++i)
		{
			out[prefix.size() + i] = kDigits[(v >> (28U - 4U * i)) & 0xFU];
		}
		out[prefix.size() + kTagHex] = '\0';
		return std::string_view(out.data(), prefix.size() + kTagHex);
	}

	// Network-order IPv4 -> dotted quad, NUL-terminated; returns the view.
	std::string_view dotted(uint32_t ipNet, std::array<char, 16>& out)
	{
		std::array<uint8_t, 4> b{};
		std::memcpy(b.data(), &ipNet, b.size());
		std::size_t n = 0;
		for (std::size_t i = 0; i < b.size(); ++i)
		{
			const uint8_t v = b[i];
			if (v >= 100U) out[n++] = static_cast<char>('0' + v / 100U);
			if (v >= 10U) out[n++] = static_cast<char>('0' + (v / 10U) % 10U);
			out[n++] = static_cast<char>('0' + v % 10U);
			if (i + 1 < b.size()) out[n++] = '.';
		}
		out[n] = '\0';   // n <= 15
		return std::string_view(out.data(), n);
	}

	std::string_view macView(const pnp::DeviceId& id)
	{
		return std::string_view(id.mac.data(), pnp::kMacCap - 1);
	}
}

PnpResponder::Mode PnpResponder::decodeStored(uint8_t v)
{
	if (v == static_cast<uint8_t>(Mode::Discover)) return Mode::Discover;
	if (v == static_cast<uint8_t>(Mode::Provision)) return Mode::Provision;
	return Mode::Off;
}

void PnpResponder::setNetwork(uint32_t ip, uint32_t mask, uint16_t port)
{
	_ip = ip;
	_mask = mask;
	_port = port;
	(void)dotted(ip, _ipText);
}

void PnpResponder::setMode(Mode m)
{
	_mode.store(m, std::memory_order_relaxed);
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	nvs_handle_t h;
	esp_err_t err = nvs_open(pbxpersist::kNvsNamespace, NVS_READWRITE, &h);
	if (err == ESP_OK)
	{
		err = nvs_set_u8(h, kNvsKey, static_cast<uint8_t>(m));
		if (err == ESP_OK) err = nvs_commit(h);
		nvs_close(h);
	}
	if (err != ESP_OK)
	{
		ESP_LOGE("PnP", "persisting pnp_mode failed (%s)", esp_err_to_name(err));
	}
#endif
}

void PnpResponder::loadMode()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	nvs_handle_t h;
	uint8_t v = 0;
	if (nvs_open(pbxpersist::kNvsNamespace, NVS_READONLY, &h) == ESP_OK)
	{
		if (nvs_get_u8(h, kNvsKey, &v) != ESP_OK) v = 0;
		nvs_close(h);
	}
	_mode.store(decodeStored(v), std::memory_order_relaxed);
#endif
}

bool PnpResponder::sameSubnet(uint32_t ip) const
{
	if (_ip == 0 || _mask == 0) return false;
	return (ip & _mask) == (_ip & _mask);
}

bool PnpResponder::takeToken(uint32_t now)
{
	if (_tokens < kBurst && now >= _refillAt + kRefillSeconds)
	{
		const uint32_t earned = (now - _refillAt) / kRefillSeconds;
		const uint32_t room = static_cast<uint32_t>(kBurst - _tokens);
		_tokens = static_cast<uint8_t>(_tokens + (earned < room ? earned : room));
		_refillAt = now;
	}
	if (_tokens == 0) return false;
	if (_tokens == kBurst) _refillAt = now;   // a full bucket banks nothing
	--_tokens;
	return true;
}

// The slot for this MAC: its own, else a free one, else the least recently seen.
PnpResponder::Device& PnpResponder::record(const pnp::DeviceId& id, uint32_t ip, uint32_t now)
{
	std::lock_guard<std::mutex> lock(_mu);
	std::size_t pick = kMaxDevices;
	std::size_t oldest = 0;
	for (std::size_t i = 0; i < kMaxDevices; ++i)
	{
		const Device& d = _devices[i];
		if (d.used && macView(d.id) == macView(id)) { pick = i; break; }
		if (!d.used && pick == kMaxDevices) pick = i;
		if (d.used && d.lastSeen < _devices[oldest].lastSeen) oldest = i;
	}
	if (pick == kMaxDevices || (_devices[pick].used && macView(_devices[pick].id) != macView(id)))
	{
		pick = oldest;
	}
	Device& d = _devices[pick];
	if (!d.used || macView(d.id) != macView(id))
	{
		d = Device{};
		d.used = true;
	}
	d.id = id;
	d.ip = ip;
	d.lastSeen = now;
	if (d.seen < UINT16_MAX) ++d.seen;
	return d;
}

PnpResponder::Reply PnpResponder::answer(const pnp::Subscribe& sub, const sockaddr_in& src,
	Device& dev, uint32_t now)
{
	std::array<char, 16> tagBuf{};
	std::array<char, 24> branchBuf{};
	std::array<char, 16> destBuf{};
	std::array<char, 96> urlBuf{};
	const uint32_t h = hash32(sub.callId);
	const std::string_view tag = hexToken("pd", h, tagBuf);
	const std::string_view branch = hexToken("z9hG4bKpnp", h, branchBuf);
	const std::string_view self(_ipText.data(), std::strlen(_ipText.data()));

	// One buffer: the 200 at the front, the NOTIFY right behind it.
	Reply r;
	const std::size_t okLen = pnp::writeOk(sub, tag, self, _port, _tx.data(), _tx.size());
	if (okLen == 0) return r;
	r.ok = std::string_view(_tx.data(), okLen);

	std::lock_guard<std::mutex> lock(_mu);
	if (dev.notified && now - dev.lastNotify < kNotifyCooldownSeconds) return r;
	const std::size_t urlLen = pnp::writeUrl(sub.id, self, urlBuf.data(), urlBuf.size());
	const std::string_view dest = dotted(src.sin_addr.s_addr, destBuf);
	const std::size_t nLen = (urlLen == 0) ? 0 : pnp::writeNotify(sub, tag, branch, self, _port, dest,
		ntohs(src.sin_port), std::string_view(urlBuf.data(), urlLen), _tx.data() + okLen, _tx.size() - okLen);
	if (nLen == 0) return r;
	r.notify = std::string_view(_tx.data() + okLen, nLen);
	dev.notified = true;
	dev.lastNotify = now;
	return r;
}

PnpResponder::Reply PnpResponder::onDatagram(std::string_view raw, const sockaddr_in& src,
	uint32_t nowSeconds, FunctionRef<bool(std::string_view mac)> canServe)
{
	const Mode m = mode();
	if (m == Mode::Off || src.sin_family != AF_INET) return {};
	_datagrams.fetch_add(1, std::memory_order_relaxed);
	if (!sameSubnet(src.sin_addr.s_addr))
	{
		_offSubnet.fetch_add(1, std::memory_order_relaxed);
		return {};
	}
	pnp::Subscribe sub;
	if (!pnp::parseSubscribe(raw, sub))
	{
		_notPnp.fetch_add(1, std::memory_order_relaxed);
		return {};
	}
	Device& dev = record(sub.id, src.sin_addr.s_addr, nowSeconds);
	if (m != Mode::Provision) return {};
	// A vendor this board has no PnP URL shape for gets silence, not a URL
	// that 404s: the phone would store it and stop looking for another server.
	if (pnp::vendorOf(sub.id) == pnp::Vendor::Generic) return {};
	// The token first: canServe() can scan a zero-touch range (#826 part B)
	// under the engine mutex, so a datagram flood must not reach it unmetered.
	if (!takeToken(nowSeconds)) return {};
	if (!canServe(macView(sub.id))) return {};
	const Reply r = answer(sub, src, dev, nowSeconds);
	if (!r.ok.empty()) _answered.fetch_add(1, std::memory_order_relaxed);
	return r;
}

PnpResponder::Counters PnpResponder::counters() const
{
	return Counters{_datagrams.load(std::memory_order_relaxed), _offSubnet.load(std::memory_order_relaxed),
		_notPnp.load(std::memory_order_relaxed), _answered.load(std::memory_order_relaxed)};
}

void PnpResponder::setSocketState(bool listening, int lastErrno)
{
	_listening.store(listening, std::memory_order_relaxed);
	_sockErrno.store(lastErrno, std::memory_order_relaxed);
}

std::size_t PnpResponder::forEachDevice(FunctionRef<void(const Device&)> visit) const
{
	std::lock_guard<std::mutex> lock(_mu);
	std::size_t n = 0;
	for (std::size_t i = 0; i < kMaxDevices; ++i)
	{
		if (!_devices[i].used) continue;
		visit(_devices[i]);
		++n;
	}
	return n;
}

const char* PnpResponder::modeName(Mode m)
{
	switch (m)
	{
		case Mode::Discover:  return "discover";
		case Mode::Provision: return "provision";
		case Mode::Off:
		default:              return "off";
	}
}

bool PnpResponder::parseMode(std::string_view s, Mode& out)
{
	if (s == "off")       { out = Mode::Off; return true; }
	if (s == "discover")  { out = Mode::Discover; return true; }
	if (s == "provision") { out = Mode::Provision; return true; }
	return false;
}

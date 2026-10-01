#include "PnpProfile.hpp"

// See PnpProfile.hpp. Power-of-10 rules: no recursion, no heap, every loop
// bounded by a named constant, every input checked before use.

namespace pnp
{
namespace
{
	constexpr std::size_t kMaxParams = 8;      // ';'-separated Event parameters scanned
	constexpr std::size_t kMacHexLen = 12;
	constexpr std::size_t kNpos = std::string_view::npos;

	char lower(char c)
	{
		return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
	}

	bool iequals(std::string_view a, std::string_view b)
	{
		if (a.size() != b.size()) return false;
		for (std::size_t i = 0; i < a.size(); ++i)
		{
			if (lower(a[i]) != lower(b[i])) return false;
		}
		return true;
	}

	bool istartsWith(std::string_view s, std::string_view prefix)
	{
		return s.size() >= prefix.size() && iequals(s.substr(0, prefix.size()), prefix);
	}

	// Case-insensitive find; npos when absent. Bounded by s.size().
	std::size_t ifind(std::string_view s, std::string_view needle)
	{
		if (needle.empty() || needle.size() > s.size()) return kNpos;
		const std::size_t last = s.size() - needle.size();
		for (std::size_t i = 0; i <= last; ++i)
		{
			if (iequals(s.substr(i, needle.size()), needle)) return i;
		}
		return kNpos;
	}

	std::string_view trim(std::string_view s)
	{
		std::size_t b = 0;
		while (b < s.size() && (s[b] == ' ' || s[b] == '\t')) ++b;
		std::size_t e = s.size();
		while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r')) --e;
		return s.substr(b, e - b);
	}

	std::string_view unquote(std::string_view s)
	{
		if (s.size() >= 2 && s.front() == '"' && s.back() == '"') return s.substr(1, s.size() - 2);
		return s;
	}

	bool isHex(char c)
	{
		const char l = lower(c);
		return (l >= '0' && l <= '9') || (l >= 'a' && l <= 'f');
	}

	// Keeps only characters that are safe to echo inside a quoted header
	// parameter, and truncates to fit. The phone's own bytes never reach our
	// NOTIFY unfiltered.
	void copySanitized(std::string_view in, std::array<char, kFieldCap>& out)
	{
		std::size_t n = 0;
		for (std::size_t i = 0; i < in.size() && n + 1 < out.size(); ++i)
		{
			const char c = in[i];
			const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				c == '.' || c == '-' || c == '_' || c == '+' || c == '/' || c == ' ';
			if (ok) out[n++] = c;
		}
		out[n] = '\0';
	}

	std::string_view view(const std::array<char, kFieldCap>& a)
	{
		std::size_t n = 0;
		while (n < a.size() && a[n] != '\0') ++n;
		return std::string_view(a.data(), n);
	}

	// "<sip:MAC%3a0004132E08B4@224.0.1.75>;tag=x" -> "0004132e08b4".
	bool extractMac(std::string_view header, std::array<char, kMacCap>& mac)
	{
		const std::size_t at = ifind(header, "sip:");
		if (at == kNpos) return false;
		std::string_view user = header.substr(at + 4);
		const std::size_t end = user.find_first_of("@;>");
		if (end == kNpos) return false;
		user = user.substr(0, end);
		if (istartsWith(user, "mac%3a")) user = user.substr(6);
		else if (istartsWith(user, "mac:")) user = user.substr(4);
		else return false;
		if (user.size() != kMacHexLen) return false;
		for (std::size_t i = 0; i < kMacHexLen; ++i)
		{
			if (!isHex(user[i])) return false;
			mac[i] = lower(user[i]);
		}
		mac[kMacHexLen] = '\0';
		return true;
	}

	// The value of parameter `name` in a ';'-separated list, unquoted.
	bool param(std::string_view params, std::string_view name, std::string_view& out)
	{
		std::size_t pos = 0;
		for (std::size_t i = 0; i < kMaxParams && pos < params.size(); ++i)
		{
			const std::size_t semi = params.find(';', pos);
			const std::string_view tok = trim(params.substr(pos, (semi == kNpos ? params.size() : semi) - pos));
			pos = (semi == kNpos) ? params.size() : semi + 1;
			const std::size_t eq = tok.find('=');
			if (eq != kNpos && iequals(trim(tok.substr(0, eq)), name))
			{
				out = unquote(trim(tok.substr(eq + 1)));
				return true;
			}
		}
		return false;
	}

	// Event: ua-profile;profile-type="device";vendor=...;model=...;version=...
	bool parseEvent(std::string_view value, DeviceId& id)
	{
		const std::size_t semi = value.find(';');
		if (semi == kNpos || !iequals(trim(value.substr(0, semi)), "ua-profile")) return false;
		const std::string_view params = value.substr(semi + 1);
		std::string_view v;
		if (!param(params, "profile-type", v) || !iequals(v, "device")) return false;
		copySanitized(param(params, "vendor", v) ? v : std::string_view(), id.vendor);
		copySanitized(param(params, "model", v) ? v : std::string_view(), id.model);
		copySanitized(param(params, "version", v) ? v : std::string_view(), id.version);
		return true;
	}

	enum class Hdr : uint8_t { Other, Via, From, To, CallId, CSeq, Event };

	// Full and RFC 3261 §7.3.3 compact names.
	Hdr classify(std::string_view name)
	{
		if (iequals(name, "Via") || iequals(name, "v")) return Hdr::Via;
		if (iequals(name, "From") || iequals(name, "f")) return Hdr::From;
		if (iequals(name, "To") || iequals(name, "t")) return Hdr::To;
		if (iequals(name, "Call-ID") || iequals(name, "i")) return Hdr::CallId;
		if (iequals(name, "CSeq")) return Hdr::CSeq;
		if (iequals(name, "Event") || iequals(name, "o")) return Hdr::Event;
		return Hdr::Other;
	}

	struct Scan
	{
		Subscribe sub;
		bool event = false;
	};

	void takeHeader(Hdr h, std::string_view value, Scan& s)
	{
		switch (h)
		{
			case Hdr::Via:
				if (s.sub.viaCount < kMaxVias) s.sub.vias[s.sub.viaCount++] = value;
				break;
			case Hdr::From:   s.sub.from = value; break;
			case Hdr::To:     s.sub.to = value; break;
			case Hdr::CallId: s.sub.callId = value; break;
			case Hdr::CSeq:   s.sub.cseq = value; break;
			case Hdr::Event:  s.event = parseEvent(value, s.sub.id); break;
			case Hdr::Other:
			default:
				break;
		}
	}

	class Writer
	{
	public:
		Writer(char* buf, std::size_t cap) : _buf(buf), _cap(cap) {}
		Writer& put(std::string_view s)
		{
			// Once a put has failed, every later one fails too: a message with a
			// piece missing must never be returned as complete.
			if (!_ok || _buf == nullptr || s.size() > _cap - _len) { _ok = false; return *this; }
			for (std::size_t i = 0; i < s.size(); ++i) _buf[_len + i] = s[i];
			_len += s.size();
			return *this;
		}
		Writer& putU(uint32_t v)
		{
			std::array<char, 10> d{};
			std::size_t n = 0;
			do { d[n++] = static_cast<char>('0' + v % 10U); v /= 10U; } while (v != 0U && n < d.size());
			std::array<char, 10> r{};
			for (std::size_t i = 0; i < n; ++i) r[i] = d[n - 1 - i];
			return put(std::string_view(r.data(), n));
		}
		std::size_t done() const { return _ok ? _len : 0; }
	private:
		char* _buf;
		std::size_t _cap;
		std::size_t _len = 0;
		bool _ok = true;
	};
}

bool parseSubscribe(std::string_view raw, Subscribe& out)
{
	if (raw.substr(0, 10) != "SUBSCRIBE ") return false;
	Scan s;
	std::size_t pos = raw.find('\n');
	pos = (pos == kNpos) ? raw.size() : pos + 1;
	for (std::size_t i = 0; i < kMaxLines && pos < raw.size(); ++i)
	{
		const std::size_t nl = raw.find('\n', pos);
		const std::string_view line = trim(raw.substr(pos, (nl == kNpos ? raw.size() : nl) - pos));
		pos = (nl == kNpos) ? raw.size() : nl + 1;
		if (line.empty()) break;   // end of headers
		const std::size_t colon = line.find(':');
		if (colon == kNpos) continue;
		takeHeader(classify(trim(line.substr(0, colon))), trim(line.substr(colon + 1)), s);
	}
	if (!s.event || s.sub.viaCount == 0 || s.sub.from.empty() || s.sub.to.empty() ||
	    s.sub.callId.empty() || s.sub.cseq.empty()) return false;
	if (ifind(s.sub.to, ";tag=") != kNpos) return false;   // in-dialog: not a discovery request
	if (!extractMac(s.sub.from, s.sub.id.mac) && !extractMac(s.sub.to, s.sub.id.mac)) return false;
	out = s.sub;
	return true;
}

Vendor vendorOf(const DeviceId& id)
{
	const std::string_view v = view(id.vendor);
	if (ifind(v, "snom") != kNpos) return Vendor::Snom;
	if (ifind(v, "yealink") != kNpos) return Vendor::Yealink;
	return Vendor::Generic;
}

std::size_t writeUrl(const DeviceId& id, std::string_view serverIp, char* buf, std::size_t cap)
{
	if (serverIp.empty() || id.mac[0] == '\0') return 0;
	Writer w(buf, cap);
	w.put("http://").put(serverIp).put("/config/");
	if (vendorOf(id) == Vendor::Snom)
	{
		w.put("snom").put(std::string_view(id.mac.data(), kMacHexLen)).put(".xml");
	}
	return w.done();
}

std::size_t writeOk(const Subscribe& sub, std::string_view toTag,
	std::string_view localIp, uint16_t localPort, char* buf, std::size_t cap)
{
	if (sub.viaCount == 0 || sub.viaCount > kMaxVias || toTag.empty()) return 0;
	Writer w(buf, cap);
	w.put("SIP/2.0 200 OK\r\n");
	for (std::size_t i = 0; i < sub.viaCount; ++i) w.put("Via: ").put(sub.vias[i]).put("\r\n");
	w.put("From: ").put(sub.from).put("\r\n");
	w.put("To: ").put(sub.to).put(";tag=").put(toTag).put("\r\n");
	w.put("Call-ID: ").put(sub.callId).put("\r\n");
	w.put("CSeq: ").put(sub.cseq).put("\r\n");
	w.put("Contact: <sip:").put(localIp).put(":").putU(localPort).put(">\r\n");
	w.put("Expires: 30\r\n");
	w.put("Content-Length: 0\r\n\r\n");
	return w.done();
}

std::size_t writeNotify(const Subscribe& sub, std::string_view toTag, std::string_view branch,
	std::string_view localIp, uint16_t localPort, std::string_view destIp, uint16_t destPort,
	std::string_view url, char* buf, std::size_t cap)
{
	if (toTag.empty() || branch.empty() || url.empty() || destIp.empty()) return 0;
	Writer w(buf, cap);
	w.put("NOTIFY sip:").put(destIp).put(":").putU(destPort).put(" SIP/2.0\r\n");
	w.put("Via: SIP/2.0/UDP ").put(localIp).put(":").putU(localPort).put(";branch=").put(branch).put("\r\n");
	w.put("Max-Forwards: 70\r\n");
	w.put("From: ").put(sub.to).put(";tag=").put(toTag).put("\r\n");
	w.put("To: ").put(sub.from).put("\r\n");
	w.put("Call-ID: ").put(sub.callId).put("\r\n");
	w.put("CSeq: 1 NOTIFY\r\n");
	w.put("Contact: <sip:").put(localIp).put(":").putU(localPort).put(">\r\n");
	w.put("Event: ua-profile;profile-type=\"device\";vendor=\"").put(view(sub.id.vendor));
	w.put("\";model=\"").put(view(sub.id.model)).put("\";version=\"").put(view(sub.id.version)).put("\"\r\n");
	w.put("Subscription-State: terminated;reason=timeout\r\n");
	w.put("Content-Type: application/url\r\n");
	w.put("Content-Length: ").putU(static_cast<uint32_t>(url.size())).put("\r\n\r\n");
	w.put(url);
	return w.done();
}
}

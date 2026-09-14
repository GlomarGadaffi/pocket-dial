#include "SmtpDialogue.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cinttypes> // PRIx32 -- uint32_t is `long unsigned int` on the xtensa-esp32s3
                     // toolchain (not `unsigned int`), so a bare "%08x" against a
                     // uint32_t argument is a real -Werror=format= build failure
                     // there, even though it is silent on host platforms where
                     // uint32_t happens to alias unsigned int. Caught by the ESP
                     // compile-only build attempt, not by any host test.
#include <cstdio>
#include <cstring>

namespace SmtpDialogue
{

namespace
{
	// ---------------------------------------------------------------------
	// Base64 (RFC 4648). Vendored so neither the host build nor this pure
	// translation unit needs mbedtls/base64.h -- mirrors SipDigest's vendored
	// MD5 for the same reason.
	// ---------------------------------------------------------------------
	constexpr char kStdAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	constexpr char kUrlAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

	std::string base64EncodeImpl(const uint8_t* data, size_t len, const char* alphabet, bool pad)
	{
		std::string out;
		out.reserve(((len + 2) / 3) * 4);
		size_t i = 0;
		while (i + 3 <= len)
		{
			uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
			             (static_cast<uint32_t>(data[i + 1]) << 8) |
			             static_cast<uint32_t>(data[i + 2]);
			out += alphabet[(v >> 18) & 0x3F];
			out += alphabet[(v >> 12) & 0x3F];
			out += alphabet[(v >> 6) & 0x3F];
			out += alphabet[v & 0x3F];
			i += 3;
		}
		size_t rem = len - i;
		if (rem == 1)
		{
			uint32_t v = static_cast<uint32_t>(data[i]) << 16;
			out += alphabet[(v >> 18) & 0x3F];
			out += alphabet[(v >> 12) & 0x3F];
			if (pad) { out += '='; out += '='; }
		}
		else if (rem == 2)
		{
			uint32_t v = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8);
			out += alphabet[(v >> 18) & 0x3F];
			out += alphabet[(v >> 12) & 0x3F];
			out += alphabet[(v >> 6) & 0x3F];
			if (pad) { out += '='; }
		}
		return out;
	}

	std::string trim(const std::string& s)
	{
		size_t b = 0, e = s.size();
		while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
		while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
		return s.substr(b, e - b);
	}

	std::string toUpper(const std::string& s)
	{
		std::string out = s;
		for (char& c : out) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
		return out;
	}

	// Reads one full (possibly multi-line) SMTP reply. `lines` receives each
	// continuation's text (prefix stripped), in order -- EHLO parsing wants
	// every line; every other caller just wants the last one, which is also
	// left in `lastText` for convenience. Returns false on timeout/closed
	// connection/malformed reply (non-digit code, or an empty line), in which
	// case `code` is left at 0.
	bool readResponse(Transport& t, uint32_t timeoutMs, int& code, std::vector<std::string>& lines, std::string& lastText)
	{
		code = 0;
		lines.clear();
		lastText.clear();
		for (;;)
		{
			std::string line;
			if (!t.readLine(line, timeoutMs)) return false;
			if (line.size() < 3) return false;
			for (int i = 0; i < 3; ++i)
			{
				if (!std::isdigit(static_cast<unsigned char>(line[i]))) return false;
			}
			int c = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
			code = c;
			bool more = (line.size() > 3 && line[3] == '-');
			std::string text = (line.size() >= 4) ? line.substr(4) : std::string();
			lines.push_back(text);
			lastText = text;
			if (!more) return true;
		}
	}

	// One line of an SMTP command, written as a single writeAll() so a
	// transport-level partial-write never splits a command across two TCP
	// segments in a way the caller has to reassemble.
	bool sendLine(Transport& t, const std::string& line)
	{
		std::string wire = line + "\r\n";
		return t.writeAll(wire.data(), wire.size());
	}

	bool sendEhlo(Transport& t, const Config& cfg, SendResult& res, EhloCapabilities& caps)
	{
		if (!sendLine(t, "EHLO " + cfg.ehloName))
		{
			res.code = ResultCode::TransportError;
			res.lastError = "write failed (EHLO)";
			return false;
		}
		int code = 0;
		std::vector<std::string> lines;
		std::string text;
		if (!readResponse(t, cfg.commandTimeoutMs, code, lines, text))
		{
			res.code = ResultCode::Timeout;
			res.lastError = "no EHLO response";
			return false;
		}
		res.smtpReplyCode = code;
		if (code != 250)
		{
			res.code = ResultCode::EhloRejected;
			res.lastError = text.empty() ? "EHLO rejected" : text;
			return false;
		}
		caps = parseEhloCapabilities(lines);
		return true;
	}

	// Fixed monotonic counter for Message-ID uniqueness within a process --
	// no RNG dependency (esp_random is ESP-only; this needs to be identical
	// in shape on host). Not a security property, just an opaque tag.
	std::atomic<uint32_t> g_messageIdCounter{0};

} // namespace

std::string base64Encode(const uint8_t* data, size_t len)
{
	return base64EncodeImpl(data, len, kStdAlphabet, /*pad=*/true);
}

std::string base64UrlEncode(const uint8_t* data, size_t len)
{
	return base64EncodeImpl(data, len, kUrlAlphabet, /*pad=*/false);
}

EhloCapabilities parseEhloCapabilities(const std::vector<std::string>& lines)
{
	EhloCapabilities caps;
	for (const auto& raw : lines)
	{
		std::string line = toUpper(trim(raw));
		if (line == "STARTTLS")
		{
			caps.startTls = true;
		}
		else if (line.compare(0, 5, "AUTH ") == 0 || line.compare(0, 5, "AUTH=") == 0)
		{
			// RFC 4954 wants "AUTH mech mech ..."; some older servers emit
			// "AUTH=mech" (a historical Microsoft/qmail variant). Either way,
			// the mechanism names are whitespace/'='-separated tokens after
			// "AUTH".
			std::string rest = line.substr(5);
			size_t pos = 0;
			while (pos < rest.size())
			{
				size_t sp = rest.find(' ', pos);
				std::string tok = (sp == std::string::npos) ? rest.substr(pos) : rest.substr(pos, sp - pos);
				if (tok == "PLAIN") caps.authPlain = true;
				else if (tok == "LOGIN") caps.authLogin = true;
				else if (tok == "XOAUTH2") caps.authXOAuth2 = true;
				if (sp == std::string::npos) break;
				pos = sp + 1;
			}
		}
	}
	return caps;
}

std::vector<std::string> splitAddresses(const std::string& list)
{
	std::vector<std::string> out;
	size_t pos = 0;
	while (pos <= list.size())
	{
		size_t comma = list.find(',', pos);
		std::string tok = trim(list.substr(pos, (comma == std::string::npos ? list.size() : comma) - pos));
		if (!tok.empty()) out.push_back(tok);
		if (comma == std::string::npos) break;
		pos = comma + 1;
	}
	return out;
}

std::string dotStuffBody(const std::string& body)
{
	std::string out;
	out.reserve(body.size() + 8);
	size_t i = 0;
	bool atLineStart = true;
	while (i < body.size())
	{
		char c = body[i];
		if (c == '\r' && i + 1 < body.size() && body[i + 1] == '\n')
		{
			out += "\r\n";
			i += 2;
			atLineStart = true;
			continue;
		}
		if (c == '\n')
		{
			// Bare LF, normalized to CRLF (RFC 5321 §2.3.8 requires CRLF on
			// the wire; a body composed with '\n' alone -- the common case
			// from any non-Windows source of the text -- must not reach the
			// server as a bare LF).
			out += "\r\n";
			++i;
			atLineStart = true;
			continue;
		}
		if (atLineStart && c == '.')
		{
			out += "..";
			++i;
			atLineStart = false;
			continue;
		}
		out += c;
		++i;
		atLineStart = false;
	}
	return out;
}

std::string formatRfc5322Date(uint64_t unixTime)
{
	if (unixTime == 0) return std::string();

	static const char* kDayNames[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
	static const char* kMonNames[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	                                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

	// Manual, allocation-free civil-from-days conversion (Howard Hinnant's
	// public-domain algorithm) rather than gmtime(), which is not
	// guaranteed reentrant/thread-safe on every libc this firmware targets
	// and behaves identically on host and device either way.
	int64_t z = static_cast<int64_t>(unixTime / 86400) + 719468;
	uint64_t secOfDay = unixTime % 86400;
	int64_t era = (z >= 0 ? z : z - 146096) / 146097;
	uint64_t doe = static_cast<uint64_t>(z - era * 146097);
	uint64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	int64_t y = static_cast<int64_t>(yoe) + era * 400;
	uint64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	uint64_t mp = (5 * doy + 2) / 153;
	uint64_t d = doy - (153 * mp + 2) / 5 + 1;
	uint64_t m = mp + (mp < 10 ? 3 : -9);
	y += (m <= 2);

	(void)z; // only used above to derive era/doe/y/m/d; weekday is independent of the +719468 shift
	int64_t daysSinceEpoch = static_cast<int64_t>(unixTime / 86400);
	int weekday = static_cast<int>(((daysSinceEpoch % 7) + 7 + 4) % 7); // 1970-01-01 was a Thursday (index 4)

	unsigned hh = static_cast<unsigned>(secOfDay / 3600);
	unsigned mm = static_cast<unsigned>((secOfDay % 3600) / 60);
	unsigned ss = static_cast<unsigned>(secOfDay % 60);

	char buf[40];
	std::snprintf(buf, sizeof(buf), "%s, %02u %s %04lld %02u:%02u:%02u +0000",
	              kDayNames[weekday], static_cast<unsigned>(d), kMonNames[static_cast<size_t>(m) - 1],
	              static_cast<long long>(y), hh, mm, ss);
	return std::string(buf);
}

bool ChunkedBase64Writer::appendEncoded(const std::string& encoded)
{
	_lineBuf += encoded;
	while (_lineBuf.size() >= 76)
	{
		std::string line = _lineBuf.substr(0, 76);
		line += "\r\n";
		if (!_sink(_ctx, line.data(), line.size())) return false;
		_lineBuf.erase(0, 76);
	}
	return true;
}

bool ChunkedBase64Writer::flushLine()
{
	if (_lineBuf.empty()) return true;
	std::string line = _lineBuf;
	line += "\r\n";
	_lineBuf.clear();
	return _sink(_ctx, line.data(), line.size());
}

bool ChunkedBase64Writer::feed(const uint8_t* data, size_t len)
{
	_carry.insert(_carry.end(), data, data + len);
	size_t groups = _carry.size() / 3;
	size_t consumed = groups * 3;
	if (consumed == 0) return true;
	std::string encoded = base64Encode(_carry.data(), consumed);
	_carry.erase(_carry.begin(), _carry.begin() + static_cast<std::vector<uint8_t>::difference_type>(consumed));
	return appendEncoded(encoded);
}

bool ChunkedBase64Writer::finish()
{
	if (!_carry.empty())
	{
		std::string encoded = base64Encode(_carry.data(), _carry.size());
		_carry.clear();
		if (!appendEncoded(encoded)) return false;
	}
	return flushLine();
}

namespace
{
	// Sink adapter: ChunkedBase64Writer speaks in raw function pointers so it
	// never allocates a std::function; this closure-free trampoline routes
	// its callback straight into Transport::writeAll.
	bool transportSink(void* ctx, const char* data, size_t len)
	{
		return static_cast<Transport*>(ctx)->writeAll(data, len);
	}

	// Builds the RFC 5322 header block shared by both the plain and
	// multipart bodies. `contentTypeLine` is the single Content-Type header
	// (differs between the two cases); everything else is identical.
	std::string buildHeaders(const Config& cfg, const Message& msg, const std::string& contentTypeLine)
	{
		std::string h;
		h += "From: " + msg.from + "\r\n";
		h += "To: " + msg.to + "\r\n";
		h += "Subject: " + msg.subject + "\r\n";
		if (!msg.dateHeader.empty())
		{
			h += "Date: " + msg.dateHeader + "\r\n";
		}
		h += "MIME-Version: 1.0\r\n";
		uint32_t n = g_messageIdCounter.fetch_add(1, std::memory_order_relaxed);
		char midBuf[96];
		std::snprintf(midBuf, sizeof(midBuf), "<pdmail-%08" PRIx32 "@%s>", n, cfg.ehloName.c_str());
		h += "Message-ID: ";
		h += midBuf;
		h += "\r\n";
		h += contentTypeLine;
		return h;
	}
}

SendResult run(Transport& transport, const Config& cfg, const Message& msg)
{
	SendResult res;
	int code = 0;
	std::vector<std::string> lines;
	std::string text;

	if (cfg.host.empty() || cfg.port == 0 || msg.from.empty() || msg.to.empty())
	{
		res.code = ResultCode::InvalidConfig;
		res.lastError = "host, port, from and to are all required";
		return res;
	}
	auto recipients = splitAddresses(msg.to);
	if (recipients.empty())
	{
		res.code = ResultCode::InvalidConfig;
		res.lastError = "no valid recipients in 'to'";
		return res;
	}

	// 1. Greeting.
	if (!readResponse(transport, cfg.commandTimeoutMs, code, lines, text))
	{
		res.code = ResultCode::Timeout;
		res.lastError = "no greeting (timeout or connection closed)";
		return res;
	}
	res.smtpReplyCode = code;
	if (code != 220)
	{
		res.code = ResultCode::GreetingRejected;
		res.lastError = text.empty() ? "greeting rejected" : text;
		return res;
	}

	// 2. EHLO.
	EhloCapabilities caps;
	if (!sendEhlo(transport, cfg, res, caps)) return res;

	// 3. STARTTLS, if configured.
	if (cfg.mode == Mode::StartTls)
	{
		if (!caps.startTls)
		{
			res.code = ResultCode::TlsFailed;
			res.lastError = "server did not advertise STARTTLS";
			return res;
		}
		if (!sendLine(transport, "STARTTLS"))
		{
			res.code = ResultCode::TransportError;
			res.lastError = "write failed (STARTTLS)";
			return res;
		}
		if (!readResponse(transport, cfg.commandTimeoutMs, code, lines, text))
		{
			res.code = ResultCode::Timeout;
			res.lastError = "no STARTTLS response";
			return res;
		}
		res.smtpReplyCode = code;
		if (code != 220)
		{
			res.code = ResultCode::TlsFailed;
			res.lastError = text.empty() ? "STARTTLS refused" : text;
			return res;
		}
		if (!transport.startTls(cfg.commandTimeoutMs))
		{
			res.code = ResultCode::TlsFailed;
			res.lastError = "TLS handshake failed";
			return res;
		}
		// RFC 3207: discard whatever capabilities were advertised in
		// plaintext and re-issue EHLO over the now-encrypted channel.
		if (!sendEhlo(transport, cfg, res, caps)) return res;
	}

	// 4. AUTH.
	if (cfg.auth != AuthMethod::None)
	{
		bool advertised = (cfg.auth == AuthMethod::Plain && caps.authPlain) ||
		                   (cfg.auth == AuthMethod::Login && caps.authLogin) ||
		                   (cfg.auth == AuthMethod::XOAuth2 && caps.authXOAuth2);
		if (!advertised)
		{
			res.code = ResultCode::AuthNotSupported;
			res.lastError = "server did not advertise the configured AUTH mechanism";
			return res;
		}

		if (cfg.auth == AuthMethod::Plain)
		{
			std::string secret;
			secret.push_back('\0');
			secret += cfg.username;
			secret.push_back('\0');
			secret += cfg.password;
			std::string cmd = "AUTH PLAIN " + base64Encode(reinterpret_cast<const uint8_t*>(secret.data()), secret.size());
			if (!sendLine(transport, cmd))
			{
				res.code = ResultCode::TransportError;
				res.lastError = "write failed (AUTH PLAIN)";
				return res;
			}
			if (!readResponse(transport, cfg.commandTimeoutMs, code, lines, text))
			{
				res.code = ResultCode::Timeout;
				res.lastError = "no response to AUTH PLAIN";
				return res;
			}
			res.smtpReplyCode = code;
			if (code != 235)
			{
				res.code = ResultCode::AuthRejected;
				res.lastError = text.empty() ? "AUTH PLAIN rejected" : text;
				return res;
			}
		}
		else if (cfg.auth == AuthMethod::Login)
		{
			if (!sendLine(transport, "AUTH LOGIN"))
			{
				res.code = ResultCode::TransportError;
				res.lastError = "write failed (AUTH LOGIN)";
				return res;
			}
			if (!readResponse(transport, cfg.commandTimeoutMs, code, lines, text))
			{
				res.code = ResultCode::Timeout;
				res.lastError = "no response to AUTH LOGIN";
				return res;
			}
			res.smtpReplyCode = code;
			if (code != 334)
			{
				res.code = ResultCode::AuthRejected;
				res.lastError = text.empty() ? "AUTH LOGIN rejected" : text;
				return res;
			}

			std::string userB64 = base64Encode(reinterpret_cast<const uint8_t*>(cfg.username.data()), cfg.username.size());
			if (!sendLine(transport, userB64))
			{
				res.code = ResultCode::TransportError;
				res.lastError = "write failed (AUTH LOGIN username)";
				return res;
			}
			if (!readResponse(transport, cfg.commandTimeoutMs, code, lines, text))
			{
				res.code = ResultCode::Timeout;
				res.lastError = "no response after AUTH LOGIN username";
				return res;
			}
			res.smtpReplyCode = code;
			if (code != 334)
			{
				res.code = ResultCode::AuthRejected;
				res.lastError = text.empty() ? "AUTH LOGIN username rejected" : text;
				return res;
			}

			std::string passB64 = base64Encode(reinterpret_cast<const uint8_t*>(cfg.password.data()), cfg.password.size());
			if (!sendLine(transport, passB64))
			{
				res.code = ResultCode::TransportError;
				res.lastError = "write failed (AUTH LOGIN password)";
				return res;
			}
			if (!readResponse(transport, cfg.commandTimeoutMs, code, lines, text))
			{
				res.code = ResultCode::Timeout;
				res.lastError = "no response after AUTH LOGIN password";
				return res;
			}
			res.smtpReplyCode = code;
			if (code != 235)
			{
				res.code = ResultCode::AuthRejected;
				res.lastError = text.empty() ? "AUTH LOGIN rejected" : text;
				return res;
			}
		}
		else // XOAuth2
		{
			std::string authStr = "user=" + cfg.username + "\x01auth=Bearer " + cfg.accessToken + "\x01\x01";
			std::string cmd = "AUTH XOAUTH2 " + base64Encode(reinterpret_cast<const uint8_t*>(authStr.data()), authStr.size());
			if (!sendLine(transport, cmd))
			{
				res.code = ResultCode::TransportError;
				res.lastError = "write failed (AUTH XOAUTH2)";
				return res;
			}
			if (!readResponse(transport, cfg.commandTimeoutMs, code, lines, text))
			{
				res.code = ResultCode::Timeout;
				res.lastError = "no response to AUTH XOAUTH2";
				return res;
			}
			res.smtpReplyCode = code;
			if (code == 334)
			{
				// RFC (draft-ietf-kitten-sasl-oauth §3.2.3): the server sent a
				// base64 JSON error-detail challenge instead of a final code.
				// The client MUST respond with an empty line so the server
				// can send the real failure response.
				if (!sendLine(transport, ""))
				{
					res.code = ResultCode::TransportError;
					res.lastError = "write failed (XOAUTH2 empty response)";
					return res;
				}
				if (!readResponse(transport, cfg.commandTimeoutMs, code, lines, text))
				{
					res.code = ResultCode::Timeout;
					res.lastError = "no final response after XOAUTH2 challenge";
					return res;
				}
				res.smtpReplyCode = code;
				res.code = ResultCode::AuthRejected;
				res.lastError = text.empty() ? "XOAUTH2 rejected" : text;
				return res;
			}
			if (code != 235)
			{
				res.code = ResultCode::AuthRejected;
				res.lastError = text.empty() ? "AUTH XOAUTH2 rejected" : text;
				return res;
			}
		}
	}

	// 5. MAIL FROM.
	if (!sendLine(transport, "MAIL FROM:<" + msg.from + ">"))
	{
		res.code = ResultCode::TransportError;
		res.lastError = "write failed (MAIL FROM)";
		return res;
	}
	if (!readResponse(transport, cfg.commandTimeoutMs, code, lines, text))
	{
		res.code = ResultCode::Timeout;
		res.lastError = "no response to MAIL FROM";
		return res;
	}
	res.smtpReplyCode = code;
	if (code < 200 || code >= 300)
	{
		res.code = ResultCode::MailFromRejected;
		res.lastError = text.empty() ? "MAIL FROM rejected" : text;
		return res;
	}

	// 6. RCPT TO, one per recipient.
	for (const auto& rcpt : recipients)
	{
		if (!sendLine(transport, "RCPT TO:<" + rcpt + ">"))
		{
			res.code = ResultCode::TransportError;
			res.lastError = "write failed (RCPT TO)";
			return res;
		}
		if (!readResponse(transport, cfg.commandTimeoutMs, code, lines, text))
		{
			res.code = ResultCode::Timeout;
			res.lastError = "no response to RCPT TO <" + rcpt + ">";
			return res;
		}
		res.smtpReplyCode = code;
		if (code < 200 || code >= 300)
		{
			res.code = ResultCode::RcptToRejected;
			res.lastError = (text.empty() ? "RCPT TO rejected" : text) + " (" + rcpt + ")";
			return res;
		}
	}

	// 7. DATA.
	if (!sendLine(transport, "DATA"))
	{
		res.code = ResultCode::TransportError;
		res.lastError = "write failed (DATA)";
		return res;
	}
	if (!readResponse(transport, cfg.commandTimeoutMs, code, lines, text))
	{
		res.code = ResultCode::Timeout;
		res.lastError = "no response to DATA";
		return res;
	}
	res.smtpReplyCode = code;
	if (code != 354)
	{
		res.code = ResultCode::DataRejected;
		res.lastError = text.empty() ? "DATA rejected" : text;
		return res;
	}

	// 8. Headers + body [+ attachment], dot-stuffed, terminated by "\r\n.\r\n".
	{
		std::string contentType;
		if (msg.attachment && msg.attachment->source)
		{
			contentType = "Content-Type: multipart/mixed; boundary=\"PDBOUNDARY\"\r\n\r\n";
		}
		else
		{
			contentType = "Content-Type: text/plain; charset=utf-8\r\n\r\n";
		}
		std::string headers = buildHeaders(cfg, msg, contentType);

		if (!msg.attachment || !msg.attachment->source)
		{
			std::string wire = dotStuffBody(headers + msg.textBody);
			if (!transport.writeAll(wire.data(), wire.size()))
			{
				res.code = ResultCode::TransportError;
				res.lastError = "write failed (message body)";
				return res;
			}
		}
		else
		{
			std::string preamble = headers;
			preamble += "--PDBOUNDARY\r\n";
			preamble += "Content-Type: text/plain; charset=utf-8\r\n\r\n";
			preamble = dotStuffBody(preamble + msg.textBody);
			if (!transport.writeAll(preamble.data(), preamble.size()))
			{
				res.code = ResultCode::TransportError;
				res.lastError = "write failed (message body)";
				return res;
			}

			// Base64 output never contains '.', so no line of the attachment
			// part can collide with dot-stuffing -- only the boundary/part
			// headers below share that property (none of them start with
			// '.' either), so this second part is written raw.
			std::string partHeader = "\r\n--PDBOUNDARY\r\n";
			partHeader += "Content-Type: " + msg.attachment->contentType + "; name=\"" + msg.attachment->filename + "\"\r\n";
			partHeader += "Content-Transfer-Encoding: base64\r\n";
			partHeader += "Content-Disposition: attachment; filename=\"" + msg.attachment->filename + "\"\r\n\r\n";
			if (!transport.writeAll(partHeader.data(), partHeader.size()))
			{
				res.code = ResultCode::TransportError;
				res.lastError = "write failed (attachment header)";
				return res;
			}

			ChunkedBase64Writer writer(&transportSink, &transport);
			uint8_t chunk[3072];
			for (;;)
			{
				size_t n = msg.attachment->source->read(chunk, sizeof(chunk));
				if (n == 0) break;
				if (!writer.feed(chunk, n))
				{
					res.code = ResultCode::TransportError;
					res.lastError = "write failed (attachment body)";
					return res;
				}
			}
			if (!writer.finish())
			{
				res.code = ResultCode::TransportError;
				res.lastError = "write failed (attachment body)";
				return res;
			}

			std::string closing = "\r\n--PDBOUNDARY--\r\n";
			if (!transport.writeAll(closing.data(), closing.size()))
			{
				res.code = ResultCode::TransportError;
				res.lastError = "write failed (MIME close)";
				return res;
			}
		}

		// RFC 5321 §4.1.1.4: the terminator is the sequence <CRLF>.<CRLF>. The
		// preceding CRLF must be written here, unconditionally -- the body
		// just written (dotStuffBody's output, or the attachment path's own
		// last write) is NOT guaranteed to already end in CRLF (a caller's
		// textBody need not end with a trailing newline), and a bare
		// "." CRLF appended straight onto non-CRLF-terminated content is not
		// a valid terminator at all: a real server (and this engine's own
		// fake-server tests) would read it as part of the previous line and
		// never see the end of DATA, hanging until the read times out. Worst
		// case here is one harmless extra blank line before the terminator
		// when the body already ended in CRLF -- ordinary and RFC-legal.
		static const char kDataTerminator[] = "\r\n.\r\n";
		if (!transport.writeAll(kDataTerminator, sizeof(kDataTerminator) - 1))
		{
			res.code = ResultCode::TransportError;
			res.lastError = "write failed (DATA terminator)";
			return res;
		}
	}

	if (!readResponse(transport, cfg.commandTimeoutMs, code, lines, text))
	{
		res.code = ResultCode::Timeout;
		res.lastError = "no response after DATA terminator";
		return res;
	}
	res.smtpReplyCode = code;
	if (code < 200 || code >= 300)
	{
		res.code = ResultCode::MessageRejected;
		res.lastError = text.empty() ? "message rejected" : text;
		return res;
	}

	// 9. QUIT, best-effort -- never overturns an already-successful send.
	if (sendLine(transport, "QUIT"))
	{
		int quitCode = 0;
		std::vector<std::string> quitLines;
		std::string quitText;
		readResponse(transport, cfg.commandTimeoutMs, quitCode, quitLines, quitText);
	}

	res.code = ResultCode::Ok;
	return res;
}

} // namespace SmtpDialogue

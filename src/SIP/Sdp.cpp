#include "Sdp.hpp"

#include <cctype>
#include <cstring>
#include <string>
#include <type_traits>

#include "SipMessage.hpp"   // SdpLimits::kMaxLines — the one bound shared with checkSdp()

namespace sdp
{
	namespace
	{
		// The same line walker every SDP consumer in this codebase uses: one flat
		// loop, primary "\n" delimiter with a trailing '\r' stripped, so CRLF and
		// bare LF bodies parse identically (docs/THREAT_MODEL.md T-7).
		std::string_view nextLine(std::string_view body, size_t& pos)
		{
			const size_t eol = body.find('\n', pos);
			const size_t end = (eol == std::string_view::npos) ? body.size() : eol;
			std::string_view line = body.substr(pos, end - pos);
			if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
			pos = (eol == std::string_view::npos) ? body.size() : eol + 1;
			return line;
		}

		Span spanOf(std::string_view body, std::string_view part)
		{
			if (part.empty()) return {};
			return Span{static_cast<uint32_t>(part.data() - body.data()),
			            static_cast<uint32_t>(part.size())};
		}

		// Decimal prefix of `s`, bounded by `max`; -1 if none or over the bound.
		// Every number this parser reads has a small documented ceiling, which is
		// what keeps the per-token work fixed rather than proportional to digits.
		long parseNumber(std::string_view s, long max, size_t* consumed = nullptr)
		{
			long v = 0;
			size_t i = 0;
			for (; i < s.size(); ++i)
			{
				const char c = s[i];
				if (c < '0' || c > '9') break;
				v = v * 10 + (c - '0');
				if (v > max) return -1;
			}
			if (consumed) *consumed = i;
			return i == 0 ? -1 : v;
		}

		bool iequal(std::string_view a, std::string_view lowerLit)
		{
			if (a.size() != lowerLit.size()) return false;
			for (size_t i = 0; i < a.size(); ++i)
				if (std::tolower(static_cast<unsigned char>(a[i])) != lowerLit[i]) return false;
			return true;
		}

		// Next SP-delimited token starting at `i`; advances `i` past it.
		std::string_view nextToken(std::string_view s, size_t& i)
		{
			while (i < s.size() && s[i] == ' ') ++i;
			const size_t start = i;
			while (i < s.size() && s[i] != ' ') ++i;
			return s.substr(start, i - start);
		}

		Direction directionOf(std::string_view name)
		{
			if (iequal(name, "sendrecv")) return Direction::SendRecv;
			if (iequal(name, "sendonly")) return Direction::SendOnly;
			if (iequal(name, "recvonly")) return Direction::RecvOnly;
			if (iequal(name, "inactive")) return Direction::Inactive;
			return Direction::None;
		}

		// m=<media> <port>[/<n>] <proto> <fmt>...
		void parseMediaLine(std::string_view body, std::string_view line, Media& m)
		{
			m.line = spanOf(body, line);
			m.portCount = 1;   // the only non-zero default; parse() zero-fills
			std::string_view rest = line.substr(2);
			size_t i = 0;

			const std::string_view type = nextToken(rest, i);
			m.typeName = spanOf(body, type);
			if (iequal(type, "audio"))      m.type = MediaType::Audio;
			else if (iequal(type, "video")) m.type = MediaType::Video;
			else                            m.type = MediaType::Other;

			const std::string_view portTok = nextToken(rest, i);
			size_t used = 0;
			const long port = parseNumber(portTok, 65535, &used);
			m.port = port < 0 ? 0 : static_cast<uint32_t>(port);
			if (used < portTok.size() && portTok[used] == '/')
			{
				const long n = parseNumber(portTok.substr(used + 1), 255);
				m.portCount = n < 1 ? 1 : static_cast<uint16_t>(n);
			}

			m.proto = spanOf(body, nextToken(rest, i));

			while (i < rest.size())
			{
				const std::string_view f = nextToken(rest, i);
				if (f.empty()) break;
				const long pt = parseNumber(f, 127);
				if (pt < 0) continue;   // non-numeric <fmt> (non-RTP proto): ignored
				if (m.fmtCount < Limits::kMaxFormats) m.fmt[m.fmtCount++] = static_cast<uint8_t>(pt);
				else if (m.droppedFormats < 255) ++m.droppedFormats;
			}
		}

		// a=rtpmap:<pt> <encoding>/<clock>[/<channels>]
		void parseRtpmap(std::string_view body, std::string_view value, Media& m)
		{
			size_t used = 0;
			const long pt = parseNumber(value, 127, &used);
			if (pt < 0) return;
			size_t i = used;
			const std::string_view enc = nextToken(value, i);
			if (enc.empty()) return;
			const size_t slash = enc.find('/');
			const std::string_view name = (slash == std::string_view::npos) ? enc : enc.substr(0, slash);
			uint32_t clock = 0;
			if (slash != std::string_view::npos)
			{
				const long c = parseNumber(enc.substr(slash + 1), 1000000);
				clock = c < 0 ? 0 : static_cast<uint32_t>(c);
			}

			// Last one wins for a repeated PT, matching the relay policy in
			// SipMessage::applyAudioPolicy. Keep any fmtp already attached to it.
			for (unsigned k = 0; k < m.rtpmapCount; ++k)
			{
				if (m.rtpmaps[k].pt == pt)
				{
					m.rtpmaps[k].encoding = spanOf(body, name);
					m.rtpmaps[k].clock = clock;
					return;
				}
			}
			if (m.rtpmapCount >= Limits::kMaxRtpmaps)
			{
				if (m.droppedRtpmaps < 255) ++m.droppedRtpmaps;
				return;
			}
			Rtpmap& r = m.rtpmaps[m.rtpmapCount++];
			r.pt = static_cast<uint8_t>(pt);
			r.encoding = spanOf(body, name);
			r.clock = clock;
			r.fmtp = {};
		}

		// a=fmtp:<pt> <params> -- attached to the rtpmap entry when one exists,
		// otherwise a placeholder entry (encoding absent) so the fmtp is still
		// reachable for a static PT the offer did not rtpmap.
		void parseFmtp(std::string_view body, std::string_view value, Media& m)
		{
			size_t used = 0;
			const long pt = parseNumber(value, 127, &used);
			if (pt < 0) return;
			size_t i = used;
			while (i < value.size() && value[i] == ' ') ++i;
			const Span params = spanOf(body, value.substr(i));
			for (unsigned k = 0; k < m.rtpmapCount; ++k)
			{
				if (m.rtpmaps[k].pt == pt) { m.rtpmaps[k].fmtp = params; return; }
			}
			if (m.rtpmapCount >= Limits::kMaxRtpmaps)
			{
				if (m.droppedRtpmaps < 255) ++m.droppedRtpmaps;
				return;
			}
			Rtpmap& r = m.rtpmaps[m.rtpmapCount++];
			r.pt = static_cast<uint8_t>(pt);
			r.encoding = {};
			r.clock = 0;
			r.fmtp = params;
		}

		// a=<name>[:<value>] at either level. The name/value split is the ONLY
		// structure read; recognised names are decoded by their own flat helper,
		// everything else is stored as an opaque span. No token re-dispatch.
		void parseAttribute(std::string_view body, std::string_view line, Session& s, Media* m)
		{
			const std::string_view rest = line.substr(2);
			const size_t colon = rest.find(':');
			const std::string_view name = (colon == std::string_view::npos) ? rest : rest.substr(0, colon);
			const std::string_view value = (colon == std::string_view::npos) ? std::string_view{} : rest.substr(colon + 1);

			Attribute a;
			a.name = spanOf(body, name);
			a.value = spanOf(body, value);

			if (m)
			{
				if (m->attrCount < Limits::kMaxMediaAttrs) m->attrs[m->attrCount++] = a;
				else if (m->droppedAttrs < 255) ++m->droppedAttrs;
			}
			else
			{
				if (s.attrCount < Limits::kMaxSessionAttrs) s.attrs[s.attrCount++] = a;
				else if (s.droppedAttrs < 255) ++s.droppedAttrs;
			}

			const Direction d = directionOf(name);
			if (d != Direction::None)
			{
				if (m) m->dir = d; else s.dir = d;
				return;
			}
			if (!m) return;   // rtpmap/fmtp/ptime are media-level only (RFC 8866 §6.6, §6.15, §6.4)
			if (iequal(name, "rtpmap"))      parseRtpmap(body, value, *m);
			else if (iequal(name, "fmtp"))   parseFmtp(body, value, *m);
			else if (iequal(name, "ptime"))
			{
				const long p = parseNumber(value, 65535);
				m->ptime = p < 0 ? 0 : static_cast<uint16_t>(p);
			}
		}
	}

	Session& scratch(unsigned slot)
	{
		// Static storage, not heap and not stack: ~1.7 KB each, allocated once at
		// load. See the declaration for the single-threaded-under-_mutex contract.
		static Session s_scratch[2];
		return s_scratch[slot < 2 ? slot : 0];
	}

	std::string_view view(std::string_view body, Span s)
	{
		if (!s.present()) return {};
		if (s.pos > body.size() || s.len > body.size() - s.pos) return {};
		return body.substr(s.pos, s.len);
	}

	bool Media::hasFormat(uint8_t pt) const
	{
		for (unsigned k = 0; k < fmtCount; ++k)
			if (fmt[k] == pt) return true;
		return false;
	}

	const Rtpmap* Media::findRtpmap(uint8_t pt) const
	{
		for (unsigned k = 0; k < rtpmapCount; ++k)
			if (rtpmaps[k].pt == pt) return &rtpmaps[k];
		return nullptr;
	}

	int Media::telephoneEventPt() const
	{
		// parse() marks the flag (it has the body to compare the encoding name
		// against); this walk needs no body. Last one wins, matching the relay
		// policy in SipMessage::applyAudioPolicy.
		int found = -1;
		for (unsigned k = 0; k < rtpmapCount; ++k)
			if (rtpmaps[k].telephoneEvent) found = rtpmaps[k].pt;
		return found;
	}

	int Session::firstAudio() const
	{
		for (unsigned k = 0; k < mediaCount; ++k)
			if (media[k].type == MediaType::Audio) return static_cast<int>(k);
		return -1;
	}

	void parse(std::string_view body, Session& out)
	{
		// Rebuilt from scratch: nothing from a previous body survives. Cleared IN
		// PLACE rather than via `out = Session{}`: that form materialises a
		// ~2.2 KB temporary Session on the caller's stack (measured by
		// tests/tools/check_parser_callgraph.py), a quarter of the 8 KB
		// sip_server_task stack, every time an accessor re-parses. Session is a
		// trivially-copyable aggregate whose every default is zero except
		// Media::portCount, which parseMediaLine() sets explicitly.
		static_assert(std::is_trivially_copyable<Session>::value, "Session must stay a plain aggregate");
		std::memset(static_cast<void*>(&out), 0, sizeof(out));

		Media* cur = nullptr;          // current m= section, nullptr while at session level
		bool   skippingMedia = false;  // an m= past kMaxMedia: its lines are counted, not decoded

		size_t pos = 0;
		while (pos < body.size())
		{
			const std::string_view line = nextLine(body, pos);
			if (line.empty()) continue;
			if (out.lines >= SdpLimits::kMaxLines) { out.truncated = true; break; }
			++out.lines;
			if (line.size() < 2 || line[1] != '=') continue;   // checkSdp() refused these on the wire path

			const char type = line[0];
			if (type == 'm')
			{
				if (out.mediaCount >= Limits::kMaxMedia)
				{
					if (out.droppedMedia < 255) ++out.droppedMedia;
					skippingMedia = true;
					cur = nullptr;
					continue;
				}
				skippingMedia = false;
				cur = &out.media[out.mediaCount++];
				parseMediaLine(body, line, *cur);
				continue;
			}
			if (skippingMedia) continue;

			switch (type)
			{
				case 'v': if (!cur) out.version = spanOf(body, line); break;
				case 'o': if (!cur) out.origin  = spanOf(body, line); break;
				case 's': if (!cur) out.name    = spanOf(body, line); break;
				case 't': if (!cur) out.time    = spanOf(body, line); break;
				case 'c':
					if (cur) cur->connection = spanOf(body, line);
					else     out.connection  = spanOf(body, line);
					break;
				case 'a':
					parseAttribute(body, line, out, cur);
					break;
				default: break;   // b=, k=, i=, u=, e=, p=, z=, r=: carried, not modelled
			}
		}

		// Second, bounded pass over the rtpmap tables only: mark telephone-event
		// entries so Media::telephoneEventPt() needs no body to answer. Encoding
		// names are compared case-insensitively (RFC 8866 §6.6 says they are not
		// case sensitive, and phones do ship "TELEPHONE-EVENT").
		for (unsigned i = 0; i < out.mediaCount; ++i)
		{
			Media& m = out.media[i];
			for (unsigned k = 0; k < m.rtpmapCount; ++k)
			{
				m.rtpmaps[k].telephoneEvent =
					iequal(view(body, m.rtpmaps[k].encoding), "telephone-event");
			}
		}
	}

	Direction effectiveDirection(const Session& s, unsigned i)
	{
		if (i >= s.mediaCount) return Direction::None;
		if (s.media[i].dir != Direction::None) return s.media[i].dir;
		if (s.dir != Direction::None) return s.dir;
		return Direction::SendRecv;
	}

	Span effectiveConnection(const Session& s, unsigned i)
	{
		if (i < s.mediaCount && s.media[i].connection.present()) return s.media[i].connection;
		return s.connection;
	}

	ConnAddress connectionAddress(std::string_view body, Span connectionLine)
	{
		ConnAddress r;
		const std::string_view line = view(body, connectionLine);
		if (line.size() < 2) return r;
		std::string_view rest = line.substr(2);          // "IN IP4 1.2.3.4"
		size_t i = 0;
		const std::string_view nettype = nextToken(rest, i);
		const std::string_view addrtype = nextToken(rest, i);
		std::string_view addr = nextToken(rest, i);
		if (!iequal(nettype, "in")) return r;
		r.isIp4 = iequal(addrtype, "ip4");
		const size_t slash = addr.find('/');           // multicast TTL / count suffix
		if (slash != std::string_view::npos) addr = addr.substr(0, slash);
		if (addr.empty()) return r;
		r.addr = spanOf(body, addr);
		r.isZero = (addr == "0.0.0.0") || (!r.isIp4 && (addr == "::" || addr == "0::0"));
		return r;
	}

	bool isHold(std::string_view body, const Session& s, unsigned i)
	{
		if (i >= s.mediaCount) return false;
		const Direction d = effectiveDirection(s, i);
		if (d == Direction::SendOnly || d == Direction::Inactive) return true;
		return connectionAddress(body, effectiveConnection(s, i)).isZero;
	}

	// ── Writer ────────────────────────────────────────────────────────────────

	const char* directionText(Direction d)
	{
		switch (d)
		{
			case Direction::SendRecv: return "sendrecv";
			case Direction::SendOnly: return "sendonly";
			case Direction::RecvOnly: return "recvonly";
			case Direction::Inactive: return "inactive";
			default: return "";
		}
	}

	bool MediaSpec::add(const FormatSpec& f)
	{
		if (formatCount >= Limits::kMaxWriteFormats) return false;
		formats[formatCount++] = f;
		return true;
	}

	MediaSpec* SessionSpec::addMedia()
	{
		if (mediaCount >= Limits::kMaxMedia) return nullptr;
		return &media[mediaCount++];
	}

	void write(const SessionSpec& spec, std::string& out)
	{
		const char* addr = spec.originAddr ? spec.originAddr : "0.0.0.0";
		out += "v=0\r\n";
		out += "o="; out += spec.originUser; out += " 0 0 IN IP4 "; out += addr; out += "\r\n";
		out += "s="; out += spec.name; out += "\r\n";
		out += "c=IN IP4 "; out += addr; out += "\r\n";
		out += "t=0 0\r\n";
		if (spec.dir != Direction::None) { out += "a="; out += directionText(spec.dir); out += "\r\n"; }
		for (unsigned i = 0; i < spec.mediaCount; ++i)
		{
			const MediaSpec& m = spec.media[i];
			out += "m="; out += m.type; out += ' '; out += std::to_string(m.port); out += ' '; out += m.proto;
			for (unsigned k = 0; k < m.formatCount; ++k) { out += ' '; out += std::to_string(m.formats[k].pt); }
			out += "\r\n";
			if (m.connection) { out += "c=IN IP4 "; out += m.connection; out += "\r\n"; }
			for (unsigned k = 0; k < m.formatCount; ++k)
			{
				const FormatSpec& f = m.formats[k];
				if (f.encoding)
				{
					out += "a=rtpmap:"; out += std::to_string(f.pt); out += ' '; out += f.encoding;
					out += '/'; out += std::to_string(f.clock); out += "\r\n";
				}
				if (f.fmtp)
				{
					out += "a=fmtp:"; out += std::to_string(f.pt); out += ' '; out += f.fmtp; out += "\r\n";
				}
			}
			if (m.ptime) { out += "a=ptime:"; out += std::to_string(m.ptime); out += "\r\n"; }
			if (m.dir != Direction::None) { out += "a="; out += directionText(m.dir); out += "\r\n"; }
		}
	}
}

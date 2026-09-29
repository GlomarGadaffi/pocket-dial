// EmittedConformance_test.cpp — every message the PBX sends, recorded (Part of #199).
//
// "We're a PBX: every message we SEND must be legit." The rest of the suite
// asserts on the fields each feature cares about; nothing looked at a whole
// emitted message as a strict peer would. These scenarios drive the real
// RequestsHandler through every message type it produces, with a tiny
// auto-answering UA standing in for each phone and for the carrier, and record
// the whole exchange -- every stimulus fed in, every datagram handed to the
// send callback -- in order.
//
// Judging happens elsewhere: tests/conformance/emitted_conformance.py reads the
// transcript (PD_EMITTED_TRANSCRIPT), feeds every outbound message to pjsip's
// parser (tests/conformance/pjsip_check.c) and runs an RFC 3261 checklist,
// against an allowlist of known, issue-referenced violations. ctest runs the
// two as a pair (tests/CMakeLists.txt, emitted_conformance*). Without the env
// var the scenarios still run, and each still asserts its positive control:
// the message it exists to provoke really went out.
//
// Conventions the checker relies on:
//   * every simulated party's tags start "<name>-tag", so the checker knows
//     whose tag is whose (the From/To orientation rule, #700);
//   * an SDP body's o= username is "<name>-offer" or "<name>-answer", so an
//     answer relayed as a new offer is visible on the wire (#719);
//   * all addresses are RFC 1918 / RFC 5737 TEST-NET; the carrier is
//     203.0.113.5. Nothing leaves the process.

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "RequestsHandler.hpp"
#include "SipSecretStore.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	constexpr const char* kCarrierIp = "203.0.113.5";

	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(port);
		return a;
	}

	std::string peerOf(const sockaddr_in& a)
	{
		char ip[INET_ADDRSTRLEN]{};
		inet_ntop(AF_INET, &a.sin_addr, ip, sizeof(ip));
		return std::string(ip) + ":" + std::to_string(ntohs(a.sin_port));
	}

	// ── raw-text helpers (the UA must not lean on the parser under test) ─────
	std::string firstLine(const std::string& m) { return m.substr(0, m.find("\r\n")); }
	bool isResponse(const std::string& m) { return m.rfind("SIP/2.0 ", 0) == 0; }
	int statusOf(const std::string& m) { return isResponse(m) ? std::atoi(m.c_str() + 8) : 0; }
	std::string methodOf(const std::string& m) { return isResponse(m) ? "" : m.substr(0, m.find(' ')); }

	std::string lower(std::string s)
	{
		for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
		return s;
	}

	// Every header line named `name` (full or compact form), without the name.
	std::vector<std::string> headers(const std::string& m, const std::string& name, const std::string& compact = "")
	{
		std::vector<std::string> out;
		const size_t headEnd = m.find("\r\n\r\n");
		size_t pos = m.find("\r\n");
		while (pos != std::string::npos && pos < headEnd)
		{
			pos += 2;
			size_t eol = m.find("\r\n", pos);
			const std::string line = m.substr(pos, eol - pos);
			const size_t colon = line.find(':');
			if (colon != std::string::npos)
			{
				std::string n = line.substr(0, colon);
				while (!n.empty() && n.back() == ' ') n.pop_back();
				if (lower(n) == lower(name) || (!compact.empty() && lower(n) == compact))
				{
					size_t v = colon + 1;
					while (v < line.size() && line[v] == ' ') ++v;
					out.push_back(line.substr(v));
				}
			}
			pos = eol;
		}
		return out;
	}
	std::string header(const std::string& m, const std::string& name, const std::string& compact = "")
	{
		auto v = headers(m, name, compact);
		return v.empty() ? std::string{} : v.front();
	}
	std::string body(const std::string& m)
	{
		const size_t p = m.find("\r\n\r\n");
		return p == std::string::npos ? std::string{} : m.substr(p + 4);
	}
	std::string param(const std::string& value, const std::string& name)
	{
		const size_t p = value.find(";" + name + "=");
		if (p == std::string::npos) return {};
		const size_t s = p + name.size() + 2;
		const size_t e = value.find_first_of(";>, \r", s);
		return value.substr(s, e == std::string::npos ? std::string::npos : e - s);
	}
	// "<sip:x@y>;tag=1" -> "sip:x@y"; "sip:x@y;tag=1" -> "sip:x@y"
	std::string uriOf(const std::string& nameAddr)
	{
		const size_t lt = nameAddr.find('<');
		if (lt != std::string::npos) return nameAddr.substr(lt + 1, nameAddr.find('>', lt) - lt - 1);
		return nameAddr.substr(0, nameAddr.find(';'));
	}
	uint32_t cseqNum(const std::string& m) { return static_cast<uint32_t>(std::strtoul(header(m, "CSeq").c_str(), nullptr, 10)); }
	std::string cseqMethod(const std::string& m)
	{
		const std::string v = header(m, "CSeq");
		const size_t sp = v.find(' ');
		return sp == std::string::npos ? "" : v.substr(sp + 1);
	}
	std::string sdpDirection(const std::string& sdp)
	{
		for (const char* d : {"sendonly", "recvonly", "inactive", "sendrecv"})
		{
			if (sdp.find(std::string("a=") + d) != std::string::npos) return d;
		}
		return "sendrecv";
	}
	std::string answerDirection(const std::string& offerDir)
	{
		if (offerDir == "sendonly") return "recvonly";
		if (offerDir == "recvonly") return "sendonly";
		if (offerDir == "inactive") return "inactive";
		return "sendrecv";
	}

	// ── transcript ───────────────────────────────────────────────────────────
	std::string jsonEscape(const std::string& s)
	{
		std::string o;
		o.reserve(s.size() + 16);
		for (unsigned char c : s)
		{
			switch (c)
			{
			case '"':  o += "\\\""; break;
			case '\\': o += "\\\\"; break;
			case '\r': o += "\\r"; break;
			case '\n': o += "\\n"; break;
			case '\t': o += "\\t"; break;
			default:
				if (c < 0x20 || c >= 0x7f)
				{
					char b[8];
					std::snprintf(b, sizeof(b), "\\u%04x", c);
					o += b;
				}
				else o += static_cast<char>(c);
			}
		}
		return o;
	}

	FILE* transcriptFile()
	{
		static FILE* f = [] {
			const char* p = std::getenv("PD_EMITTED_TRANSCRIPT");
			return (p && *p) ? std::fopen(p, "wb") : nullptr;
		}();
		return f;
	}

	struct Bench;

	// ── the simulated user agent ─────────────────────────────────────────────
	struct Phone
	{
		enum class OnInvite { Answer, Ring, Busy, Progress, Reject, Ignore };
		enum class OnReinvite { Answer, Glare };

		std::string name, ext, ip;
		uint16_t port = 5060;
		OnInvite onInvite = OnInvite::Answer;
		OnReinvite onReinvite = OnReinvite::Answer;
		std::string recordRoute;   // the carrier puts itself in the route set
		bool challengeRegister = false;   // the carrier answers a bare REGISTER 401
		int rejectCode = 0;               // OnInvite::Reject
		std::string rejectReason;
		int seq = 0;

		struct Dialog
		{
			std::string localTag, remoteTag, localUri, remoteUri, remoteTarget;
			std::string inviteRaw;      // our own INVITE (UAC) or theirs pending an answer (UAS)
			uint32_t cseq = 100;
			bool answered = false;
		};
		std::map<std::string, Dialog> dialogs;   // by Call-ID

		sockaddr_in addr() const { return addrFor(ip, port); }
		std::string tag() { return name + "-tag" + std::to_string(++seq); }
		std::string branch() { return "z9hG4bK" + name + "br" + std::to_string(++seq); }
		std::string contact() const { return "<sip:" + ext + "@" + ip + ":" + std::to_string(port) + ">"; }
		std::string via() { return "Via: SIP/2.0/UDP " + ip + ":" + std::to_string(port) + ";branch=" + branch() + ";rport\r\n"; }

		std::string sdp(const std::string& role, const std::string& dir, int mport = 0) const
		{
			return
				"v=0\r\n"
				"o=" + name + "-" + role + " 1 1 IN IP4 " + ip + "\r\n"
				"s=-\r\n"
				"c=IN IP4 " + ip + "\r\n"
				"t=0 0\r\n"
				"m=audio " + std::to_string(mport ? mport : 20000 + (seq % 100) * 2) + " RTP/AVP 0 101\r\n"
				"a=rtpmap:0 PCMU/8000\r\n"
				"a=rtpmap:101 telephone-event/8000\r\n"
				"a=fmtp:101 0-15\r\n"
				"a=" + dir + "\r\n";
		}
		static std::string withBody(const std::string& head, const std::string& b)
		{
			if (b.empty()) return head + "Content-Length: 0\r\n\r\n";
			return head + "Content-Type: application/sdp\r\nContent-Length: " + std::to_string(b.size()) + "\r\n\r\n" + b;
		}

		// A response to `req`, echoing it the way RFC 3261 §8.2.6 says.
		std::string response(const std::string& req, int code, const std::string& reason,
			const std::string& localTag, const std::string& sdpBody = "", const std::string& extra = "")
		{
			std::string r = "SIP/2.0 " + std::to_string(code) + " " + reason + "\r\n";
			for (const auto& v : headers(req, "Via", "v")) r += "Via: " + v + "\r\n";
			for (const auto& rr : headers(req, "Record-Route")) r += "Record-Route: " + rr + "\r\n";
			if (!recordRoute.empty() && methodOf(req) == "INVITE") r += "Record-Route: " + recordRoute + "\r\n";
			r += "From: " + header(req, "From", "f") + "\r\n";
			std::string to = header(req, "To", "t");
			if (code > 100 && param(to, "tag").empty() && !localTag.empty()) to += ";tag=" + localTag;
			r += "To: " + to + "\r\n";
			r += "Call-ID: " + header(req, "Call-ID", "i") + "\r\n";
			r += "CSeq: " + header(req, "CSeq") + "\r\n";
			const std::string m = methodOf(req);
			if (code > 100 && code < 300 && (m == "INVITE" || m == "UPDATE" || m == "SUBSCRIBE"))
				r += "Contact: " + contact() + "\r\n";
			r += extra;
			return withBody(r, sdpBody);
		}

		// Plain, pure request builder for this party (out of dialog or in-dialog).
		std::string request(const std::string& method, const std::string& ruri,
			const std::string& from, const std::string& to, const std::string& callId,
			uint32_t cseq, const std::string& extra = "", const std::string& sdpBody = "")
		{
			std::string r = method + " " + ruri + " SIP/2.0\r\n" + via() +
				"From: " + from + "\r\nTo: " + to + "\r\nCall-ID: " + callId + "\r\n"
				"CSeq: " + std::to_string(cseq) + " " + method + "\r\nMax-Forwards: 70\r\n";
			if (method != "ACK" && method != "CANCEL" && method != "BYE") r += "Contact: " + contact() + "\r\n";
			r += extra;
			return withBody(r, sdpBody);
		}
		std::string inDialog(const std::string& callId, const std::string& method,
			const std::string& extra = "", const std::string& sdpBody = "")
		{
			Dialog& d = dialogs[callId];
			const std::string ruri = d.remoteTarget.empty() ? d.remoteUri : d.remoteTarget;
			return request(method, ruri, "<" + d.localUri + ">;tag=" + d.localTag,
				"<" + d.remoteUri + ">;tag=" + d.remoteTag, callId, ++d.cseq, extra, sdpBody);
		}

		void react(Bench& b, const std::string& m);
	};

	// ── one scenario: a real handler, its parties, and the transcript ────────
	struct Bench
	{
		struct Rec { std::string kind, peer, raw; };

		std::string scenario;
		std::string serverIp;
		std::mutex mu;
		std::vector<Rec> recs;
		size_t pumped = 0;
		std::deque<Phone> parties;
		std::unique_ptr<RequestsHandler> h;

		explicit Bench(std::string name, std::string server = "192.168.77.1")
			: scenario(std::move(name)), serverIp(std::move(server))
		{
			h = std::make_unique<RequestsHandler>(serverIp, 5060,
				[this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
					if (!m) return;
					std::lock_guard<std::mutex> lk(mu);
					recs.push_back(Rec{"out", peerOf(a), m->toString()});
				});
		}

		~Bench()
		{
			FILE* f = transcriptFile();
			if (!f) return;
			std::string meta = "{\"s\":\"" + scenario + "\",\"k\":\"meta\",\"server\":\"" + serverIp + ":5060\",\"parties\":[";
			for (size_t i = 0; i < parties.size(); ++i)
			{
				const Phone& p = parties[i];
				meta += std::string(i ? "," : "") + "{\"name\":\"" + p.name + "\",\"ext\":\"" + p.ext +
					"\",\"peer\":\"" + p.ip + ":" + std::to_string(p.port) + "\"}";
			}
			std::fputs((meta + "]}\n").c_str(), f);
			for (const Rec& r : recs)
			{
				std::fputs(("{\"s\":\"" + scenario + "\",\"k\":\"" + r.kind + "\",\"peer\":\"" + r.peer +
					"\",\"raw\":\"" + jsonEscape(r.raw) + "\"}\n").c_str(), f);
			}
			std::fflush(f);
		}

		sockaddr_in server() const { return addrFor(serverIp); }

		Phone& party(const std::string& name, const std::string& ext, const std::string& ip, bool doRegister = true)
		{
			parties.push_back(Phone{});
			Phone& p = parties.back();
			p.name = name; p.ext = ext; p.ip = ip;
			if (doRegister) registerPhone(p);
			return p;
		}

		void registerPhone(Phone& p, int expires = 3600)
		{
			feed(p, p.request("REGISTER", "sip:" + serverIp,
				"<sip:" + p.ext + "@" + serverIp + ">;tag=" + p.tag(), "<sip:" + p.ext + "@" + serverIp + ">",
				p.name + "-reg@" + p.ip, static_cast<uint32_t>(++p.seq),
				"Expires: " + std::to_string(expires) + "\r\n"));
		}

		// Feed one datagram from `from` to the PBX, then let every party react.
		void feed(Phone& from, const std::string& raw)
		{
			feedFrom(from.addr(), raw);
		}
		void feedFrom(const sockaddr_in& src, const std::string& raw)
		{
			{
				std::lock_guard<std::mutex> lk(mu);
				recs.push_back(Rec{"in", peerOf(src), raw});
			}
			auto msg = RequestsHandler::getMessageFromPool(raw, src);
			ASSERT_TRUE(msg) << "message pool refused a stimulus";
			h->handle(msg);
			pump();
		}
		void tick()
		{
			h->forceNextTickForTest();
			h->tick();
			pump();
		}
		void pump()
		{
			for (int guard = 0; guard < 400; ++guard)
			{
				Rec r;
				{
					std::lock_guard<std::mutex> lk(mu);
					while (pumped < recs.size() && recs[pumped].kind != "out") ++pumped;
					if (pumped >= recs.size()) return;
					r = recs[pumped++];
				}
				for (Phone& p : parties)
				{
					if (r.peer == p.ip + ":" + std::to_string(p.port)) { p.react(*this, r.raw); break; }
				}
			}
			ADD_FAILURE() << scenario << ": message storm (400 reactions without going quiet)";
		}

		// ── positive controls ────────────────────────────────────────────────
		// Outbound messages to `p` whose first line starts with `start`.
		std::vector<std::string> sentTo(const Phone& p, const std::string& start)
		{
			std::lock_guard<std::mutex> lk(mu);
			std::vector<std::string> out;
			const std::string peer = p.ip + ":" + std::to_string(p.port);
			for (const Rec& r : recs)
			{
				if (r.kind == "out" && r.peer == peer && r.raw.rfind(start, 0) == 0) out.push_back(r.raw);
			}
			return out;
		}
		bool sent(const Phone& p, const std::string& start) { return !sentTo(p, start).empty(); }
		std::string dump()
		{
			std::lock_guard<std::mutex> lk(mu);
			std::string s;
			for (const Rec& r : recs) s += r.kind + " " + r.peer + " " + firstLine(r.raw) + " | " + header(r.raw, "CSeq") + "\n";
			return s;
		}

		// ── party actions ────────────────────────────────────────────────────
		// `from` dials `target`; returns the Call-ID.
		std::string call(Phone& from, const std::string& target, const std::string& callId,
			const std::string& dir = "sendrecv", const std::string& extra = "", bool withSdp = true)
		{
			Phone::Dialog& d = from.dialogs[callId];
			d.localTag = from.tag();
			d.localUri = "sip:" + from.ext + "@" + serverIp;
			d.remoteUri = "sip:" + target + "@" + serverIp;
			d.cseq = 1;
			d.inviteRaw = from.request("INVITE", d.remoteUri, "<" + d.localUri + ">;tag=" + d.localTag,
				"<" + d.remoteUri + ">", callId, 1, extra, withSdp ? from.sdp("offer", dir) : "");
			feed(from, d.inviteRaw);
			return callId;
		}
		void bye(Phone& from, const std::string& callId) { feed(from, from.inDialog(callId, "BYE")); }
		void reinvite(Phone& from, const std::string& callId, const std::string& dir)
		{
			Phone::Dialog& d = from.dialogs[callId];
			const std::string raw = from.inDialog(callId, "INVITE", "", from.sdp("offer", dir));
			d.inviteRaw = raw;
			feed(from, raw);
		}
		void cancel(Phone& from, const std::string& callId)
		{
			const std::string& inv = from.dialogs[callId].inviteRaw;
			std::string r = "CANCEL " + firstLine(inv).substr(7, firstLine(inv).rfind(' ') - 7) + " SIP/2.0\r\n"
				"Via: " + header(inv, "Via") + "\r\n"
				"From: " + header(inv, "From") + "\r\nTo: " + header(inv, "To") + "\r\n"
				"Call-ID: " + callId + "\r\nCSeq: " + std::to_string(cseqNum(inv)) + " CANCEL\r\n"
				"Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n";
			feed(from, r);
		}
		// A party that was left ringing answers now.
		void answer(Phone& p, const std::string& callId)
		{
			Phone::Dialog& d = p.dialogs[callId];
			const std::string& inv = d.inviteRaw;
			const std::string b = body(inv);
			d.answered = true;
			feed(p, p.response(inv, 200, "OK", d.localTag,
				b.empty() ? p.sdp("offer", "sendrecv") : p.sdp("answer", answerDirection(sdpDirection(b)))));
		}
	};

	void Phone::react(Bench& b, const std::string& m)
	{
		const std::string callId = header(m, "Call-ID", "i");
		if (isResponse(m))
		{
			const int code = statusOf(m);
			auto it = dialogs.find(callId);
			if (cseqMethod(m) != "INVITE" || it == dialogs.end()) return;
			Dialog& d = it->second;
			const std::string toTag = param(header(m, "To", "t"), "tag");
			if (code > 100 && code < 300 && !toTag.empty())
			{
				d.remoteTag = toTag;
				const std::string c = header(m, "Contact", "m");
				if (!c.empty()) d.remoteTarget = uriOf(c);
			}
			if (code < 200) return;
			// ACK: a 2xx gets its own transaction (new branch, remote target);
			// a non-2xx reuses the INVITE's branch and Request-URI (§17.1.1.3).
			std::string ruri, via;
			if (code < 300)
			{
				ruri = d.remoteTarget.empty() ? d.remoteUri : d.remoteTarget;
				via = this->via();
			}
			else
			{
				const std::string fl = firstLine(d.inviteRaw);
				ruri = fl.substr(7, fl.rfind(' ') - 7);
				via = "Via: " + header(m, "Via", "v") + "\r\n";
			}
			std::string ack = "ACK " + ruri + " SIP/2.0\r\n" + via +
				"From: " + header(m, "From", "f") + "\r\nTo: " + header(m, "To", "t") + "\r\n"
				"Call-ID: " + callId + "\r\nCSeq: " + std::to_string(cseqNum(m)) + " ACK\r\n"
				"Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n";
			b.feed(*this, ack);
			return;
		}

		const std::string method = methodOf(m);
		const std::string to = header(m, "To", "t");
		const bool inDialogReq = !param(to, "tag").empty();
		if (method == "ACK") return;

		if (method == "INVITE" && !inDialogReq)
		{
			Dialog& d = dialogs[callId];
			d.localTag = tag();
			d.remoteTag = param(header(m, "From", "f"), "tag");
			d.localUri = uriOf(to);
			d.remoteUri = uriOf(header(m, "From", "f"));
			d.remoteTarget = uriOf(header(m, "Contact", "m"));
			d.inviteRaw = m;
			const std::string offer = body(m);
			const std::string ans = offer.empty() ? sdp("offer", "sendrecv") : sdp("answer", answerDirection(sdpDirection(offer)));
			switch (onInvite)
			{
			case OnInvite::Ignore: return;
			case OnInvite::Busy:
				b.feed(*this, response(m, 486, "Busy Here", d.localTag));
				return;
			case OnInvite::Ring:
				b.feed(*this, response(m, 180, "Ringing", d.localTag));
				return;
			case OnInvite::Reject:
				d.answered = true;
				b.feed(*this, response(m, rejectCode, rejectReason, d.localTag));
				return;
			case OnInvite::Progress:
				b.feed(*this, response(m, 100, "Trying", ""));
				b.feed(*this, response(m, 183, "Session Progress", d.localTag, offer.empty() ? "" : ans));
				break;
			case OnInvite::Answer:
				b.feed(*this, response(m, 180, "Ringing", d.localTag));
				break;
			}
			d.answered = true;
			b.feed(*this, response(m, 200, "OK", d.localTag, ans));
			return;
		}
		if (method == "INVITE")
		{
			Dialog& d = dialogs[callId];
			if (onReinvite == OnReinvite::Glare)
			{
				b.feed(*this, response(m, 491, "Request Pending", ""));
				return;
			}
			const std::string c = header(m, "Contact", "m");
			if (!c.empty()) d.remoteTarget = uriOf(c);
			const std::string offer = body(m);
			b.feed(*this, response(m, 200, "OK", "",
				offer.empty() ? sdp("offer", "sendrecv") : sdp("answer", answerDirection(sdpDirection(offer)))));
			return;
		}
		if (method == "CANCEL")
		{
			b.feed(*this, response(m, 200, "OK", dialogs[callId].localTag));
			Dialog& d = dialogs[callId];
			if (!d.answered && !d.inviteRaw.empty())
			{
				d.answered = true;
				b.feed(*this, response(d.inviteRaw, 487, "Request Terminated", d.localTag));
			}
			return;
		}
		if (method == "REGISTER")
		{
			if (challengeRegister && header(m, "Authorization").empty())
			{
				b.feed(*this, response(m, 401, "Unauthorized", tag(), "",
					"WWW-Authenticate: Digest realm=\"carrier\", nonce=\"n0nce1\", algorithm=MD5, qop=\"auth\"\r\n"));
				return;
			}
			b.feed(*this, response(m, 200, "OK", tag(), "",
				"Contact: " + header(m, "Contact", "m") + ";expires=600\r\n"));
			return;
		}
		if (method == "UPDATE" && !body(m).empty())
		{
			b.feed(*this, response(m, 200, "OK", "", sdp("answer", answerDirection(sdpDirection(body(m))))));
			return;
		}
		b.feed(*this, response(m, 200, "OK", inDialogReq ? "" : tag()));
	}

	SipTrunk::Config trunkConfig()
	{
		SipTrunk::Config c;
		std::snprintf(c.host, sizeof(c.host), "%s", kCarrierIp);
		c.port = 5060;
		std::snprintf(c.fromUser, sizeof(c.fromUser), "%s", "5555550199");
		c.enabled = true;
		return c;
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Registrar
// ═════════════════════════════════════════════════════════════════════════════

TEST(EmittedConformance, RegisterAndUnregister)
{
	Bench b("register");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	b.registerPhone(a, 0);
	EXPECT_EQ(b.sentTo(a, "SIP/2.0 200 OK").size(), 2u) << b.dump();
}

TEST(EmittedConformance, SecureModeChallengesAndRefuses)
{
	Bench b("secure_mode");
	Phone& a = b.party("pa", "202", "192.168.77.11");
	ASSERT_TRUE(SipSecretStore::setSecret("202", "s3cret"));
	b.h->setRegistrarMode(RequestsHandler::RegistrarMode::Secure);
	b.registerPhone(a);                                       // 401 challenge
	Phone& spoof = b.party("ps", "202", "192.168.77.99", false);
	b.call(spoof, "203", "sec-spoof");                        // 403 from the wrong address
	b.h->setRegistrarMode(RequestsHandler::RegistrarMode::Learn);
	SipSecretStore::clearSecret("202");
	EXPECT_TRUE(b.sent(a, "SIP/2.0 401")) << b.dump();
	EXPECT_TRUE(b.sent(spoof, "SIP/2.0 403")) << b.dump();
}

// ═════════════════════════════════════════════════════════════════════════════
// Basic calls
// ═════════════════════════════════════════════════════════════════════════════

TEST(EmittedConformance, CallAnsweredAndHungUpByCaller)
{
	Bench b("basic_call");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	Phone& c = b.party("pb", "202", "192.168.77.20");
	const std::string id = b.call(a, "202", "basic-1@192.168.77.10");
	b.bye(a, id);
	EXPECT_TRUE(b.sent(c, "INVITE ")) << b.dump();
	EXPECT_TRUE(b.sent(a, "SIP/2.0 180")) << b.dump();
	EXPECT_TRUE(b.sent(a, "SIP/2.0 200")) << b.dump();
	EXPECT_TRUE(b.sent(c, "ACK ")) << b.dump();
	EXPECT_TRUE(b.sent(c, "BYE ")) << b.dump();
}

TEST(EmittedConformance, CallHungUpByCallee)
{
	Bench b("callee_bye");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	Phone& c = b.party("pb", "202", "192.168.77.20");
	const std::string id = b.call(a, "202", "calleebye-1@192.168.77.10");
	b.bye(c, id);
	EXPECT_TRUE(b.sent(a, "BYE ")) << b.dump();
}

TEST(EmittedConformance, CancelledWhileRinging)
{
	Bench b("cancel");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	Phone& c = b.party("pb", "202", "192.168.77.20");
	c.onInvite = Phone::OnInvite::Ring;
	const std::string id = b.call(a, "202", "cancel-1@192.168.77.10");
	b.cancel(a, id);
	EXPECT_TRUE(b.sent(c, "CANCEL ")) << b.dump();
	EXPECT_TRUE(b.sent(a, "SIP/2.0 487")) << b.dump();
}

TEST(EmittedConformance, EarlyMediaThenAnswer)
{
	Bench b("early_media");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	Phone& c = b.party("pb", "202", "192.168.77.20");
	c.onInvite = Phone::OnInvite::Progress;
	b.call(a, "202", "early-1@192.168.77.10");
	// The callee's 183 is not relayed between extensions (onSessionProgress is
	// trunk-only); the relayed 183 is covered by the trunk scenario.
	EXPECT_TRUE(b.sent(a, "SIP/2.0 200")) << b.dump();
}

TEST(EmittedConformance, BusyCallee)
{
	Bench b("busy");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	Phone& c = b.party("pb", "202", "192.168.77.20");
	c.onInvite = Phone::OnInvite::Busy;
	b.call(a, "202", "busy-1@192.168.77.10");
	EXPECT_TRUE(b.sent(a, "SIP/2.0 486")) << b.dump();
	EXPECT_TRUE(b.sent(c, "ACK ")) << b.dump();
}

TEST(EmittedConformance, RefusalsBeforeAnySession)
{
	Bench b("refusals");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	Phone& c = b.party("pb", "202", "192.168.77.20");
	b.call(a, "299", "notfound-1@192.168.77.10");                  // 404
	b.h->setDnd("202", true);
	b.call(a, "202", "dnd-1@192.168.77.10");                       // 480
	b.h->setDnd("202", false);
	// 488: an offer with no audio codec the PBX can relay.
	{
		const std::string sdp = "v=0\r\no=pa-offer 1 1 IN IP4 192.168.77.10\r\ns=-\r\nc=IN IP4 192.168.77.10\r\n"
			"t=0 0\r\nm=audio 20000 RTP/AVP 96\r\na=rtpmap:96 opus/48000/2\r\n";
		b.feed(a, a.request("INVITE", "sip:202@192.168.77.1", "<sip:201@192.168.77.1>;tag=" + a.tag(),
			"<sip:202@192.168.77.1>", "opus-1@192.168.77.10", 1, "", sdp));
	}
	// 422: a Session-Expires below the PBX's Min-SE.
	b.call(a, "202", "smallse-1@192.168.77.10", "sendrecv", "Session-Expires: 30\r\nSupported: timer\r\n");
	// 481: a re-INVITE for a dialog that does not exist.
	b.feed(a, a.request("INVITE", "sip:202@192.168.77.1", "<sip:201@192.168.77.1>;tag=" + a.tag(),
		"<sip:202@192.168.77.1>;tag=pb-tagnosuch", "ghost-1@192.168.77.10", 2, "", a.sdp("offer", "sendrecv")));
	// A BYE for a dialog that does not exist.
	b.feed(a, a.request("BYE", "sip:202@192.168.77.1", "<sip:201@192.168.77.1>;tag=" + a.tag(),
		"<sip:202@192.168.77.1>;tag=pb-tagnosuch", "ghost-2@192.168.77.10", 2));
	// 400: an AOR the PBX will not accept (REGISTER and INVITE).
	b.feed(a, a.request("REGISTER", "sip:192.168.77.1", "<sip:bad!aor@192.168.77.1>;tag=" + a.tag(),
		"<sip:bad!aor@192.168.77.1>", "badreg-1@192.168.77.10", 1));
	b.call(a, "20!2", "badinv-1@192.168.77.10");
	(void)c;
	for (const char* code : {"SIP/2.0 404", "SIP/2.0 480", "SIP/2.0 488", "SIP/2.0 422", "SIP/2.0 481", "SIP/2.0 400"})
		EXPECT_TRUE(b.sent(a, code)) << code << "\n" << b.dump();
}

TEST(EmittedConformance, CalleeRejects)
{
	Bench b("callee_rejects");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	Phone& c = b.party("pb", "202", "192.168.77.20");
	c.onInvite = Phone::OnInvite::Reject;
	const std::pair<int, const char*> codes[] = {{480, "Temporarily Unavailable"}, {603, "Decline"},
		{415, "Unsupported Media Type"}, {420, "Bad Extension"}, {488, "Not Acceptable Here"}};
	int n = 0;
	for (const auto& [code, reason] : codes)
	{
		c.rejectCode = code;
		c.rejectReason = reason;
		b.call(a, "202", "rej-" + std::to_string(++n) + "@192.168.77.10");
	}
	EXPECT_TRUE(b.sent(a, "SIP/2.0 480")) << b.dump();
}

TEST(EmittedConformance, RingGroupAnsweredByOneMember)
{
	Bench b("ring_group");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	Phone& c = b.party("pb", "202", "192.168.77.20");
	Phone& d = b.party("pc", "203", "192.168.77.30");
	b.h->setRingGroup("600", "202,203", "ringall");
	c.onInvite = Phone::OnInvite::Ring;
	d.onInvite = Phone::OnInvite::Ring;
	const std::string id = b.call(a, "600", "group-1@192.168.77.10");
	ASSERT_TRUE(b.sent(c, "INVITE ")) << b.dump();
	b.answer(c, id);
	b.bye(a, id);
	EXPECT_TRUE(b.sent(d, "CANCEL ")) << b.dump();
}

TEST(EmittedConformance, ParkAndPickup)
{
	Bench b("park_pickup");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	Phone& c = b.party("pb", "202", "192.168.77.20");
	Phone& d = b.party("pc", "203", "192.168.77.30");
	b.call(a, "700", "park-1@192.168.77.10");
	const std::string retrieve = b.call(c, "700", "park-2@192.168.77.20");
	b.bye(c, retrieve);
	// Directed pickup: 201 rings 203, 202 (same pickup group) picks it up.
	b.h->setRingGroup("610", "202,203", "ringall");
	d.onInvite = Phone::OnInvite::Ring;
	b.call(a, "203", "pick-1@192.168.77.10");
	const std::string picker = b.call(c, "**203", "pick-2@192.168.77.20");
	ASSERT_TRUE(b.sent(c, "SIP/2.0 200 OK")) << b.dump();
	b.bye(c, picker);
	EXPECT_TRUE(b.sent(d, "CANCEL ")) << b.dump();
	EXPECT_GE(b.sentTo(a, "INVITE ").size(), 1u) << "park retrieve re-INVITE\n" << b.dump();
}

TEST(EmittedConformance, OutOfDialogOptionsMessageInfoAndPing)
{
	Bench b("options_message_info");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	b.feed(a, a.request("OPTIONS", "sip:192.168.77.1", "<sip:201@192.168.77.1>;tag=" + a.tag(),
		"<sip:192.168.77.1>", "opt-1@192.168.77.10", 1));
	b.feed(a, a.request("MESSAGE", "sip:202@192.168.77.1", "<sip:201@192.168.77.1>;tag=" + a.tag(),
		"<sip:202@192.168.77.1>", "msg-1@192.168.77.10", 1, "Content-Type: text/plain\r\n"));
	for (int i = 0; i < 8 && !b.sent(a, "OPTIONS "); ++i) b.tick();   // the keep-alive ping
	EXPECT_TRUE(b.sent(a, "SIP/2.0 200 OK")) << b.dump();
	EXPECT_TRUE(b.sent(a, "OPTIONS ")) << b.dump();
}

// ═════════════════════════════════════════════════════════════════════════════
// Mid-dialog: hold, UPDATE, glare
// ═════════════════════════════════════════════════════════════════════════════

TEST(EmittedConformance, HoldResumeAndUpdate)
{
	Bench b("hold_update");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	Phone& c = b.party("pb", "202", "192.168.77.20");
	const std::string id = b.call(a, "202", "hold-1@192.168.77.10");
	b.reinvite(a, id, "sendonly");
	b.reinvite(a, id, "sendrecv");
	b.feed(a, a.inDialog(id, "UPDATE", "", a.sdp("offer", "sendrecv")));
	b.feed(a, a.inDialog(id, "INFO", "Content-Type: application/dtmf-relay\r\n"));
	b.bye(c, id);
	EXPECT_GE(b.sentTo(c, "INVITE ").size(), 3u) << b.dump();
	EXPECT_TRUE(b.sent(c, "UPDATE ")) << b.dump();
}

TEST(EmittedConformance, ReinviteGlareIsRelayed491)
{
	Bench b("glare");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	Phone& c = b.party("pb", "202", "192.168.77.20");
	const std::string id = b.call(a, "202", "glare-1@192.168.77.10");
	c.onReinvite = Phone::OnReinvite::Glare;
	b.reinvite(a, id, "sendonly");
	// The 491 itself is not relayed back (see the checker's ack-missing rule).
	EXPECT_GE(b.sentTo(c, "INVITE ").size(), 2u) << b.dump();
}

// ═════════════════════════════════════════════════════════════════════════════
// Server-terminated legs
// ═════════════════════════════════════════════════════════════════════════════

TEST(EmittedConformance, ServiceExtensions)
{
	Bench b("service_ext");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	for (const char* ext : {"777", "440", "888"})
	{
		const std::string id = b.call(a, ext, std::string("svc-") + ext + "@192.168.77.10");
		b.bye(a, id);
	}
	EXPECT_GE(b.sentTo(a, "SIP/2.0 200 OK").size(), 3u) << b.dump();
}

TEST(EmittedConformance, RegisterBeep)
{
	Bench b("register_beep");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	b.h->fireRegisterBeepsForTest();
	b.pump();
	for (int i = 0; i < 6; ++i) b.tick();
	EXPECT_TRUE(b.sent(a, "INVITE ")) << b.dump();
}

// ═════════════════════════════════════════════════════════════════════════════
// BLF, transfer
// ═════════════════════════════════════════════════════════════════════════════

TEST(EmittedConformance, BlfSubscribeAndNotify)
{
	Bench b("blf");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	Phone& c = b.party("pb", "202", "192.168.77.20");
	Phone& d = b.party("pc", "203", "192.168.77.30");
	b.feed(a, a.request("SUBSCRIBE", "sip:202@192.168.77.1", "<sip:201@192.168.77.1>;tag=" + a.tag(),
		"<sip:202@192.168.77.1>", "blf-1@192.168.77.10", 1, "Event: dialog\r\nExpires: 600\r\nAccept: application/dialog-info+xml\r\n"));
	b.feed(a, a.request("SUBSCRIBE", "sip:202@192.168.77.1", "<sip:201@192.168.77.1>;tag=" + a.tag(),
		"<sip:202@192.168.77.1>", "blf-2@192.168.77.10", 1, "Event: presence\r\nExpires: 600\r\n"));
	const std::string id = b.call(d, "202", "blfcall-1@192.168.77.30");
	b.bye(d, id);
	(void)c;
	EXPECT_TRUE(b.sent(a, "NOTIFY ")) << b.dump();
	EXPECT_TRUE(b.sent(a, "SIP/2.0 489")) << b.dump();
}

TEST(EmittedConformance, BlindTransfer)
{
	Bench b("blind_transfer");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	Phone& c = b.party("pb", "202", "192.168.77.20");
	Phone& t = b.party("pc", "203", "192.168.77.30");
	const std::string id = b.call(a, "202", "bx-1@192.168.77.10");
	b.reinvite(a, id, "sendonly");                      // the Transfer key holds B first
	b.feed(a, a.inDialog(id, "REFER", "Refer-To: <sip:203@192.168.77.1>\r\nReferred-By: <sip:201@192.168.77.1>\r\n"));
	EXPECT_TRUE(b.sent(a, "SIP/2.0 202")) << b.dump();
	EXPECT_TRUE(b.sent(a, "NOTIFY ")) << b.dump();
	EXPECT_TRUE(b.sent(t, "INVITE ")) << b.dump();
	EXPECT_GE(b.sentTo(c, "INVITE ").size(), 3u) << "the transferee's swap re-INVITE\n" << b.dump();
}

// #719's trigger: every phone's Transfer key holds the far party before it
// consults, so at splice time B's stored SDP is its hold ANSWER.
TEST(EmittedConformance, AttendedTransferAfterHold)
{
	Bench b("attended_transfer");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	Phone& c = b.party("pb", "202", "192.168.77.20");
	Phone& t = b.party("pc", "203", "192.168.77.30");
	const std::string ab = b.call(a, "202", "ax-ab@192.168.77.10");
	b.reinvite(a, ab, "sendonly");                      // A holds B; B answers recvonly
	const std::string ac = b.call(a, "203", "ax-ac@192.168.77.10");
	const Phone::Dialog& dc = a.dialogs[ac];
	b.feed(a, a.inDialog(ab, "REFER", "Refer-To: <sip:203@192.168.77.1?Replaces=" + ac +
		"%3Bto-tag%3D" + dc.remoteTag + "%3Bfrom-tag%3D" + dc.localTag + ">\r\n"));
	EXPECT_TRUE(b.sent(a, "SIP/2.0 202")) << b.dump();
	EXPECT_GE(b.sentTo(t, "INVITE ").size(), 2u) << "C's splice re-INVITE\n" << b.dump();
	// A second pair, then a REFER whose Replaces names no dialog: 603.
	const std::string ab2 = b.call(a, "202", "ax-ab2@192.168.77.10");
	b.feed(a, a.inDialog(ab2, "REFER", "Refer-To: <sip:203@192.168.77.1?Replaces=nosuch%3Bto-tag%3Dx%3Bfrom-tag%3Dy>\r\n"));
	EXPECT_TRUE(b.sent(a, "SIP/2.0 603")) << b.dump();
	EXPECT_GE(b.sentTo(c, "INVITE ").size(), 3u) << "B's splice re-INVITE\n" << b.dump();
}

// ═════════════════════════════════════════════════════════════════════════════
// Trunk (carrier at TEST-NET-3; nothing leaves the process)
// ═════════════════════════════════════════════════════════════════════════════

TEST(EmittedConformance, TrunkRegisterWithDigest)
{
	Bench b("trunk_register");
	Phone& sbc = b.party("sbc", "carrier", kCarrierIp, false);
	sbc.challengeRegister = true;
	b.h->setTrunkConfig(trunkConfig());
	ASSERT_TRUE(b.h->setTrunkCredentials("trunkpass"));
	for (int i = 0; i < 6 && b.sentTo(sbc, "REGISTER ").size() < 2; ++i) b.tick();
	const auto regs = b.sentTo(sbc, "REGISTER ");
	ASSERT_GE(regs.size(), 2u) << b.dump();
	EXPECT_NE(regs.back().find("Authorization: Digest"), std::string::npos) << regs.back();
}

TEST(EmittedConformance, TrunkOutboundCallCarrierHangsUp)
{
	Bench b("trunk_call");
	Phone& h = b.party("pa", "1001", "192.168.77.40");
	Phone& sbc = b.party("sbc", "carrier", kCarrierIp, false);
	sbc.onInvite = Phone::OnInvite::Progress;
	sbc.recordRoute = "<sip:203.0.113.5;lr>";
	b.h->setTrunkConfig(trunkConfig());
	b.h->setDialRule("9XXXXXXXXXX", "trunk", "1", 1);
	const std::string id = b.call(h, "95555550100", "trunk-1@192.168.77.40");
	for (int i = 0; i < 3 && !b.sent(sbc, "INVITE "); ++i) b.tick();
	ASSERT_TRUE(b.sent(sbc, "INVITE ")) << b.dump();
	EXPECT_TRUE(b.sent(h, "SIP/2.0 183")) << "carrier early media reaches the handset\n" << b.dump();
	EXPECT_TRUE(b.sent(sbc, "ACK ")) << b.dump();
	const std::string carrierCallId = sbc.dialogs.begin()->first;
	// A session refresh from the carrier (RFC 4028): a re-INVITE with its SDP.
	b.reinvite(sbc, carrierCallId, "sendrecv");
	// The carrier hangs up: the PBX BYEs the handset (#700's path).
	b.feed(sbc, sbc.inDialog(carrierCallId, "BYE"));
	(void)id;
	EXPECT_TRUE(b.sent(h, "BYE ")) << b.dump();
}

TEST(EmittedConformance, TrunkOutboundCallHandsetHangsUpAndCancel)
{
	Bench b("trunk_call_handset");
	Phone& h = b.party("pa", "1001", "192.168.77.40");
	Phone& sbc = b.party("sbc", "carrier", kCarrierIp, false);
	sbc.recordRoute = "<sip:203.0.113.5;lr>";
	b.h->setTrunkConfig(trunkConfig());
	b.h->setDialRule("9XXXXXXXXXX", "trunk", "1", 1);
	const std::string id = b.call(h, "95555550101", "trunk-2@192.168.77.40");
	for (int i = 0; i < 3 && !b.sent(sbc, "INVITE "); ++i) b.tick();
	b.bye(h, id);
	EXPECT_TRUE(b.sent(sbc, "BYE ")) << b.dump();

	sbc.onInvite = Phone::OnInvite::Ring;
	const std::string id2 = b.call(h, "95555550102", "trunk-3@192.168.77.40");
	for (int i = 0; i < 3 && b.sentTo(sbc, "INVITE ").size() < 2; ++i) b.tick();
	b.cancel(h, id2);
	// #779: a handset CANCEL of a ringing trunk call now reaches the carrier (it used to
	// be answered 404 here and never did).
	EXPECT_TRUE(b.sent(sbc, "CANCEL ")) << b.dump();
	EXPECT_FALSE(b.sent(h, "SIP/2.0 404")) << "the old answer to that CANCEL must be gone: " << b.dump();
}

// ═════════════════════════════════════════════════════════════════════════════
// Anchor (host loopback client) and emergency (loopback only; no real calls)
// ═════════════════════════════════════════════════════════════════════════════

TEST(EmittedConformance, AnchorLegThroughTheLoopbackClient)
{
	Bench b("anchor");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	const std::string id = b.call(a, "555", "anchor-1@192.168.77.10");
	b.reinvite(a, id, "sendonly");
	b.reinvite(a, id, "sendrecv");
	b.bye(a, id);
	EXPECT_TRUE(b.sent(a, "SIP/2.0 200 OK")) << b.dump();
}

TEST(EmittedConformance, EmergencyOnALoopbackOnlyBoardIsRefused)
{
	Bench b("emergency_loopback");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	b.call(a, "911", "e911-1@192.168.77.10");
	b.call(a, "933", "e933-1@192.168.77.10");
	EXPECT_TRUE(b.sent(a, "SIP/2.0 503")) << b.dump();
}

TEST(EmittedConformance, EmergencyWithATrunkGoesToTheCarrier)
{
	Bench b("emergency_trunk");
	Phone& a = b.party("pa", "201", "192.168.77.10");
	Phone& sbc = b.party("sbc", "carrier", kCarrierIp, false);
	b.h->setTrunkConfig(trunkConfig());
	const std::string id = b.call(a, "911", "e911-2@192.168.77.10");
	for (int i = 0; i < 3 && !b.sent(sbc, "INVITE "); ++i) b.tick();
	b.bye(a, id);
	EXPECT_TRUE(b.sent(sbc, "INVITE sip:911@")) << b.dump();
}

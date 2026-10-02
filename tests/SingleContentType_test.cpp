// SingleContentType_test.cpp -- #845: an SDP answer the PBX builds from a copy
// of the caller's INVITE carries exactly one Content-Type, application/sdp
// (RFC 3261 §7.3.1, §20.15).
//
// buildOkWithSdp(), the 440 answer and answerAnchorReinvite() copy the INVITE's
// header lines and replace its body with the PBX's own SDP. When the INVITE's
// Content-Type was not SDP they added a second line, so a 911 sent with
// Content-Type: text/plain was answered with text/plain AND application/sdp.
// The trunk's 183 and 200 to the handset (onTrunkRinging, onTrunkAnswered)
// copy the INVITE the same way and kept its Content-Type line, whatever it was.
//
// Reachability. The header gate answers 415 to an INVITE whose body is not
// labelled SDP, unless it yields for emergency traffic: a To of 911, a
// Priority: psap-callback, or a request on a live 911 dialog. And hasSdp()
// reads "application/sdp" anywhere in the datagram, so these INVITEs carry the
// Accept: application/sdp line phones send; without it a text/plain 911 is
// refused 400 before any answer is built.

#include <gtest/gtest.h>

#include <cctype>
#include <cstdio>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "RequestsHandler.hpp"
#include "SipMessage.hpp"
#include "SipMessageFactory.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	constexpr const char* kServerIp  = "192.168.84.1";
	constexpr const char* kCallerIp  = "192.168.84.50";   // ext 500
	constexpr const char* kSbcIp     = "203.0.113.5";     // RFC 5737 TEST-NET-3

	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(5060);
		return a;
	}

	std::shared_ptr<SipMessage> fromWire(const std::string& raw, const std::string& ip)
	{
		SipMessageFactory factory;
		auto m = factory.createMessage(raw, addrFor(ip));
		return m ? *m : nullptr;
	}

	std::string headerValue(const std::string& raw, const std::string& name)
	{
		size_t pos = raw.find("\r\n");
		while (pos != std::string::npos)
		{
			pos += 2;
			const size_t eol = raw.find("\r\n", pos);
			if (eol == std::string::npos || eol == pos) break;
			if (raw.compare(pos, name.size() + 1, name + ":") == 0)
			{
				size_t v = pos + name.size() + 1;
				while (v < eol && raw[v] == ' ') ++v;
				return raw.substr(v, eol - v);
			}
			pos = eol;
		}
		return {};
	}

	// Every Content-Type line of a message, full or compact (c:) form, any case.
	std::vector<std::string> contentTypeLines(const std::string& raw)
	{
		std::vector<std::string> lines;
		size_t pos = raw.find("\r\n");
		while (pos != std::string::npos)
		{
			pos += 2;
			const size_t eol = raw.find("\r\n", pos);
			if (eol == std::string::npos || eol == pos) break;
			const std::string line = raw.substr(pos, eol - pos);
			std::string name = line.substr(0, line.find(':'));
			while (!name.empty() && (name.back() == ' ' || name.back() == '\t')) name.pop_back();
			for (char& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
			if (name == "content-type" || name == "c") lines.push_back(line);
			pos = eol;
		}
		return lines;
	}

	std::string bodyOf(const std::string& raw)
	{
		const size_t sep = raw.find("\r\n\r\n");
		return sep == std::string::npos ? std::string() : raw.substr(sep + 4);
	}

	std::string offerFrom(const std::string& ip)
	{
		return
			"v=0\r\n"
			"o=- 1 1 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio 40000 RTP/AVP 0 101\r\n"
			"a=rtpmap:0 PCMU/8000\r\n"
			"a=rtpmap:101 telephone-event/8000\r\n"
			"a=sendrecv\r\n";
	}

	// An INVITE from 500 with an SDP offer. `typeLines` are its Content-Type
	// lines, CRLF-terminated ("" for none); `toLine` and `cseq` make it a
	// re-INVITE; `extra` is any further header lines.
	std::string invite(const std::string& to, const std::string& callId, const std::string& typeLines,
		const std::string& extra = "", const std::string& toLine = "", int cseq = 1)
	{
		const std::string offer = offerFrom(kCallerIp);
		return
			"INVITE sip:" + to + "@" + std::string(kServerIp) + " SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kCallerIp) + ":5060;branch=z9hG4bK" + callId + std::to_string(cseq) + "\r\n"
			"From: <sip:500@server>;tag=f" + callId + "\r\n" +
			(toLine.empty() ? "To: <sip:" + to + "@server>" : toLine) + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:500@" + std::string(kCallerIp) + ":5060>\r\n"
			"Accept: application/sdp\r\n" + extra + typeLines +
			"Content-Length: " + std::to_string(offer.size()) + "\r\n\r\n" + offer;
	}

	// The carrier's `status` to the INVITE the PBX sent it, with its own SDP.
	std::string carrierResponse(const std::string& carrierInvite, const std::string& status)
	{
		const std::string sdp =
			"v=0\r\no=- 0 0 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\n"
			"t=0 0\r\nm=audio 41000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n"
			"a=rtpmap:101 telephone-event/8000\r\n";
		return status + "\r\n"
			"Via: " + headerValue(carrierInvite, "Via") + "\r\n"
			"From: " + headerValue(carrierInvite, "From") + "\r\n"
			"To: " + headerValue(carrierInvite, "To") + ";tag=carrier845\r\n"
			"Call-ID: " + headerValue(carrierInvite, "Call-ID") + "\r\n"
			"CSeq: " + headerValue(carrierInvite, "CSeq") + "\r\n"
			"Contact: <sip:psap@203.0.113.9:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(sdp.size()) + "\r\n\r\n" + sdp;
	}

	// Ext 500 registered. By default a real-call anchor and no trunk, so a 911
	// is answered over the anchor; with `trunk`, a carrier and no real anchor.
	struct Rig
	{
		std::vector<std::pair<sockaddr_in, std::string>> sent;
		RequestsHandler handler;

		explicit Rig(bool trunk = false) : handler(kServerIp, 5060,
			[this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, m ? m->toString() : std::string()); })
		{
			if (trunk)
			{
				SipTrunk::Config c;
				std::snprintf(c.host, sizeof(c.host), "%s", kSbcIp);
				c.port = 5060;
				std::snprintf(c.fromUser, sizeof(c.fromUser), "%s", "15551230000");
				c.enabled = true;
				handler.setTrunkConfig(c);
			}
			else
			{
				handler.setAnchorPlacesRealCallsForTest(true);
			}
			send(
				"REGISTER sip:server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP " + std::string(kCallerIp) + ":5060;branch=z9hG4bKct845reg\r\n"
				"From: <sip:500@server>;tag=ct845reg\r\n"
				"To: <sip:500@server>\r\n"
				"Call-ID: ct845-reg\r\n"
				"CSeq: 1 REGISTER\r\n"
				"Contact: <sip:500@" + std::string(kCallerIp) + ":5060>;expires=3600\r\n"
				"Content-Length: 0\r\n\r\n", kCallerIp);
			sent.clear();
		}

		void send(const std::string& raw, const char* ip) { handler.handle(fromWire(raw, ip)); }

		// The first message sent to `ip` whose first line contains `needle`.
		std::string first(const std::string& needle, const char* ip) const
		{
			for (const auto& [addr, raw] : sent)
			{
				if (addr.sin_addr.s_addr != inet_addr(ip)) continue;
				if (raw.substr(0, raw.find("\r\n")).find(needle) != std::string::npos) return raw;
			}
			return {};
		}

		std::string dump() const
		{
			std::string out;
			for (const auto& p : sent) out += p.second.substr(0, p.second.find("\r\n")) + "\n";
			return out;
		}
	};

	// What the caller is answered on each path, for an INVITE whose Content-Type
	// lines are `typeLines`. Empty, with the traffic reported, when it is not.
	std::string answerOrReport(const Rig& r, const char* status)
	{
		std::string answer = r.first(status, kCallerIp);
		if (answer.empty()) ADD_FAILURE() << "no " << status << " to the caller:\n" << r.dump();
		return answer;
	}

	// buildOkWithSdp(): a 911 answered over the anchor.
	std::string anchorAnswer(const std::string& typeLines)
	{
		Rig r;
		r.send(invite("911", "ct845-anchor", typeLines), kCallerIp);
		return answerOrReport(r, "SIP/2.0 200");
	}

	// The 440 answer. No 911 reaches 440; a PSAP callback is the traffic the
	// gate lets through to it with a body not labelled SDP.
	std::string toneAnswer(const std::string& typeLines)
	{
		Rig r;
		r.send(invite("440", "ct845-tone", typeLines, "Priority: psap-callback\r\n"), kCallerIp);
		return answerOrReport(r, "SIP/2.0 200");
	}

	// answerAnchorReinvite(): a re-INVITE on a 911 answered over the anchor.
	std::string reinviteAnswer(const std::string& typeLines)
	{
		Rig r;
		r.send(invite("911", "ct845-reinv", "Content-Type: application/sdp\r\n"), kCallerIp);
		const std::string setup = answerOrReport(r, "SIP/2.0 200");
		if (setup.empty()) return {};
		r.sent.clear();
		r.send(invite("911", "ct845-reinv", typeLines, "", "To: " + headerValue(setup, "To"), 2), kCallerIp);
		return answerOrReport(r, "SIP/2.0 200");
	}

	// onTrunkRinging() and onTrunkAnswered(): a 911 over the trunk, the
	// carrier's 183 with early media and then its 200.
	std::pair<std::string, std::string> trunkAnswers(const std::string& typeLines)
	{
		Rig r(/*trunk=*/true);
		r.send(invite("911", "ct845-trunk", typeLines), kCallerIp);
		const std::string carrierInvite = r.first("INVITE sip:911@", kSbcIp);
		if (carrierInvite.empty())
		{
			ADD_FAILURE() << "the 911 did not reach the carrier:\n" << r.dump();
			return {};
		}
		r.send(carrierResponse(carrierInvite, "SIP/2.0 183 Session Progress"), kSbcIp);
		r.send(carrierResponse(carrierInvite, "SIP/2.0 200 OK"), kSbcIp);
		return {answerOrReport(r, "SIP/2.0 183"), answerOrReport(r, "SIP/2.0 200")};
	}

	// The PBX's own SDP, whole, under exactly the Content-Type line `typeLine`.
	void expectOwnSdpUnder(const std::string& answer, const std::string& typeLine)
	{
		EXPECT_EQ(contentTypeLines(answer), std::vector<std::string>{typeLine}) << answer;
		const std::string body = bodyOf(answer);
		EXPECT_EQ(body.rfind("v=0\r\n", 0), 0u) << answer;
		EXPECT_NE(body.find("\r\ns=pocketdial-media\r\nc=IN IP4 " + std::string(kServerIp) + "\r\n"),
			std::string::npos) << answer;
		EXPECT_NE(body.find("\r\nm=audio "), std::string::npos) << answer;
		EXPECT_EQ(headerValue(answer, "Content-Length"), std::to_string(body.size())) << answer;
	}

	const char* const kSdpType = "Content-Type: application/sdp";
}

// ── The defect: a non-SDP Content-Type is answered with two ──────────────────

TEST(SingleContentType, AnEmergencyAnsweredOverTheAnchorGetsOneSdpContentType)
{
	for (const char* typeLine : {"Content-Type: text/plain", "c: text/plain"})
	{
		SCOPED_TRACE(typeLine);
		const std::string ok = anchorAnswer(std::string(typeLine) + "\r\n");
		ASSERT_FALSE(ok.empty());
		expectOwnSdpUnder(ok, kSdpType);
	}
}

TEST(SingleContentType, APsapCallbackToTheToneLineGetsOneSdpContentType)
{
	const std::string ok = toneAnswer("Content-Type: text/plain\r\n");
	ASSERT_FALSE(ok.empty());
	expectOwnSdpUnder(ok, kSdpType);
}

TEST(SingleContentType, AnEmergencyReinviteOnTheAnchorGetsOneSdpContentType)
{
	const std::string ok = reinviteAnswer("Content-Type: text/plain\r\n");
	ASSERT_FALSE(ok.empty());
	expectOwnSdpUnder(ok, kSdpType);
}

// The sibling copies on the trunk route, where a 911 goes on a trunk board.
TEST(SingleContentType, AnEmergencyCallOverTheTrunkGetsOneSdpContentTypeOnItsProgressAndAnswer)
{
	const auto [progress, ok] = trunkAnswers("Content-Type: text/plain\r\n");
	ASSERT_FALSE(progress.empty());
	ASSERT_FALSE(ok.empty());
	{
		SCOPED_TRACE("183");
		expectOwnSdpUnder(progress, kSdpType);
	}
	{
		SCOPED_TRACE("200");
		expectOwnSdpUnder(ok, kSdpType);
	}
}

// A request is not supposed to carry two (RFC 3261 §7.3.1), and the gate reads
// the last one. A 555 call passes it with text/plain first and SDP last.
TEST(SingleContentType, AnInviteWithTwoContentTypeLinesIsAnsweredWithOne)
{
	Rig r;
	r.send(invite("555", "ct845-two", "Content-Type: text/plain\r\nContent-Type: application/sdp\r\n"), kCallerIp);
	const std::string ok = answerOrReport(r, "SIP/2.0 200");
	ASSERT_FALSE(ok.empty());
	expectOwnSdpUnder(ok, kSdpType);
}

// ── Controls ─────────────────────────────────────────────────────────────────

// A Content-Type that already names SDP is left exactly as the caller wrote it.
TEST(SingleContentType, AnInviteAlreadyLabelledSdpKeepsItsOwnLineOnEveryPath)
{
	for (const char* typeLine : {"Content-Type: application/sdp", "c: Application/SDP"})
	{
		SCOPED_TRACE(typeLine);
		const std::string lines = std::string(typeLine) + "\r\n";
		std::string answer = anchorAnswer(lines);
		ASSERT_FALSE(answer.empty());
		expectOwnSdpUnder(answer, typeLine);
		answer = toneAnswer(lines);
		ASSERT_FALSE(answer.empty());
		expectOwnSdpUnder(answer, typeLine);
		answer = reinviteAnswer(lines);
		ASSERT_FALSE(answer.empty());
		expectOwnSdpUnder(answer, typeLine);
		const auto [progress, ok] = trunkAnswers(lines);
		ASSERT_FALSE(progress.empty());
		ASSERT_FALSE(ok.empty());
		expectOwnSdpUnder(progress, typeLine);
		expectOwnSdpUnder(ok, typeLine);
	}
}

// With none (#844 for the three answer builders), the answer gets exactly one.
TEST(SingleContentType, AnInviteWithNoContentTypeGetsExactlyOneOnEveryPath)
{
	std::string answer = anchorAnswer("");
	ASSERT_FALSE(answer.empty());
	expectOwnSdpUnder(answer, kSdpType);
	answer = toneAnswer("");
	ASSERT_FALSE(answer.empty());
	expectOwnSdpUnder(answer, kSdpType);
	answer = reinviteAnswer("");
	ASSERT_FALSE(answer.empty());
	expectOwnSdpUnder(answer, kSdpType);
	const auto [progress, ok] = trunkAnswers("");
	ASSERT_FALSE(progress.empty());
	ASSERT_FALSE(ok.empty());
	{
		SCOPED_TRACE("trunk 183");
		expectOwnSdpUnder(progress, kSdpType);
	}
	{
		SCOPED_TRACE("trunk 200");
		expectOwnSdpUnder(ok, kSdpType);
	}
}

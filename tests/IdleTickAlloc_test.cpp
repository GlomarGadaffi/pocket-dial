// Issue #463 (#284 batch B): the idle-board allocators.
//
//   - tick()'s dashboard snapshot was rebuilt from empty and the old one freed
//     every second (~2-5 KB of internal-DRAM churn); it is now refilled in place
//     into a persistent scratch copy and swapped in.
//   - buildOptionsPing() (one per phone every 5 s) was an ostringstream plus
//     seven string temporaries; it is now one stack snprintf.
//   - setHeaderOnce()/addHeader()/syncContentLength() built std::string
//     temporaries on nearly every response; they now write in place.
//
// Found on the way: the old whole-struct snapshot move preserved `devices` and
// `pageZones` across the swap but not `voicemail`, so the dashboard's voicemail
// list was blanked one tick after every change.
//
// The ping path still allocates in the pooled re-parse and on send; those are
// #462 (batch A). The steady tick below pings nobody, so it measures this
// batch alone.

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

#include "RequestsHandler.hpp"
#include "SipMessage.hpp"
#include "support/AllocCounter.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	using SentList = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(port);
		return a;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip)
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKr463" + ext + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: reg-463-" + ext + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	std::string headerValue(const std::string& raw, const std::string& name)
	{
		size_t pos = 0;
		while (pos < raw.size())
		{
			size_t eol = raw.find("\r\n", pos);
			if (eol == std::string::npos) eol = raw.size();
			if (eol == pos) break;
			if (raw.compare(pos, name.size() + 1, name + ":") == 0)
			{
				size_t v = pos + name.size() + 1;
				while (v < eol && raw[v] == ' ') ++v;
				return raw.substr(v, eol - v);
			}
			pos = eol + 2;
		}
		return {};
	}

	struct Rig
	{
		SentList sent;
		RequestsHandler handler;
		Rig() : handler("192.168.63.1", 5060,
			[this](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				sent.emplace_back(addr, std::move(msg));
			})
		{
			for (int i = 0; i < 4; ++i)
			{
				handler.handle(makeRegister(std::to_string(100 + i), "192.168.63." + std::to_string(10 + i)));
			}
		}
		void tickNow()
		{
			handler.forceNextTickForTest();
			handler.tick();
		}
	};
}

// The #463 gate for this batch: with four phones registered and nothing
// changing, a tick() that pings nobody allocates nothing. The first two ticks
// are warm-up: the first pings every phone (their 5 s interval starts at the
// epoch) and grows the snapshot tables; the second refills the scratch copy
// the first swapped out, which is then at full capacity too.
TEST(IdleTickAlloc, SteadyTickWithFourPhonesAllocatesNothing)
{
	Rig r;
	r.tickNow();
	r.tickNow();
	r.sent.clear();

	AllocGuard guard;
	r.tickNow();
	const size_t allocs = guard.delta();

	EXPECT_TRUE(r.sent.empty()) << "no ping is due within 5 s of the last one";
	EXPECT_EQ(allocs, 0u) << "an unchanged dashboard snapshot must be refilled in place";
	EXPECT_EQ(r.handler.getActiveClients().size(), 4u) << "the refilled snapshot must still list every phone";
}

// Found while writing #463: tick() used to move-assign a fresh snapshot over
// _snapshot, blanking `voicemail` (mirrored out of band) one tick after every
// change. The tables tick() does not rebuild must survive it.
TEST(IdleTickAlloc, VoicemailListSurvivesATick)
{
	Rig r;
	r.handler.setVoicemail("101", true);
	auto before = r.handler.getVoicemailExtensions();
	ASSERT_NE(std::find(before.begin(), before.end(), "101"), before.end())
		<< "setVoicemail must mirror into the dashboard snapshot";

	r.tickNow();
	auto after = r.handler.getVoicemailExtensions();
	EXPECT_NE(std::find(after.begin(), after.end(), "101"), after.end())
		<< "a tick must not blank the voicemail list";
}

// The rewritten ping is the same request: method line, Via with the RFC 3261
// magic cookie, To/From, CSeq, and a Call-ID of 15 random characters @ our IP.
TEST(IdleTickAlloc, OptionsPingIsWellFormed)
{
	Rig r;
	r.sent.clear();
	r.tickNow();

	std::string ping;
	for (const auto& [addr, msg] : r.sent)
	{
		if (addr.sin_addr.s_addr != addrFor("192.168.63.10").sin_addr.s_addr) continue;
		const std::string raw = msg->toString();
		if (raw.rfind("OPTIONS ", 0) == 0) ping = raw;
	}
	ASSERT_FALSE(ping.empty()) << "the first tick must ping phone 100";
	EXPECT_EQ(ping.rfind("OPTIONS sip:100@192.168.63.10:5060 SIP/2.0\r\n", 0), 0u) << ping;
	const std::string via = headerValue(ping, "Via");
	const size_t b = via.find(";branch=z9hG4bK");
	ASSERT_NE(b, std::string::npos) << via;
	EXPECT_EQ(via.size() - (b + 15), 12u) << "branch = magic cookie + 12 random chars: " << via;
	EXPECT_EQ(headerValue(ping, "To"), "<sip:100@192.168.63.10:5060>");
	EXPECT_NE(headerValue(ping, "From").find(";tag="), std::string::npos);
	EXPECT_EQ(headerValue(ping, "CSeq"), "1 OPTIONS");
	const std::string callId = headerValue(ping, "Call-ID");
	const size_t at = callId.find('@');
	ASSERT_NE(at, std::string::npos) << callId;
	EXPECT_EQ(at, 15u) << "15 random characters (SSO-sized, so IDGen does not allocate): " << callId;
	EXPECT_EQ(headerValue(ping, "Content-Length"), "0");
}

// setHeaderOnce() over an existing line rewrites it in place, and
// syncContentLength() rewrites its line from a stack buffer: neither needs a
// new allocation when the line already has room.
TEST(IdleTickAlloc, HeaderRewritesReuseTheExistingLine)
{
	auto msg = std::make_shared<SipMessage>(std::string(
		"SIP/2.0 200 OK\r\n"
		"Via: SIP/2.0/UDP 192.168.63.10:5060;branch=z9hG4bKh463\r\n"
		"From: <sip:100@server>;tag=a\r\n"
		"To: <sip:100@server>;tag=b\r\n"
		"Call-ID: hdr-463\r\n"
		"CSeq: 1 OPTIONS\r\n"
		"Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, REGISTER, INFO, MESSAGE, REFER, UPDATE, SUBSCRIBE, NOTIFY, PRACK\r\n"
		"Content-Length: 1234\r\n\r\n"), addrFor("192.168.63.10"));

	AllocGuard guard;
	msg->setHeaderOnce("Allow", "INVITE, ACK, BYE");
	msg->syncContentLength();
	const size_t allocs = guard.delta();

	const std::string raw = msg->toString();
	EXPECT_EQ(allocs, 0u);
	EXPECT_EQ(headerValue(raw, "Allow"), "INVITE, ACK, BYE");
	EXPECT_EQ(raw.find("Allow:"), raw.rfind("Allow:")) << "exactly one Allow line";
	EXPECT_EQ(headerValue(raw, "Content-Length"), "0");
}

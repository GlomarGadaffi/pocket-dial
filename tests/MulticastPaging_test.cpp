// MulticastPaging_test.cpp -- issue #800: dial 997, and the caller's audio is
// re-sent as G.711 RTP to a LAN multicast group (default 239.0.1.75:50000, TTL 1).
//
// Two layers:
//   MulticastPager   the re-sender alone: RTP header, our own SSRC/sequence/
//                    timestamp, TTL 1, PCMU only, no heap per frame (#284).
//   MulticastPaging  RequestsHandler: the 997 answer (recvonly), off by default,
//                    one page at a time (486), teardown on BYE and on silence, the
//                    reserved-number refusals, 911 untouched, pool refusal, and
//                    the /api/multicast-paging config route.
//
// The send goes through a fake McastTx. On host RtpReceiver::start() binds no
// socket, so caller RTP is injected through the receiver's dispatchRaw(), which
// is what its receive task calls on the board.

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "AdminAuth.hpp"
#include "AllocCounter.hpp"
#include "HttpServer.hpp"
#include "LoopbackAnchorClient.hpp"
#include "MulticastPager.hpp"
#include "PbxConfig.hpp"
#include "PoolConfig.hpp"
#include "RequestsHandler.hpp"
#include "RtpReceiver.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>
#endif

#if POCKETDIAL_MULTICAST_PAGING

namespace
{
	constexpr uint32_t kGroup = (239u << 24) | (0u << 16) | (1u << 8) | 75u;   // 239.0.1.75

	// Records into fixed storage only, so the zero-allocation test measures the pager.
	struct FakeTx : McastTx
	{
		int opens = 0;
		int ttl = -1;
		bool failOpen = false;
		size_t sends = 0;
		uint32_t lastGroup = 0;
		uint16_t lastPort = 0;
		uint8_t last[RtpReceiver::MAX_DATAGRAM_BYTES] = {};
		size_t lastLen = 0;
		struct Hdr { bool marker; uint8_t pt; uint16_t seq; uint32_t ts; uint32_t ssrc; size_t len; };
		Hdr hdrs[16] = {};

		bool open(uint8_t t) override
		{
			++opens;
			ttl = t;
			return !failOpen;
		}
		bool sendTo(const uint8_t* d, size_t n, uint32_t g, uint16_t p) override
		{
			lastGroup = g;
			lastPort = p;
			lastLen = n < sizeof(last) ? n : sizeof(last);
			std::memcpy(last, d, lastLen);
			if (sends < 16 && n >= 12)
			{
				hdrs[sends] = Hdr{(d[1] & 0x80) != 0, static_cast<uint8_t>(d[1] & 0x7F),
					static_cast<uint16_t>((d[2] << 8) | d[3]),
					(uint32_t(d[4]) << 24) | (uint32_t(d[5]) << 16) | (uint32_t(d[6]) << 8) | d[7],
					(uint32_t(d[8]) << 24) | (uint32_t(d[9]) << 16) | (uint32_t(d[10]) << 8) | d[11],
					n - 12};
			}
			++sends;
			return true;
		}
	};

	uint8_t g_frame[RtpReceiver::MAX_DATAGRAM_BYTES];

	// One caller packet as RtpReceiver::parseRtp() hands it to the raw sink.
	RtpReceiver::RtpPacket callerPkt(size_t n, uint8_t pt = 0, uint16_t seq = 4242, uint32_t ts = 777000)
	{
		for (size_t i = 0; i < sizeof(g_frame); ++i) g_frame[i] = static_cast<uint8_t>(i * 7 + 3);
		RtpReceiver::RtpPacket p;
		p.version = 2;
		p.payloadType = pt;
		p.seq = seq;
		p.timestamp = ts;
		p.ssrc = 0xCAFEBABEu;
		p.payload = g_frame;
		p.payloadLen = n;
		return p;
	}

	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	std::string reg(const std::string& ext, const std::string& ip, const std::string& callId)
	{
		return "REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKr" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + callId + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
	}

	std::string invite(const std::string& from, const std::string& to, const std::string& ip,
		const std::string& callId, const std::string& toTag = "")
	{
		const std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
		return "INVITE sip:" + to + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKi" + callId + toTag + "\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + to + "@server>" + (toTag.empty() ? "" : ";tag=" + toTag) + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + (toTag.empty() ? "1" : "2") + " INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + from + "@" + ip + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
	}

	std::string bye(const std::string& from, const std::string& to, const std::string& ip,
		const std::string& callId)
	{
		return "BYE sip:" + to + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKb" + callId + "\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + to + "@server>;tag=srv" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 3 BYE\r\n"
			"Content-Length: 0\r\n\r\n";
	}

	struct Bench
	{
		std::vector<std::pair<sockaddr_in, std::string>> sent;
		std::unique_ptr<RequestsHandler> handler;
		FakeTx tx;

		explicit Bench(bool enable = true)
		{
			handler = std::make_unique<RequestsHandler>("192.168.80.1", 5060,
				[this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
					sent.emplace_back(a, m ? m->toString() : std::string());
				});
			handler->setMulticastTxForTest(&tx);
			send(reg("501", "192.168.80.51", "reg-501"), "192.168.80.51");
			send(reg("502", "192.168.80.52", "reg-502"), "192.168.80.52");
			if (enable)
			{
				pbx::MulticastPagingConfig cfg;
				cfg.enabled = true;
				EXPECT_EQ(handler->setMulticastPaging(cfg), "");
			}
			sent.clear();
		}

		void send(const std::string& raw, const std::string& ip)
		{
			handler->handle(RequestsHandler::getMessageFromPool(raw, addrFor(ip)));
		}

		std::string first() const { return sent.empty() ? std::string() : sent.front().second; }

		bool saw(const std::string& needle) const
		{
			for (const auto& s : sent)
				if (s.second.find(needle) != std::string::npos) return true;
			return false;
		}

		size_t byesTo(const std::string& ip) const
		{
			size_t n = 0;
			const in_addr_t want = inet_addr(ip.c_str());
			for (const auto& s : sent)
				if (s.first.sin_addr.s_addr == want && s.second.rfind("BYE ", 0) == 0) ++n;
			return n;
		}

		bool hasSession(const std::string& callId)
		{
			return handler->getSession("Call-ID: " + callId).has_value();
		}

		// 501 pages; asserts the answer.
		void page(const std::string& callId = "pg-1")
		{
			sent.clear();
			send(invite("501", "997", "192.168.80.51", callId), "192.168.80.51");
			ASSERT_NE(first().find("SIP/2.0 200 OK"), std::string::npos) << first();
			ASSERT_TRUE(handler->multicastPageActiveForTest());
			sent.clear();
		}
	};
}

// ── The re-sender ─────────────────────────────────────────────────────────────

TEST(MulticastPager, PacketIsRtpV2PcmuWithOurHeaderAndThePayloadUntouched)
{
	uint8_t payload[160];
	for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = static_cast<uint8_t>(0xFF - i);
	uint8_t out[RtpReceiver::MAX_DATAGRAM_BYTES] = {};

	const size_t n = MulticastPager::buildPacket(out, sizeof(out), /*marker=*/true, 0x1234,
		0x89ABCDEFu, 0x01020304u, payload, sizeof(payload));
	ASSERT_EQ(n, 172u);
	EXPECT_EQ(out[0], 0x80) << "V=2, no padding, no extension, no CSRC";
	EXPECT_EQ(out[1], 0x80) << "M=1, PT=0 (PCMU)";
	EXPECT_EQ(out[2], 0x12); EXPECT_EQ(out[3], 0x34);
	EXPECT_EQ(out[4], 0x89); EXPECT_EQ(out[5], 0xAB); EXPECT_EQ(out[6], 0xCD); EXPECT_EQ(out[7], 0xEF);
	EXPECT_EQ(out[8], 0x01); EXPECT_EQ(out[9], 0x02); EXPECT_EQ(out[10], 0x03); EXPECT_EQ(out[11], 0x04);
	EXPECT_EQ(std::memcmp(out + 12, payload, sizeof(payload)), 0) << "the G.711 bytes are re-sent as received";

	EXPECT_EQ(MulticastPager::buildPacket(out, 100, false, 1, 1, 1, payload, sizeof(payload)), 0u)
		<< "a packet that does not fit is refused, never truncated";
}

TEST(MulticastPager, SequenceAndTimestampRunOnOurOwnClockAcrossFrames)
{
	FakeTx tx;
	MulticastPager pager(tx);
	ASSERT_TRUE(pager.start("Call-ID: c1", kGroup, 50000, 0xAABBCCDDu, 65534, 1000));

	// The caller's own numbering jumps around; ours must not. 30 ms ptime on the last.
	pager.onRtp(callerPkt(160, 0, 10, 5000));
	pager.onRtp(callerPkt(160, 0, 900, 99999));
	pager.onRtp(callerPkt(160, 0, 11, 5160));
	pager.onRtp(callerPkt(240, 0, 12, 5320));

	ASSERT_EQ(tx.sends, 4u);
	const uint16_t seqs[] = {65534, 65535, 0, 1};
	const uint32_t tss[]  = {1000, 1160, 1320, 1480};
	for (size_t i = 0; i < 4; ++i)
	{
		SCOPED_TRACE(i);
		EXPECT_EQ(tx.hdrs[i].seq, seqs[i]) << "sequence +1 per packet, wrapping at 65535";
		EXPECT_EQ(tx.hdrs[i].ts, tss[i]) << "timestamp + samples in the previous packet";
		EXPECT_EQ(tx.hdrs[i].ssrc, 0xAABBCCDDu) << "our own SSRC, never the caller's";
		EXPECT_EQ(tx.hdrs[i].marker, i == 0) << "M=1 on the first packet of the page only";
		EXPECT_EQ(tx.hdrs[i].pt, 0);
	}
	EXPECT_EQ(tx.hdrs[3].len, 240u);
	EXPECT_EQ(pager.txPackets(), 4u);
}

TEST(MulticastPager, OpensTheSocketWithTtlOneAndSendsToTheDefaultGroup)
{
	const pbx::MulticastPagingConfig defaults;
	EXPECT_FALSE(defaults.enabled) << "off until an admin turns it on";
	EXPECT_EQ(defaults.group, kGroup) << "239.0.1.75";
	EXPECT_EQ(defaults.port, 50000) << "port 50000, not 10000 (desmo, #800)";

	FakeTx tx;
	MulticastPager pager(tx);
	ASSERT_TRUE(pager.start("Call-ID: c1", defaults.group, defaults.port, 1, 1, 1));
	EXPECT_EQ(tx.opens, 1);
	EXPECT_EQ(tx.ttl, 1) << "TTL 1: the page never leaves the LAN";
	pager.onRtp(callerPkt(160));
	EXPECT_EQ(tx.lastGroup, kGroup);
	EXPECT_EQ(tx.lastPort, 50000);
}

TEST(MulticastPager, OnlyPcmuIsSentButEveryPacketCountsAsLiveness)
{
	FakeTx tx;
	MulticastPager pager(tx);
	ASSERT_TRUE(pager.start("Call-ID: c1", kGroup, 50000, 1, 1, 1));

	pager.onRtp(callerPkt(4, 101));   // RFC 4733 telephone-event
	pager.onRtp(callerPkt(1, 13));    // comfort noise
	pager.onRtp(callerPkt(160, 8));   // PCMA, which the answer never offered
	EXPECT_EQ(tx.sends, 0u) << "only PCMU goes to the group";
	EXPECT_EQ(pager.rxPackets(), 3u) << "the caller is still talking to us: not silence";

	pager.onRtp(callerPkt(160, 0));
	EXPECT_EQ(tx.sends, 1u);
	EXPECT_EQ(pager.rxPackets(), 4u);
}

TEST(MulticastPager, ForwardingAFrameAllocatesNothing)
{
	FakeTx tx;
	MulticastPager pager(tx);
	ASSERT_TRUE(pager.start("Call-ID: c1", kGroup, 50000, 7, 7, 7));
	const RtpReceiver::RtpPacket pkt = callerPkt(160);
	pager.onRtp(pkt);   // warm-up

	AllocGuard guard;
	for (int i = 0; i < 50; ++i) MulticastPager::rawSink(&pager, pkt);
	EXPECT_EQ(guard.delta(), 0u) << "#284: no heap on the RTP path once the page has started";
	EXPECT_EQ(tx.sends, 51u);
}

TEST(MulticastPager, OnePageAtATimeAndAStoppedPageSendsNothing)
{
	FakeTx tx;
	MulticastPager pager(tx);
	ASSERT_TRUE(pager.start("Call-ID: c1", kGroup, 50000, 1, 1, 1));
	EXPECT_TRUE(pager.holds("Call-ID: c1"));
	EXPECT_FALSE(pager.start("Call-ID: c2", kGroup, 50000, 1, 1, 1)) << "a second page is refused";
	EXPECT_FALSE(pager.stopFor("Call-ID: c2")) << "another call cannot end this page";
	EXPECT_TRUE(pager.isActive());

	EXPECT_TRUE(pager.stopFor("Call-ID: c1"));
	EXPECT_FALSE(pager.isActive());
	EXPECT_FALSE(pager.holds("Call-ID: c1"));
	pager.onRtp(callerPkt(160));
	EXPECT_EQ(tx.sends, 0u) << "a late packet on the receive task after stop is dropped";

	FakeTx broken;
	broken.failOpen = true;
	MulticastPager p2(broken);
	EXPECT_FALSE(p2.start("Call-ID: c3", kGroup, 50000, 1, 1, 1)) << "no socket, no page";
	EXPECT_FALSE(p2.isActive());
}

// ── The 997 dial ──────────────────────────────────────────────────────────────

TEST(MulticastPaging, DialingTheExtensionAnswersRecvonlyAndRelaysTheCallersAudio)
{
	Bench b;
	b.send(invite("501", "997", "192.168.80.51", "pg-ok"), "192.168.80.51");

	const std::string ok = b.first();
	ASSERT_NE(ok.find("SIP/2.0 200 OK"), std::string::npos) << ok;
	EXPECT_NE(ok.find("a=recvonly"), std::string::npos) << "we only listen on this leg:\n" << ok;
	EXPECT_EQ(ok.find("a=sendrecv"), std::string::npos) << ok;
	EXPECT_NE(ok.find("RTP/AVP 0\r\n"), std::string::npos) << "PCMU only:\n" << ok;
	EXPECT_NE(ok.find("Contact: <sip:997@"), std::string::npos) << ok;
	EXPECT_TRUE(b.hasSession("pg-ok"));
	ASSERT_TRUE(b.handler->multicastPageActiveForTest());

	EXPECT_TRUE(b.handler->multicastRtpForTest(callerPkt(160)));
	EXPECT_EQ(b.tx.sends, 1u);
	EXPECT_EQ(b.tx.lastGroup, kGroup);
	EXPECT_EQ(b.tx.lastPort, 50000);
	EXPECT_EQ(b.tx.ttl, 1);
}

TEST(MulticastPaging, OffByDefaultTheDialIsRefused403AndNothingStarts)
{
	Bench b(/*enable=*/false);
	EXPECT_FALSE(b.handler->getMulticastPaging().enabled);
	b.send(invite("501", "997", "192.168.80.51", "pg-off"), "192.168.80.51");

	EXPECT_NE(b.first().find("SIP/2.0 403"), std::string::npos) << b.first();
	EXPECT_FALSE(b.hasSession("pg-off"));
	EXPECT_FALSE(b.handler->multicastPageActiveForTest());
	EXPECT_EQ(b.tx.opens, 0);
}

TEST(MulticastPaging, ASecondCallerGets486WhileAPageIsLive)
{
	Bench b;
	b.page("pg-a");
	b.send(invite("502", "997", "192.168.80.52", "pg-b"), "192.168.80.52");

	EXPECT_NE(b.first().find("486 Busy Here"), std::string::npos) << b.first();
	EXPECT_FALSE(b.hasSession("pg-b"));
	EXPECT_TRUE(b.hasSession("pg-a"));
	EXPECT_TRUE(b.handler->multicastPageActiveForTest()) << "the live page is untouched";
}

TEST(MulticastPaging, ByeEndsThePageAndFreesItForTheNextCaller)
{
	Bench b;
	b.page("pg-a");
	b.send(bye("501", "997", "192.168.80.51", "pg-a"), "192.168.80.51");

	EXPECT_NE(b.first().find("SIP/2.0 200 OK"), std::string::npos) << b.first();
	EXPECT_FALSE(b.hasSession("pg-a"));
	EXPECT_FALSE(b.handler->multicastPageActiveForTest());
	EXPECT_FALSE(b.handler->multicastRtpForTest(callerPkt(160))) << "receiver stopped";

	b.page("pg-b");
}

TEST(MulticastPaging, SilenceEndsThePageWithAByeToTheCaller)
{
	Bench b;
	b.page("pg-s");
	const auto t0 = std::chrono::steady_clock::now();

	b.handler->multicastRtpForTest(callerPkt(160));
	b.handler->sweepMulticastPageForTest(t0 + std::chrono::seconds(3));
	b.handler->sweepMulticastPageForTest(t0 + std::chrono::seconds(3) + pbx::kMulticastPageSilence
		- std::chrono::seconds(1));
	EXPECT_TRUE(b.handler->multicastPageActiveForTest()) << "RTP at 3 s keeps it up";
	EXPECT_EQ(b.byesTo("192.168.80.51"), 0u);

	b.handler->sweepMulticastPageForTest(t0 + std::chrono::seconds(4) + pbx::kMulticastPageSilence);
	EXPECT_EQ(b.byesTo("192.168.80.51"), 1u) << "the caller is told the page is over";
	EXPECT_TRUE(b.saw("Call-ID: pg-s"));
	EXPECT_FALSE(b.hasSession("pg-s"));
	EXPECT_FALSE(b.handler->multicastPageActiveForTest());
}

TEST(MulticastPaging, AnEmergencyCallStillRoutesWhileAPageIsLive)
{
	Bench b;
	b.handler->setAnchorPlacesRealCallsForTest(true);
	b.page("pg-911");
	auto* loopback = dynamic_cast<LoopbackAnchorClient*>(b.handler->anchorClientForTest());
	ASSERT_NE(loopback, nullptr);

	b.send(invite("502", "911", "192.168.80.52", "em-911"), "192.168.80.52");
	EXPECT_EQ(loopback->lastMakeCallDestination(), "911") << "a page never gates or pre-empts 911";
	EXPECT_FALSE(b.saw("486 Busy Here"));
}

TEST(MulticastPaging, TheExtensionIsReservedEverywhere)
{
	EXPECT_TRUE(pbx::isReservedExtension("997"));
	EXPECT_TRUE(pbx::isReservedOrPstnAor("997")) << "REGISTER and Learn adoption refuse it";

	Bench b;
	b.send(reg("997", "192.168.80.97", "reg-997"), "192.168.80.97");
	EXPECT_NE(b.first().find("SIP/2.0 403"), std::string::npos) << "no phone may register as 997:\n" << b.first();

	b.handler->setDialRule("997", "group", "600");
	b.handler->setRingGroup("997", "501,502", "ringall");
	b.handler->setForward("997", "always", "501");
	for (const auto& r : b.handler->getDialRules()) EXPECT_NE(std::get<0>(r), "997");
	for (const auto& g : b.handler->getRingGroups()) EXPECT_NE(std::get<0>(g), "997");
	for (const auto& f : b.handler->getForwards()) EXPECT_NE(std::get<0>(f), "997");
}

TEST(MulticastPaging, AHoldReinviteIsDeclinedAndThePageSurvives)
{
	Bench b;
	b.page("pg-h");
	b.send(invite("501", "997", "192.168.80.51", "pg-h", "srvtag"), "192.168.80.51");

	EXPECT_TRUE(b.saw("488 Not Acceptable Here")) << b.first();
	for (const auto& s : b.sent) EXPECT_NE(s.second.rfind("INVITE ", 0), 0u) << "nothing relayed back";
	EXPECT_TRUE(b.handler->multicastPageActiveForTest());
}

TEST(MulticastPaging, AnAdminKillByesTheCallerOnceAndEndsThePage)
{
	Bench b;
	b.page("pg-k");
	ASSERT_TRUE(b.handler->forceDisconnect("501"));
	// forceDisconnect queues on the async outbox; the next SIP pass flushes it.
	b.send("OPTIONS sip:server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.80.99:5060;branch=z9hG4bKflush\r\n"
		"From: <sip:probe@server>;tag=probe\r\nTo: <sip:server@server>\r\n"
		"Call-ID: flush-800\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\n"
		"Content-Length: 0\r\n\r\n", "192.168.80.99");

	EXPECT_EQ(b.byesTo("192.168.80.51"), 1u)
		<< "the page's dest is a stand-in at the caller's own address: one BYE, not two";
	EXPECT_FALSE(b.handler->multicastPageActiveForTest());
}

TEST(MulticastPaging, MessagePoolRefusalOnTheAnswerUnwindsThePage)
{
	Bench b;
	auto inv = RequestsHandler::getMessageFromPool(invite("501", "997", "192.168.80.51", "pg-pool"),
		addrFor("192.168.80.51"));
	ASSERT_NE(inv, nullptr);
	{
		std::vector<std::shared_ptr<SipMessage>> held;
		const std::string filler = reg("599", "192.168.80.59", "hold");
		for (size_t i = 0; i < 4 * POCKETDIAL_MSG_POOL; ++i)
		{
			auto m = RequestsHandler::getMessageFromPool(filler, addrFor("192.168.80.59"));
			if (!m) break;
			held.push_back(std::move(m));
		}
		b.handler->handle(inv);
		EXPECT_EQ(b.tx.opens, 1) << "the page got as far as starting before the answer draw";
		EXPECT_FALSE(b.handler->multicastPageActiveForTest()) << "no answer, so no page";
		EXPECT_FALSE(b.hasSession("pg-pool"));
	}
	inv.reset();

	// The caller's retransmit finds a clean slate.
	b.page("pg-pool");
}

// ── /api/multicast-paging ─────────────────────────────────────────────────────

#if !defined(_WIN32) && !defined(_WIN64)
namespace
{
	struct HttpBench
	{
		RequestsHandler handler{"10.0.0.1", 5060, [](const sockaddr_in&, std::shared_ptr<SipMessage>) {}};
		HttpServer server{"127.0.0.1", 28800, nullptr};   // never start()ed
		std::string cookie;
		std::string csrf;

		HttpBench()
		{
			server.attachHandler(&handler);
			AdminAuth::clearCredential();
			EXPECT_TRUE(AdminAuth::setLoginCredential("admin", "gatepassword123"));
			const std::string token = AdminAuth::createSession(AdminAuth::Role::Owner);
			cookie = "pd_session=" + token;
			csrf = AdminAuth::sessionCsrf(token);
		}
		~HttpBench() { AdminAuth::clearCredential(); }

		std::string serve(const std::string& method, const std::string& body = "")
		{
			std::string req = method + " /api/multicast-paging HTTP/1.1\r\n"
				"Host: 127.0.0.1\r\nOrigin: http://127.0.0.1\r\n"
				"Cookie: " + cookie + "\r\nX-CSRF: " + csrf + "\r\n";
			if (!body.empty())
				req += "Content-Type: application/x-www-form-urlencoded\r\n"
				       "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			else
				req += "\r\n";
			int sv[2];
			if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return "socketpair failed";
			::send(sv[1], req.data(), req.size(), MSG_NOSIGNAL);
			::shutdown(sv[1], SHUT_WR);
			std::string got;
			std::thread reader([&] {
				char buf[4096];
				for (ssize_t n; (n = ::recv(sv[1], buf, sizeof(buf), 0)) > 0;) got.append(buf, static_cast<size_t>(n));
			});
			server.handleClientForTest(sv[0]);
			reader.join();
			::close(sv[1]);
			return got;
		}
	};
}

TEST(MulticastPaging, ConfigRouteReadsAndWritesTheGroupAndRefusesBadOnes)
{
	HttpBench h;
	std::string r = h.serve("GET");
	ASSERT_EQ(r.rfind("HTTP/1.1 200", 0), 0u) << r;
	EXPECT_NE(r.find("\"enabled\":false"), std::string::npos) << r;
	EXPECT_NE(r.find("\"group\":\"239.0.1.75\""), std::string::npos) << r;
	EXPECT_NE(r.find("\"port\":50000"), std::string::npos) << r;

	r = h.serve("PUT", "enabled=1&group=239.1.2.3&port=40000");
	ASSERT_EQ(r.rfind("HTTP/1.1 200", 0), 0u) << r;
	EXPECT_NE(r.find("\"enabled\":true"), std::string::npos) << r;
	EXPECT_NE(r.find("\"group\":\"239.1.2.3\""), std::string::npos) << r;
	EXPECT_NE(r.find("\"port\":40000"), std::string::npos) << r;

	for (const char* bad : {"group=224.0.0.251", "group=10.1.2.3", "group=239.1.2", "port=0", "port=70000",
	                        "port=5x"})
	{
		SCOPED_TRACE(bad);
		r = h.serve("PUT", bad);
		EXPECT_EQ(r.rfind("HTTP/1.1 400", 0), 0u) << r;
	}
	const pbx::MulticastPagingConfig kept = h.handler.getMulticastPaging();
	EXPECT_TRUE(kept.enabled);
	EXPECT_EQ(kept.group, (239u << 24) | (1u << 16) | (2u << 8) | 3u) << "a refused PUT changes nothing";
	EXPECT_EQ(kept.port, 40000);
}
#endif

#endif // POCKETDIAL_MULTICAST_PAGING

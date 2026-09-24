// Issue #430: packetsDropped split by reason, plus a fixed ring of the most
// recent refusals (src/SIP/DropProbe.hpp). The idle ~5% on .244 could not be
// attributed because the one counter merged malformed packets with rate-limit
// refusals and recorded nothing about either.

#include <gtest/gtest.h>

#include "DropProbe.hpp"
#include "RequestsHandler.hpp"
#include "support/AllocCounter.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include <string>

namespace
{
	sockaddr_in addr(const char* ip, uint16_t port)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_port   = htons(port);
		::inet_pton(AF_INET, ip, &a.sin_addr);
		return a;
	}

	void noSend(const sockaddr_in&, std::shared_ptr<SipMessage>) {}

	// Feed `raw` the way SipServer::onNewMessage does: parsed through the pool,
	// with the wire bytes alongside.
	void feed(RequestsHandler& h, const std::string& raw, const sockaddr_in& src)
	{
		h.handle(RequestsHandler::getMessageFromPool(raw, src), raw);
	}

	std::string options(int n)
	{
		const std::string id = std::to_string(n);
		return "OPTIONS sip:server SIP/2.0\r\n"
		       "Via: SIP/2.0/UDP 192.168.4.60:5060;branch=z9hG4bKdp" + id + "\r\n"
		       "From: <sip:101@server>;tag=dp" + id + "\r\n"
		       "To: <sip:server>\r\n"
		       "Call-ID: drop-probe-" + id + "\r\n"
		       "CSeq: 1 OPTIONS\r\n"
		       "Content-Length: 0\r\n\r\n";
	}
}

// The hypothesis #430 is testing: an RFC 5626 double-CRLF keep-alive (and
// pjsip's single-CRLF one) is refused as malformed. The probe must say so,
// with the sender and the bytes, and must not call it a rate-limit refusal.
TEST(DropProbe, CrlfKeepAliveIsRecordedAsInvalidWithSourceAndBytes)
{
	RequestsHandler handler("192.168.4.1", 5060, noSend);
	const sockaddr_in phone = addr("192.168.4.181", 5062);

	feed(handler, "\r\n\r\n", phone);
	feed(handler, "\r\n", phone);

	EXPECT_EQ(handler.getPacketsDropped(), 2u);
	EXPECT_EQ(handler.getDroppedInvalid(), 2u);
	EXPECT_EQ(handler.getDroppedRate(), 0u);
	EXPECT_EQ(handler.getPacketsProcessed(), 0u);

	const auto drops = handler.getRecentDrops();
	ASSERT_EQ(drops.size(), 2u);
	EXPECT_EQ(drops[0].reason, DropProbe::Reason::Invalid);
	EXPECT_EQ(drops[0].src.sin_addr.s_addr, phone.sin_addr.s_addr);
	EXPECT_EQ(drops[0].src.sin_port, phone.sin_port);
	EXPECT_EQ(drops[0].len, 4u);
	ASSERT_EQ(drops[0].headLen, 4u);
	EXPECT_EQ(std::string(reinterpret_cast<const char*>(drops[0].head.data()), 4), "\r\n\r\n");
	EXPECT_EQ(drops[1].len, 2u);
	EXPECT_LT(drops[0].seq, drops[1].seq);
}

// A burst past the token bucket (40) from one address is a Rate refusal, and
// the per-reason counters sum to the legacy packetsDropped.
TEST(DropProbe, TokenBucketRefusalIsRecordedAsRateAndCountersSum)
{
	RequestsHandler handler("192.168.4.1", 5060, noSend);
	const sockaddr_in src = addr("192.168.4.60", 5060);

	for (int i = 0; i < 60; ++i) feed(handler, options(i), src);
	feed(handler, "\r\n\r\n", src);

	EXPECT_GE(handler.getDroppedRate(), 1u)
		<< "60 packets inside one burst must exhaust a 40-token bucket";
	EXPECT_EQ(handler.getDroppedInvalid(), 1u);
	EXPECT_EQ(handler.getPacketsDropped(), handler.getDroppedInvalid() + handler.getDroppedRate());

	bool sawRate = false;
	for (const auto& d : handler.getRecentDrops())
	{
		if (d.reason == DropProbe::Reason::Rate)
		{
			sawRate = true;
			EXPECT_EQ(d.src.sin_addr.s_addr, src.sin_addr.s_addr);
			ASSERT_EQ(d.headLen, DropProbe::kHeadBytes);
			EXPECT_EQ(std::string(reinterpret_cast<const char*>(d.head.data()), 7), "OPTIONS");
		}
	}
	EXPECT_TRUE(sawRate);
}

// Bounded: the ring keeps the newest kRingSize, oldest first, and the counts
// keep counting past it.
TEST(DropProbe, RingKeepsTheNewestAndCountsKeepGoing)
{
	DropProbe probe;
	const sockaddr_in src = addr("10.0.0.1", 5060);
	const std::size_t total = DropProbe::kRingSize + 5;
	for (std::size_t i = 0; i < total; ++i) probe.note(DropProbe::Reason::Invalid, src, "x");

	EXPECT_EQ(probe.invalidCount(), total);
	const auto drops = probe.recent();
	ASSERT_EQ(drops.size(), DropProbe::kRingSize);
	EXPECT_EQ(drops.front().seq, total - DropProbe::kRingSize);
	EXPECT_EQ(drops.back().seq, total - 1);
	for (std::size_t i = 1; i < drops.size(); ++i) EXPECT_EQ(drops[i].seq, drops[i - 1].seq + 1);
}

// Milestone 1: recording a drop is on the SIP receive path and must not touch
// the heap, whatever the payload size. The head is clamped, never copied whole.
TEST(DropProbe, RecordingAllocatesNothing)
{
	DropProbe probe;
	const sockaddr_in src = addr("10.0.0.2", 5060);
	const std::string big(3000, 'A');
	probe.note(DropProbe::Reason::Invalid, src, "warm");   // first-use effects, if any

	AllocGuard guard;
	for (int i = 0; i < 3 * static_cast<int>(DropProbe::kRingSize); ++i)
	{
		probe.note(DropProbe::Reason::Invalid, src, std::string_view());
		probe.note(DropProbe::Reason::Rate, src, "\r\n\r\n");
		probe.note(DropProbe::Reason::Invalid, src, big);
	}
	EXPECT_EQ(guard.delta(), 0u);

	const auto drops = probe.recent();
	EXPECT_EQ(drops.back().len, 3000u);
	EXPECT_EQ(drops.back().headLen, DropProbe::kHeadBytes);
}

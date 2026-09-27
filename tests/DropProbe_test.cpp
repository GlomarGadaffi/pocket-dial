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
#include <vector>

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

	// Test-side read of the ring, through the same window()/at() the HTTP
	// path uses. (The vector is the test's; the product never builds one.)
	std::vector<DropProbe::Record> recentOf(const DropProbe& probe)
	{
		std::vector<DropProbe::Record> out;
		uint32_t first = 0, end = 0;
		probe.window(first, end);
		for (uint32_t seq = first; seq != end; ++seq)
		{
			DropProbe::Record r;
			if (probe.at(seq, r)) out.push_back(r);
		}
		return out;
	}

	void note(DropProbe& p, DropProbe::Reason r, const sockaddr_in& a, std::string_view bytes)
	{
		p.note(r, a.sin_addr.s_addr, a.sin_port, bytes);
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

	const auto drops = recentOf(handler.getDropProbe());
	ASSERT_EQ(drops.size(), 2u);
	EXPECT_EQ(drops[0].reason, DropProbe::Reason::Invalid);
	EXPECT_EQ(drops[0].ip, phone.sin_addr.s_addr);
	EXPECT_EQ(drops[0].port, phone.sin_port);
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
	for (const auto& d : recentOf(handler.getDropProbe()))
	{
		if (d.reason == DropProbe::Reason::Rate)
		{
			sawRate = true;
			EXPECT_EQ(d.ip, src.sin_addr.s_addr);
			ASSERT_EQ(d.headLen, DropProbe::kHeadBytes);
			EXPECT_EQ(std::string(reinterpret_cast<const char*>(d.head.data()), 7), "OPTIONS");
		}
	}
	EXPECT_TRUE(sawRate);
}

// A reader that races the writer never gets a stale slot: once a sequence
// number has been evicted, at() refuses it rather than returning its successor.
TEST(DropProbe, EvictedSequenceIsRefusedNotAliased)
{
	DropProbe probe;
	const sockaddr_in src = addr("10.0.0.3", 5060);
	note(probe, DropProbe::Reason::Invalid, src, "first");
	uint32_t first = 0, end = 0;
	probe.window(first, end);
	ASSERT_EQ(end - first, 1u);
	for (std::size_t i = 0; i < DropProbe::kRingSize; ++i) note(probe, DropProbe::Reason::Rate, src, "later");

	DropProbe::Record r;
	EXPECT_FALSE(probe.at(first, r)) << "seq " << first << " was overwritten and must not be served";
	EXPECT_TRUE(probe.at(first + 1, r));
	EXPECT_EQ(r.seq, first + 1);
	EXPECT_FALSE(probe.at(first + 1 + DropProbe::kRingSize, r)) << "not written yet";
}

// Bounded: the ring keeps the newest kRingSize, oldest first, and the counts
// keep counting past it.
TEST(DropProbe, RingKeepsTheNewestAndCountsKeepGoing)
{
	DropProbe probe;
	const sockaddr_in src = addr("10.0.0.1", 5060);
	const std::size_t total = DropProbe::kRingSize + 5;
	for (std::size_t i = 0; i < total; ++i) note(probe, DropProbe::Reason::Invalid, src, "x");

	EXPECT_EQ(probe.invalidCount(), total);
	const auto drops = recentOf(probe);
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
	note(probe, DropProbe::Reason::Invalid, src, "warm");   // first-use effects, if any

	AllocGuard guard;
	for (int i = 0; i < 3 * static_cast<int>(DropProbe::kRingSize); ++i)
	{
		note(probe, DropProbe::Reason::Invalid, src, std::string_view());
		note(probe, DropProbe::Reason::Rate, src, "\r\n\r\n");
		note(probe, DropProbe::Reason::Invalid, src, big);
	}
	EXPECT_EQ(guard.delta(), 0u) << "note() allocated";

	// The reader side too: /api/status copies one Record at a time.
	AllocGuard readGuard;
	uint32_t first = 0, end = 0;
	probe.window(first, end);
	uint32_t read = 0;
	for (uint32_t seq = first; seq != end; ++seq)
	{
		DropProbe::Record r;
		if (probe.at(seq, r)) ++read;
	}
	EXPECT_EQ(readGuard.delta(), 0u) << "window()/at() allocated";
	EXPECT_EQ(read, DropProbe::kRingSize);

	const auto drops = recentOf(probe);
	EXPECT_EQ(drops.back().len, 3000u);
	EXPECT_EQ(drops.back().headLen, DropProbe::kHeadBytes);
}

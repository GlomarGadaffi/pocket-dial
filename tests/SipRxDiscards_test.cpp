// SipRxDiscards_test.cpp — issues #443 and #444: nothing the SIP receive path
// throws away goes uncounted, and nothing truncated is parsed as whole.
//
//   #444: a datagram longer than UdpServer::BUFFER_SIZE used to be cut to the
//         buffer by recvfrom() and handed on as if complete (a cut SDP parsed
//         as a whole INVITE). It is now detected (recvmsg() + MSG_TRUNC),
//         refused, and counted as `oversize` with its real length.
//   #443 S1: when the message pool and its bounded heap fallback are spent,
//         SipServer::onNewMessage() dropped the datagram with no count. Now
//         `no_pool`.
//   #443 S2: a failed receive was skipped silently. Now counted with its errno,
//         while the SO_RCVTIMEO idle wake (EAGAIN) is NOT -- an idle board must
//         not count up.
//   Also: a 0-byte datagram was skipped silently; it now counts as `invalid`
//   AND in packetsDropped, so #430's invalid + rate == packetsDropped holds.
//
// Two levels: UdpServer on its own (exact sizes at the boundary, the idle
// wake), then a real SipServer end to end (socket -> UdpServer -> SipServer ->
// RequestsHandler's DropProbe), including a genuinely exhausted pool.

#include <gtest/gtest.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "DropProbe.hpp"
#include "PoolConfig.hpp"
#include "RequestsHandler.hpp"
#include "SipServer.hpp"
#include "UdpServer.hpp"

#if !defined(_WIN32) && !defined(_WIN64)   // POSIX host: real loopback UDP

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace
{
	constexpr int kUdpPort = 25443;   // UdpServer-level tests
	constexpr int kSipPort = 25444;   // SipServer end-to-end tests

	void sendDatagram(int port, const std::string& bytes)
	{
		const int s = ::socket(AF_INET, SOCK_DGRAM, 0);
		ASSERT_GE(s, 0);
		sockaddr_in to{};
		to.sin_family = AF_INET;
		to.sin_port = htons(static_cast<uint16_t>(port));
		to.sin_addr.s_addr = inet_addr("127.0.0.1");
		const ssize_t n = ::sendto(s, bytes.data(), bytes.size(), 0,
			reinterpret_cast<const sockaddr*>(&to), sizeof(to));
		::close(s);
		ASSERT_EQ(n, static_cast<ssize_t>(bytes.size()));
	}

	std::string pattern(size_t n)
	{
		std::string s(n, '\0');
		for (size_t i = 0; i < n; ++i) s[i] = static_cast<char>('A' + (i * 7) % 26);
		return s;
	}

	// Everything a UdpServer hands out, in order, waitable.
	struct Recorder
	{
		struct Event { bool delivered; UdpServer::Discard what; std::string bytes; size_t fullLen; int err; };
		std::mutex m;
		std::condition_variable cv;
		std::vector<Event> events;

		void push(Event e)
		{
			{ std::lock_guard<std::mutex> lk(m); events.push_back(std::move(e)); }
			cv.notify_all();
		}
		bool waitFor(size_t n, std::chrono::milliseconds t = std::chrono::milliseconds(2000))
		{
			std::unique_lock<std::mutex> lk(m);
			return cv.wait_for(lk, t, [&] { return events.size() >= n; });
		}
	};

	template <class F>
	bool eventually(F pred, std::chrono::milliseconds t = std::chrono::milliseconds(2000))
	{
		const auto until = std::chrono::steady_clock::now() + t;
		while (std::chrono::steady_clock::now() < until)
		{
			if (pred()) return true;
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
		}
		return pred();
	}

	std::string registerRaw(const std::string& callId)
	{
		return "REGISTER sip:127.0.0.1 SIP/2.0\r\n"
		       "Via: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bK" + callId + "\r\n"
		       "From: <sip:100@127.0.0.1>;tag=1\r\n"
		       "To: <sip:100@127.0.0.1>\r\n"
		       "Call-ID: " + callId + "\r\n"
		       "CSeq: 1 REGISTER\r\n"
		       "Contact: <sip:100@127.0.0.1:5070>\r\n"
		       "Content-Length: 0\r\n\r\n";
	}
}

TEST(UdpServerRx, OversizeIsRefusedWithItsRealLengthAndTheBoundaryIsDelivered)
{
	Recorder rec;
	UdpServer server("127.0.0.1", kUdpPort,
		[&](std::string_view v, sockaddr_in) {
			rec.push({ true, UdpServer::Discard::Empty, std::string(v), v.size(), 0 });
		},
		[&](UdpServer::Discard what, std::string_view v, sockaddr_in, size_t fullLen, int err) {
			rec.push({ false, what, std::string(v), fullLen, err });
		});
	server.startReceive();

	const size_t B = static_cast<size_t>(UdpServer::BUFFER_SIZE);
	const std::vector<size_t> sizes = { 100, B, B + 1, 3000, 0 };
	for (size_t n : sizes) sendDatagram(kUdpPort, pattern(n));
	ASSERT_TRUE(rec.waitFor(sizes.size())) << "only " << rec.events.size() << " events";

	std::lock_guard<std::mutex> lk(rec.m);
	ASSERT_EQ(rec.events.size(), sizes.size());
	// 100 B and exactly BUFFER_SIZE: delivered whole.
	EXPECT_TRUE(rec.events[0].delivered);
	EXPECT_EQ(rec.events[0].bytes, pattern(100));
	EXPECT_TRUE(rec.events[1].delivered) << "a datagram of exactly BUFFER_SIZE fits";
	EXPECT_EQ(rec.events[1].bytes, pattern(B));
	// One byte over, and well over: refused, never delivered truncated.
	for (size_t i : { 2u, 3u })
	{
		SCOPED_TRACE(::testing::Message() << "size " << sizes[i]);
		EXPECT_FALSE(rec.events[i].delivered) << "a truncated datagram must not be delivered";
		EXPECT_EQ(rec.events[i].what, UdpServer::Discard::Oversize);
		EXPECT_EQ(rec.events[i].fullLen, sizes[i]) << "the real length, not the buffer's";
		EXPECT_EQ(rec.events[i].bytes, pattern(sizes[i]).substr(0, B)) << "the first BUFFER_SIZE bytes";
	}
	// Zero bytes: a discard, not a delivery and not silence.
	EXPECT_FALSE(rec.events[4].delivered);
	EXPECT_EQ(rec.events[4].what, UdpServer::Discard::Empty);
}

TEST(UdpServerRx, TheReceiveTimeoutsIdleWakeIsNotAnError)
{
	std::atomic<int> discards{0};
	{
		UdpServer server("127.0.0.1", kUdpPort,
			[](std::string_view, sockaddr_in) {},
			[&](UdpServer::Discard, std::string_view, sockaddr_in, size_t, int) { ++discards; });
		server.startReceive();
		// Past one 500 ms SO_RCVTIMEO wake, with nothing sent.
		std::this_thread::sleep_for(std::chrono::milliseconds(700));
	}
	EXPECT_EQ(discards.load(), 0) << "an idle socket must not count receive errors";

	EXPECT_TRUE(UdpServer::isIdleWake(EAGAIN));
	EXPECT_TRUE(UdpServer::isIdleWake(EWOULDBLOCK));
	EXPECT_TRUE(UdpServer::isIdleWake(EINTR));
	EXPECT_FALSE(UdpServer::isIdleWake(ENOMEM)) << "lwIP's out-of-buffers is a real error";
	EXPECT_FALSE(UdpServer::isIdleWake(EBADF));
}

TEST(DropProbeRx, RecvErrorsCountWithTheirErrnoAndLeaveNoRingRecord)
{
	DropProbe probe;
	probe.noteRecvError(ENOMEM);
	probe.noteRecvError(EBADF);
	EXPECT_EQ(probe.recvErrorCount(), 2u);
	EXPECT_EQ(probe.lastRecvErrno(), EBADF);
	uint32_t first = 0, end = 0;
	probe.window(first, end);
	EXPECT_EQ(first, end) << "a failed receive has no source or bytes to record";
	EXPECT_STREQ(DropProbe::reasonName(DropProbe::Reason::NoPool), "no_pool");
	EXPECT_STREQ(DropProbe::reasonName(DropProbe::Reason::Oversize), "oversize");
}

class SipRxEndToEnd : public ::testing::Test
{
protected:
	SipServer server{"127.0.0.1", kSipPort, 0};
	RequestsHandler& h() { return server.getHandler(); }
	const DropProbe& probe() { return h().getDropProbe(); }

	// The newest ring record, or false.
	bool newest(DropProbe::Record& out)
	{
		uint32_t first = 0, end = 0;
		probe().window(first, end);
		return first != end && probe().at(end - 1, out);
	}
};

TEST_F(SipRxEndToEnd, OversizeDatagramIsCountedAndNeverReachesTheParser)
{
	const uint64_t processed = h().getPacketsProcessed();
	const uint64_t dropped = h().getPacketsDropped();
	// A plausible REGISTER padded past the buffer: truncated, it would still
	// parse (the headers survive) -- which is exactly the bug.
	std::string big = registerRaw("oversize-1");
	big.insert(big.size() - 4, "\r\nX-Pad: " + std::string(3000, 'p'));
	sendDatagram(kSipPort, big);

	ASSERT_TRUE(eventually([&] { return probe().count(DropProbe::Reason::Oversize) == 1; }));
	DropProbe::Record r;
	ASSERT_TRUE(newest(r));
	EXPECT_EQ(r.reason, DropProbe::Reason::Oversize);
	EXPECT_EQ(r.len, big.size()) << "recorded with its real length";
	EXPECT_EQ(r.ip, inet_addr("127.0.0.1"));
	EXPECT_EQ(h().getPacketsProcessed(), processed) << "never handed to handle()";
	EXPECT_EQ(h().getPacketsDropped(), dropped) << "not part of handle()'s packetsDropped";
}

TEST_F(SipRxEndToEnd, EmptyDatagramCountsAsInvalidAndKeepsThe430Sum)
{
	const uint64_t invalid = h().getDroppedInvalid();
	const uint64_t dropped = h().getPacketsDropped();
	sendDatagram(kSipPort, "");
	ASSERT_TRUE(eventually([&] { return h().getDroppedInvalid() == invalid + 1; }));
	EXPECT_EQ(h().getPacketsDropped(), dropped + 1);
	EXPECT_EQ(h().getDroppedInvalid() + h().getDroppedRate(), h().getPacketsDropped())
		<< "#430: invalid + rate == packetsDropped";
}

TEST_F(SipRxEndToEnd, PoolExhaustionDropIsCountedAsNoPool)
{
	// Genuinely spend the process-global pool and its heap fallback (as
	// RequestsHandler_pool_test does), so createMessage() fails for real.
	sockaddr_in src{};
	src.sin_family = AF_INET;
	src.sin_addr.s_addr = inet_addr("127.0.0.1");
	const uint64_t processed = h().getPacketsProcessed();
	{
		std::vector<std::shared_ptr<SipMessage>> held;
		const size_t cap = (POCKETDIAL_MSG_POOL + POCKETDIAL_MSG_HEAP_FALLBACK_MAX) * 4 + 16;
		for (size_t i = 0; i < cap; ++i)
		{
			auto m = RequestsHandler::getMessageFromPool(registerRaw("hold" + std::to_string(i)), src);
			if (!m) break;
			held.push_back(std::move(m));
		}
		ASSERT_EQ(RequestsHandler::getMessageFromPool(registerRaw("probe"), src), nullptr)
			<< "precondition: the pool is spent";

		sendDatagram(kSipPort, registerRaw("nopool-1"));
		ASSERT_TRUE(eventually([&] { return probe().count(DropProbe::Reason::NoPool) == 1; }));
		DropProbe::Record r;
		ASSERT_TRUE(newest(r));
		EXPECT_EQ(r.reason, DropProbe::Reason::NoPool);
		EXPECT_EQ(r.len, registerRaw("nopool-1").size());
		EXPECT_EQ(std::string(reinterpret_cast<const char*>(r.head.data()), r.headLen),
		          registerRaw("nopool-1").substr(0, DropProbe::kHeadBytes));
		EXPECT_EQ(h().getPacketsProcessed(), processed);
	}   // everything released before the next test draws on the shared pool
}

#endif

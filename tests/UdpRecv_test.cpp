// UdpRecv_test.cpp — issues #444 and #469: the one receive helper both UDP
// paths (SIP's UdpServer, RTP's RtpReceiver) use to tell a cut datagram from a
// whole one. Real loopback sockets, at the boundaries of an RTP-sized buffer:
// a datagram that fits exactly is whole; one byte more is TRUNCATED, reported
// with its real length (Linux, like lwIP, gives it), and the buffer holds its
// first `cap` bytes. The SIP side's end-to-end behaviour on top of this helper
// is pinned by SipRxDiscards_test.

#include <gtest/gtest.h>

#include <string>

#include "UdpRecv.hpp"

#if !defined(_WIN32) && !defined(_WIN64)

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace
{
	std::string pattern(size_t n)
	{
		std::string s(n, '\0');
		for (size_t i = 0; i < n; ++i) s[i] = static_cast<char>('a' + (i * 5) % 26);
		return s;
	}

	struct Loopback
	{
		int rx = -1, tx = -1;
		sockaddr_in rxAddr{};
		Loopback()
		{
			rx = ::socket(AF_INET, SOCK_DGRAM, 0);
			tx = ::socket(AF_INET, SOCK_DGRAM, 0);
			rxAddr.sin_family = AF_INET;
			rxAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
			rxAddr.sin_port = 0;   // ephemeral
			::bind(rx, reinterpret_cast<sockaddr*>(&rxAddr), sizeof(rxAddr));
			socklen_t l = sizeof(rxAddr);
			::getsockname(rx, reinterpret_cast<sockaddr*>(&rxAddr), &l);
			timeval tv{};
			tv.tv_usec = 200 * 1000;
			::setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		}
		~Loopback() { ::close(rx); ::close(tx); }
		void send(const std::string& b)
		{
			::sendto(tx, b.data(), b.size(), 0, reinterpret_cast<const sockaddr*>(&rxAddr), sizeof(rxAddr));
		}
	};
}

TEST(UdpRecv, WholeDatagramsUpToTheBufferAreNotTruncated)
{
	Loopback lb;
	constexpr size_t kCap = 512;   // RtpReceiver::MAX_DATAGRAM_BYTES
	char buf[kCap];
	for (size_t n : { size_t{1}, size_t{172}, kCap })
	{
		SCOPED_TRACE(n);
		lb.send(pattern(n));
		sockaddr_in from{};
		const udprecv::Result r = udprecv::recvDatagram(lb.rx, buf, kCap, &from);
		ASSERT_EQ(r.n, static_cast<int>(n));
		EXPECT_FALSE(r.truncated);
		EXPECT_EQ(std::string(buf, n), pattern(n));
		EXPECT_EQ(from.sin_addr.s_addr, inet_addr("127.0.0.1"));
	}
}

TEST(UdpRecv, OneByteOverIsTruncatedWithItsRealLength)
{
	Loopback lb;
	constexpr size_t kCap = 512;
	char buf[kCap];
	for (size_t n : { kCap + 1, size_t{652} /* G.711 at 80 ms ptime */, size_t{3000} })
	{
		SCOPED_TRACE(n);
		lb.send(pattern(n));
		const udprecv::Result r = udprecv::recvDatagram(lb.rx, buf, kCap, nullptr);   // no `from` needed
		EXPECT_TRUE(r.truncated) << "a cut datagram must be reported, not passed off as whole";
		EXPECT_EQ(r.n, static_cast<int>(n)) << "the real length";
		EXPECT_EQ(std::string(buf, kCap), pattern(n).substr(0, kCap)) << "the first cap bytes";
	}
}

TEST(UdpRecv, AnIdleTimeoutIsAnErrorThatIsAnIdleWake)
{
	Loopback lb;
	char buf[64];
	const udprecv::Result r = udprecv::recvDatagram(lb.rx, buf, sizeof(buf), nullptr);   // nothing sent
	EXPECT_LT(r.n, 0);
	EXPECT_FALSE(r.truncated);
	EXPECT_TRUE(udprecv::isIdleWake(r.err)) << "errno " << r.err;
}

#endif

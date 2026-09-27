#ifndef UDP_RCV_BUF_HPP
#define UDP_RCV_BUF_HPP

// ── Per-socket UDP receive caps (issue #496, #509 review) ─────────────────────
//
// With IPv4 reassembly on (CONFIG_LWIP_IP4_REASSEMBLY, sdkconfig.defaults), a
// COMPLETED datagram can be a chain of up to LWIP_IP_REASS_MAX_PBUFS (10)
// fragment pbufs, about 14.8 KB. IP_REASS_MAX_PBUFS bounds only the fragments
// still being reassembled; once a datagram completes, the only limit left is
// the socket's recvmbox (CONFIG_LWIP_UDP_RECVMBOX_SIZE entries, 32 here), i.e.
// ~470 KB per socket while its reader is slow -- or forever, for a bound socket
// nobody reads. CONFIG_LWIP_SO_RCVBUF=y plus these per-socket SO_RCVBUF values
// cap the queued PAYLOAD bytes per socket (lwIP api_msg.c recv_udp: a datagram
// that would take recv_avail past recv_bufsize is freed on arrival). lwIP's
// default recv_bufsize is INT_MAX, so the setsockopt is what makes the cap.
//
// ESP only. Host builds use the OS stack and never call these: a Linux
// SO_RCVBUF counts skb truesize, not payload, and would change host tests.

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "sdkconfig.h"
#include <sys/socket.h>

// Reassembly without the cap is the unbounded configuration the #509 review
// found. A tree whose existing sdkconfig kept LWIP_SO_RCVBUF off must fail
// here, not ship it.
#if defined(CONFIG_LWIP_IP4_REASSEMBLY) && !defined(CONFIG_LWIP_SO_RCVBUF)
#error "CONFIG_LWIP_IP4_REASSEMBLY needs CONFIG_LWIP_SO_RCVBUF=y (issue #496): see src/Helpers/UdpRcvBuf.hpp"
#endif

namespace udprcvbuf
{
	// SIP (UdpServer, port 5060). Sized so the mailbox of ordinary (<= 1 KB)
	// SIP messages fills before the byte cap binds, which keeps #78's burst
	// headroom, and never below 16 KB, so one datagram of the largest size
	// reassembly can produce (~14.8 KB) still reaches #468's oversize counter
	// instead of vanishing. 32 KB with the 32-entry mailbox, 16 KB with the
	// constrained profile's 6.
	constexpr int kSip = (CONFIG_LWIP_UDP_RECVMBOX_SIZE * 1024 > 16384)
		? CONFIG_LWIP_UDP_RECVMBOX_SIZE * 1024 : 16384;

	// RTP receive legs (RtpReceiver). A real RTP datagram is at most
	// RtpReceiver::MAX_DATAGRAM_BYTES (512); 8 KB holds 47 G.711 20 ms packets,
	// so for normal media the 32-entry mailbox still fills first.
	constexpr int kRtp = 8192;

	// A bound socket that is never read (RtpSender, HoldMusic, Syslog): whatever
	// arrives there would sit in its mailbox until close. Queue nothing. lwIP's
	// test is recv_avail + len > recv_bufsize, so a 0-LENGTH datagram still gets
	// in: on Ethernet it pins only its own minimum frame (the IPv4 input guard,
	// Ip4InputGuard.h, stops padding), ~3 KB for a full 32-entry mailbox.
	constexpr int kSendOnly = 0;

	// The captive-portal DNS server (main/wifi/DnsServer.cpp, SoftAP builds). A
	// query is one small datagram (<= 512 B classic, 4 KB with EDNS0).
	constexpr int kDns = 4096;

	// Returns false if the cap did not take. The caller logs it; the socket
	// still works, just without the bound.
	inline bool set(int sock, int bytes)
	{
#if defined(CONFIG_LWIP_SO_RCVBUF)
		return setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes)) == 0;
#else
		// Only reachable with reassembly OFF too (the #error above), where a
		// datagram is at most one MTU and the mailbox bound is what it always
		// was. Nothing to cap, nothing to report.
		(void)sock;
		(void)bytes;
		return true;
#endif
	}
}
#endif

#endif

#pragma once

// udprecv -- receive ONE UDP datagram and say whether it was cut short
// (issues #444 and #469). The single copy of this logic: UdpServer (SIP) and
// RtpReceiver (RTP) both call it.
//
// For UDP, every stack silently discards whatever does not fit the buffer. The
// trap is in how each one REPORTS it:
//   * lwIP's recvfrom() returns min(len, datagram) and says nothing -- a cut
//     datagram is indistinguishable from a whole one. lwIP's recvmsg() returns
//     the REAL datagram length and sets MSG_TRUNC in msg_flags -- but
//     lwip_recvmsg() REJECTS any input flag except MSG_PEEK|MSG_DONTWAIT (it
//     fails with -1), so MSG_TRUNC must never be passed IN on lwIP.
//   * Linux recvmsg() sets MSG_TRUNC in msg_flags too, and returns the real
//     length only when MSG_TRUNC is passed in -- so it is, there.
//   * Winsock reports a cut datagram as the error WSAEMSGSIZE, with the first
//     `cap` bytes filled; its real length is unknown.

#include <cerrno>
#include <cstddef>
#include <cstring>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <sys/socket.h>
#include <lwip/sockets.h>
#elif defined(__linux__)
#include <sys/socket.h>
#include <netinet/in.h>
#elif defined _WIN32 || defined _WIN64
#include <WinSock2.h>
#endif

namespace udprecv
{
	struct Result
	{
		// Bytes received; for a truncated datagram, its REAL length where the
		// stack reports it (lwIP, Linux) and `cap` where it cannot (Winsock).
		// Negative on a failed receive (see err).
		int  n = 0;
		bool truncated = false;   // the datagram was longer than `cap`; buf holds its first `cap` bytes
		int  err = 0;             // errno / WSAGetLastError() when n < 0
	};

	// `from` may be null. Never allocates.
	inline Result recvDatagram(int sock, void* buf, size_t cap, sockaddr_in* from)
	{
		Result r;
#if defined(__linux__) || defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		struct iovec iov;
		iov.iov_base = buf;
		iov.iov_len = cap;
		struct msghdr msg;
		std::memset(&msg, 0, sizeof(msg));
		msg.msg_name = from;
		msg.msg_namelen = from ? sizeof(*from) : 0;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
#if defined(__linux__) && !defined(ESP_PLATFORM)
		const int flags = MSG_TRUNC;   // real length on Linux; never on lwIP (see above)
#else
		const int flags = 0;
#endif
		r.n = static_cast<int>(recvmsg(sock, &msg, flags));
		if (r.n < 0)
			r.err = errno;
		else
			r.truncated = (msg.msg_flags & MSG_TRUNC) != 0;
#elif defined _WIN32 || defined _WIN64
		int fromLen = from ? static_cast<int>(sizeof(*from)) : 0;
		r.n = recvfrom(static_cast<SOCKET>(sock), static_cast<char*>(buf), static_cast<int>(cap), 0,
			reinterpret_cast<sockaddr*>(from), from ? &fromLen : nullptr);
		if (r.n == SOCKET_ERROR)
		{
			r.err = WSAGetLastError();
			if (r.err == WSAEMSGSIZE) { r.truncated = true; r.n = static_cast<int>(cap); r.err = 0; }
		}
#endif
		return r;
	}

	// True for the error a receive returns when nothing arrived before the
	// SO_RCVTIMEO wake (or on a signal) -- idle, not a failure.
	inline bool isIdleWake(int err)
	{
#if defined _WIN32 || defined _WIN64
		return err == WSAETIMEDOUT || err == WSAEWOULDBLOCK || err == WSAEINTR;
#else
		return err == EAGAIN || err == EWOULDBLOCK || err == EINTR;
#endif
	}
}

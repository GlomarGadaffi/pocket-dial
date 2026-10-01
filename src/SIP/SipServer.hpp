#ifndef SIP_SERVER_HPP
#define SIP_SERVER_HPP

#include "UdpServer.hpp"
#include "RequestsHandler.hpp"
#include "Session.hpp"
#include "SipMessageFactory.hpp"

#include <array>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>

#if !defined(ESP_PLATFORM) && !defined(ARDUINO)
#include <thread>
#include <atomic>
#endif

class SipServer
{
public:
	SipServer(std::string ip, int port = 5060, int httpPort = 80);
	~SipServer();

	// Dashboard access to the SIP engine state
	RequestsHandler& getHandler() { return _handler; }

	// Issue #826: SIP PnP. Called from the board's 1 s SIP loop (next to
	// tick()). Opens the 224.0.1.75:5060 socket while PnP is on, closes it
	// while off, and answers what the responder says to. Non-blocking, no task
	// of its own, no allocation. A no-op off the board.
	void pollPnp();

private:
	// Issue #81: `data` is a zero-copy view into UdpServer::receiveLoop()'s stack
	// buffer, valid only for the duration of this call — see UdpServer::
	// OnNewMessageEvent's comment. This function runs entirely synchronously
	// (createMessage() copies what it parses out of `data` before returning, and
	// the raw view handed to handle() below is consumed before handle() returns),
	// so it never needs to outlive the call.
	void onNewMessage(std::string_view data, sockaddr_in src);
	// Issue #443/#444: what the receive loop threw away, counted on the
	// handler's DropProbe (same view-lifetime rule as onNewMessage).
	void onDiscard(UdpServer::Discard what, std::string_view bytes, sockaddr_in src,
	               size_t fullLen, int err);
	void onHandled(const sockaddr_in& dest, std::shared_ptr<SipMessage> message);

	// #462 (#284 rank 2): one reusable send buffer instead of a fresh
	// toString() string per outbound message (300-1500 B each).
	//
	// onHandled() is reached from THREE threads -- the UDP receive task
	// (handle()), the tick task (tick()) and the HTTP task (sendMessageTo()) --
	// so the buffer has its own leaf mutex. Leaf: nothing else is ever locked
	// while it is held, and the socket send takes none of ours, so it cannot
	// take part in a lock-order cycle. It also serialises the three threads'
	// sends on the socket, which they previously entered concurrently.
	//
	// Declared BEFORE _socket on purpose: members are destroyed in reverse
	// order, and _socket's receive thread is what calls onHandled(). Declared
	// after it, these would be destroyed while that thread could still use them.
	std::mutex  _sendMutex;
	std::string _sendBuf;

	UdpServer _socket;
	RequestsHandler _handler;
	SipMessageFactory _messagesFactory;

	// Issue #826: the PnP group socket and its receive buffer (fixed, here
	// rather than on the SIP task's stack). Only the SIP task touches them.
	static constexpr int kPnpDrainPerPoll = 8;
	static constexpr uint32_t kPnpRetrySeconds = 30;
	bool openPnpSocket(uint32_t now);
	void closePnpSocket();
	void sendPnp(const sockaddr_in& dest, std::string_view msg);
	uint32_t _localIp = 0;           // network byte order
	int _pnpSock = -1;
	uint32_t _pnpRetryAt = 0;
	// A ua-profile SUBSCRIBE is ~500 B. A longer datagram is cut here, and the
	// parser refuses one whose headers never end (PnpProfile.hpp).
	static constexpr size_t kPnpRxBytes = 1024;
	std::array<char, kPnpRxBytes> _pnpRx{};

#if !defined(ESP_PLATFORM) && !defined(ARDUINO)
	std::thread _tickThread;
	std::atomic<bool> _tickRunning{false};
	void tickLoop();
#endif
};
#endif

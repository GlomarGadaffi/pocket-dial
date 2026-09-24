#ifndef SIP_SERVER_HPP
#define SIP_SERVER_HPP

#include "UdpServer.hpp"
#include "RequestsHandler.hpp"
#include "Session.hpp"
#include "SipMessageFactory.hpp"

#include <mutex>
#include <string>

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

private:
	// Issue #81: `data` is a zero-copy view into UdpServer::receiveLoop()'s stack
	// buffer, valid only for the duration of this call — see UdpServer::
	// OnNewMessageEvent's comment. This function runs entirely synchronously
	// (createMessage() copies what it parses out of `data` before returning, and
	// the raw view handed to handle() below is consumed before handle() returns),
	// so it never needs to outlive the call.
	void onNewMessage(std::string_view data, sockaddr_in src);
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

#if !defined(ESP_PLATFORM) && !defined(ARDUINO)
	std::thread _tickThread;
	std::atomic<bool> _tickRunning{false};
	void tickLoop();
#endif
};
#endif

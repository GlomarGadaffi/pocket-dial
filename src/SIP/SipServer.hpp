#ifndef SIP_SERVER_HPP
#define SIP_SERVER_HPP

#include "UdpServer.hpp"
#include "RequestsHandler.hpp"
#include "Session.hpp"
#include "SipMessageFactory.hpp"

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
	// Issue #443/#444: what the receive loop threw away, counted on the
	// handler's DropProbe (same view-lifetime rule as onNewMessage).
	void onDiscard(UdpServer::Discard what, std::string_view bytes, sockaddr_in src,
	               size_t fullLen, int err);
	void onHandled(const sockaddr_in& dest, std::shared_ptr<SipMessage> message);

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

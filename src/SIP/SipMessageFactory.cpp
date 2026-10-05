#include "SipMessageFactory.hpp"
#include "RequestsHandler.hpp"

std::optional<std::shared_ptr<SipMessage>> SipMessageFactory::createMessage(std::string_view message, sockaddr_in src)
{
	auto msg = RequestsHandler::getMessageFromWire(message, src);   // #838: a datagram keeps 64 lines
	if (!msg)
	{
		return std::nullopt;
	}
	return msg;
}

bool SipMessageFactory::containsSdp(const std::string& message) const
{
	return message.find(SDP_CONTENT_TYPE) != std::string::npos;
}

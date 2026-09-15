#include "EmergencyNotifier.hpp"

#include <sstream>

#include "IDGen.hpp"
#include "ServiceExtensions.hpp"
#include "SipClient.hpp"
#include "SipMessage.hpp"
#include "SipWireUtil.hpp"
#include "Syslog.hpp"

namespace pbx
{

std::string formatE911Notification(bool isTest, std::string_view fromExt,
	std::string_view dialed, bool hadTrunkPrefix, bool routed,
	const E911Config& cfg)
{
	std::string out;
	out.reserve(200);

	// TEST first, so a 933 can never be skim-read as a live emergency. This is
	// the whole reason 933 is tracked separately rather than folded in.
	out += isTest ? "TEST: 933" : "EMERGENCY: 911";
	out += " dialed by ext ";
	out += std::string(fromExt);

	// Only worth saying when it differs from the bare number, but then it is
	// worth saying exactly: it is the difference between a user who dialed 911
	// and one who dialed 9 first, and it tells an operator their trunk-access
	// habit is in play.
	if (hadTrunkPrefix)
	{
		out += " (as ";
		out += std::string(dialed);
		out += ")";
	}

	out += routed ? " - ROUTED TO TRUNK" : " - NOT ROUTED (no trunk connected)";

	// An absent callback is stated rather than omitted: a blank field reads as
	// "nothing to report", and here it means the opposite.
	out += " - callback ";
	out += cfg.callback.empty() ? "not configured" : cfg.callback;

	if (!cfg.location.empty())
	{
		out += " - ";
		out += cfg.location;
	}

	// The MESSAGE path caps a body at 512 bytes; trim here so the syslog line
	// and the SIP body are the same text rather than diverging silently.
	if (out.size() > 512)
	{
		out.resize(512);
	}
	return out;
}

} // namespace pbx

std::shared_ptr<SipMessage> EmergencyNotifier::buildNotifyMessage(const std::string& ext,
	const std::string& text, sockaddr_in& addrOut)
{
	auto client = _env.findRegistered(ext);
	if (!client)
	{
		// Not registered: nothing to send to. Not an error — a notify extension
		// whose phone is unplugged must not disturb anything on this path.
		return nullptr;
	}

	addrOut = client->getAddress();
	const std::string destIpPort = sipwire::addrToIpPort(addrOut);
	const std::string activeIp   = _env.localIp();
	const std::string srcIpPort  = activeIp + ":" + std::to_string(_env.serverPort());

	const std::string callId  = IDGen::GenerateID(16) + "@" + activeIp;
	const std::string branch  = "z9hG4bK" + IDGen::GenerateID(12);
	const std::string fromTag = IDGen::GenerateID(9);

	std::ostringstream ss;
	ss << "MESSAGE sip:" << ext << "@" << destIpPort << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << branch << "\r\n"
	   << "From: \"Emergency\" <sip:" << pbx::kServicePbx << "@" << srcIpPort << ">;tag=" << fromTag << "\r\n"
	   << "To: <sip:" << ext << "@" << activeIp << ">\r\n"
	   << "Call-ID: " << callId << "\r\n"
	   << "CSeq: 1 MESSAGE\r\n"
	   << "Max-Forwards: 70\r\n"
	   << "User-Agent: pocket-dial\r\n"
	   << "Content-Type: text/plain\r\n"
	   << "Content-Length: " << text.size() << "\r\n\r\n"
	   << text;

	auto msg = _env.messageFromPool(ss.str(), addrOut);
	if (!msg)
	{
		// Pool exhausted: drop this one notification (#101A). Deliberately NOT
		// propagated as a failure — the call leg is already enqueued and must
		// not be affected by how many notifications fit.
		return nullptr;
	}
	msg->syncContentLength();
	return msg;
}

std::size_t EmergencyNotifier::notify(const pbx::E911Config& cfg, bool isTest,
	std::string_view fromExt, std::string_view dialed,
	bool hadTrunkPrefix, bool routed)
{
	const std::string text =
		pbx::formatE911Notification(isTest, fromExt, dialed, hadTrunkPrefix, routed, cfg);

	// 1. The record. Unconditional and unconfigurable: an operator can leave
	//    notifyExts empty, but they cannot turn off the fact that a 911 dial is
	//    written down. Alert (severity 1) rather than Emergency (0) -- 0 is
	//    "system is unusable", which this is not; Alert is "action must be taken
	//    immediately", which this is exactly.
	//
	//    Syslog::send never blocks, never throws and no-ops when unconfigured,
	//    so it is safe on the SIP thread under the engine mutex (Syslog.hpp).
	Syslog::send(Syslog::Severity::Alert, std::string("pbx-911"), text);

	// Also into the engine's own log so it lands in the UART/dashboard record
	// for a deployment with no syslog collector configured.
	_env.log(text, true);

	// 2. The notifications. Every one is independent and every failure is
	//    swallowed: an unregistered extension or an exhausted pool costs that
	//    one notification and nothing else.
	std::size_t enqueued = 0;
	std::size_t considered = 0;
	for (const std::string& ext : cfg.notifyExts)
	{
		if (considered++ >= pbx::kMaxE911NotifyExts)
		{
			// Bounded regardless of what got persisted. A config written by an
			// older/newer build cannot turn one 911 dial into an unbounded burst
			// of pooled messages on the emergency path.
			break;
		}
		if (ext.empty())
		{
			continue;
		}

		sockaddr_in addr{};
		auto msg = buildNotifyMessage(ext, text, addr);
		if (!msg)
		{
			continue;
		}
		_env.enqueue(addr, std::move(msg));
		++enqueued;
	}

	return enqueued;
}

#include "EmergencyNotifier.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

#include "IDGen.hpp"
#include "ServiceExtensions.hpp"
#include "SipClient.hpp"
#include "SipMessage.hpp"
#include "SipWireUtil.hpp"
#include "Syslog.hpp"
#include "Witness.hpp"

namespace pbx
{

std::string formatE911Notification(bool isTest, std::string_view fromExt,
	std::string_view dialed, bool hadTrunkPrefix, bool routed,
	const E911Config& cfg, std::string_view note, bool callUp)
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

	// desmo, #878: say what failed. NOT ROUTED names the route; a call the
	// trunk took after the anchor failed says that too. The caller knows which;
	// "no trunk available" is only the fallback wording.
	if (callUp)
	{
		// #906: connected, and the audio to the anchor keeps failing. Neither of
		// the two wordings below: the call was not hung up and was not refused.
		out += " - CALL STILL UP, AUDIO DEGRADED";
		if (!note.empty())
		{
			out += " (";
			out += note;
			out += ")";
		}
	}
	else if (routed)
	{
		out += " - ROUTED TO TRUNK";
		if (!note.empty())
		{
			out += " (";
			out += note;
			out += ")";
		}
	}
	else
	{
		out += " - NOT ROUTED (";
		out += note.empty() ? std::string_view("no trunk available") : note;
		out += ")";
	}

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
		// Trim to a UTF-8 CODEPOINT boundary, not a byte one. `location` is
		// operator free text and may be non-ASCII; a half-written multi-byte
		// sequence renders as a replacement character or garbage in whatever
		// reads the notification, which is the one thing this text must not do.
		std::size_t cut = 512;
		while (cut > 0 && (static_cast<unsigned char>(out[cut]) & 0xC0) == 0x80)
		{
			--cut;   // inside a sequence: back up to its lead byte
		}
		out.resize(cut);
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
	const std::string activeIp   = _env.localIp();
	const std::string srcIpPort  = activeIp + ":" + std::to_string(_env.serverPort());

	const std::string callId  = IDGen::GenerateID(16) + "@" + activeIp;
	const std::string branch  = "z9hG4bK" + IDGen::GenerateID(12);
	const std::string fromTag = IDGen::GenerateID(9);

	std::ostringstream ss;
	// The registered Contact URI with its parameters: a Snom answers 404 to the
	// bare form without its ;line= (#904 review). Bare only when none is stored.
	PD_WITNESS_I("e911", "notify MESSAGE Request-URI: %s",
		client->getContactUri().empty() ? "bare (no Contact stored)" : "registered Contact");
	ss << "MESSAGE " << sipwire::memberRequestUri(*client) << " SIP/2.0\r\n"
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

void EmergencyNotifier::flushStaged()
{
	while (_staged.load())
	{
		// try_lock, not lock: the flusher that holds _sendMutex is mid-send, and a
		// second one (handle() on the receive thread) must not queue behind a UDP
		// send. It can leave, because the holder looks at _staged again after it
		// unlocks (the loop), so a frame staged before this try_lock failed is
		// still picked up.
		std::unique_lock<std::mutex> sending(_sendMutex, std::try_to_lock);
		if (!sending.owns_lock())
		{
			return;
		}

		unsigned replaced = 0;
		{
			std::lock_guard<std::mutex> lock(_slotMutex);
			if (!_staged.load())
			{
				// Another flusher took it between the loop test and here. Look again
				// rather than leave: a notify that stages in the window before this
				// unlock, whose flusher try_lock failed against our hold, would be
				// stranded until the next pass.
				continue;
			}
			// Taken and cleared in one step, before the send: whoever sends a frame
			// has emptied the slot, so no other flusher can send it again.
			std::memcpy(_sendBuf, _slot, sizeof(_sendBuf));
			replaced = _slotOverwritten;
			_slotOverwritten = 0;
			_staged.store(false);
		}

		// The blocking part: Syslog::send holds the syslog mutex across a UDP send().
		// No engine lock and no slot lock is held here, so notify() is never behind it.
		Syslog::send(Syslog::Severity::Alert, "pbx-911", _sendBuf);

		if (replaced != 0)
		{
			// After the send, off the engine lock: a witness is console I/O. The
			// replaced alerts' text is in the engine log (notify() step 1b).
			PD_WITNESS_W("e911", "pbx-911 alert overwritten before it was sent (%u replaced)", replaced);
		}
	}
}

std::size_t EmergencyNotifier::notify(const pbx::E911Config& cfg, bool isTest,
	std::string_view fromExt, std::string_view dialed,
	bool hadTrunkPrefix, bool routed, std::string_view note, bool callUp)
{
	const std::string text =
		pbx::formatE911Notification(isTest, fromExt, dialed, hadTrunkPrefix, routed, cfg, note, callUp);

	// 1. The record. Unconditional and unconfigurable: an operator can leave
	//    notifyExts empty, but they cannot turn off the fact that a 911 dial is
	//    written down. Alert (severity 1) rather than Emergency (0) -- 0 is
	//    "system is unusable", which this is not; Alert is "action must be taken
	//    immediately", which this is exactly.
	//
	//    STAGED, not sent: Syslog::send holds the syslog mutex across a blocking
	//    UDP send() (and the log-drain task holds it for its own), and this runs
	//    under the engine mutex. flushStaged() sends it after the lock is
	//    released. One slot: a second notify() before the flush replaces this
	//    text, and flushStaged() says so; the text below is the record of it.
	{
		std::lock_guard<std::mutex> lock(_slotMutex);
		if (_staged.load() && _slotOverwritten < UINT8_MAX)
		{
			++_slotOverwritten;
		}
		const std::size_t n = std::min(text.size(), sizeof(_slot) - 1);
		std::memcpy(_slot, text.data(), n);
		_slot[n] = '\0';
		_staged.store(true);
	}

	// 1b. Also into the engine's own log so it lands in the UART/dashboard record
	//     for a deployment with no syslog collector configured, and so a text the
	//     slot replaces is still on record.
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

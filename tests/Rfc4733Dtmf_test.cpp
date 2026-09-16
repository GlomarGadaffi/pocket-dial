// Rfc4733Dtmf_test.cpp — issue #199 item 3: DTMF over RTP actually reaching the
// feature-code machine.
//
// TelephoneEvent_test.cpp already covers the RFC 4733 *parser* thoroughly — the
// four fields, network byte order, the sixteen symbols, the SDP payload-type
// read and echo. All of that existed and all of it worked. What did not exist
// was any wiring: nothing ever called setDtmfPayloadType(), so `_dtmfPt` stayed
// kDtmfPayloadTypeUnset and the receive branch never ran, and nothing ever set a
// sink, so a decoded digit had nowhere to go.
//
// The consequence was that on a stock-configured handset the entire feature-code
// surface (*8 pickup, *60/*72/*73/*80/*69) was unreachable, because RFC 4733 is
// the DEFAULT DTMF mode on most desk phones and softphones while SIP INFO — the
// only mode that worked — generally has to be selected by hand.
//
// So this file tests the two things that were missing rather than the parser:
// the dispatch (one report per key press, off a burst of packets, which on host
// is only reachable because dispatchDtmf() was split out of the socket loop) and
// the end-to-end path (a digit captured on a media task reaching onDigit() and
// doing the same thing an INFO digit does).

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "ConferenceRoom.hpp"
#include "RequestsHandler.hpp"
#include "RtpReceiver.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	constexpr const char* kServerIp = "192.168.47.1";
	constexpr uint8_t     kDtmfPt   = 101;   // what nearly every phone offers

	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(port);
		return a;
	}

	// One RFC 4733 event body: event code, E bit, volume, duration.
	struct EventBody { uint8_t b[4]; };

	EventBody eventBody(uint8_t event, bool end, uint16_t duration)
	{
		EventBody e{};
		e.b[0] = event;
		e.b[1] = static_cast<uint8_t>((end ? 0x80 : 0x00) | 0x0A);   // volume 10
		e.b[2] = static_cast<uint8_t>(duration >> 8);
		e.b[3] = static_cast<uint8_t>(duration & 0xFF);
		return e;
	}

	// A parsed packet as runLoop() would hand it to dispatchDtmf().
	RtpReceiver::RtpPacket packetFor(const EventBody& body, uint8_t pt, uint32_t timestamp)
	{
		RtpReceiver::RtpPacket pkt{};
		pkt.payloadType = pt;
		pkt.timestamp   = timestamp;
		pkt.seq         = 0;
		pkt.payload     = body.b;
		pkt.payloadLen  = sizeof(body.b);
		return pkt;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip,
		const std::string& callId)
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKr" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + callId + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	// An INVITE to the 888 conference — a leg the SERVER terminates, which is the
	// only kind of call whose RTP reaches this board at all. `dtmfPt` < 0 omits
	// the telephone-event line entirely, i.e. a phone that offers no RFC 4733.
	std::shared_ptr<SipMessage> makeConfInvite(const std::string& from, const std::string& ip,
		const std::string& callId, int dtmfPt = kDtmfPt)
	{
		std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n";
		if (dtmfPt >= 0)
		{
			body += "m=audio 10000 RTP/AVP 0 " + std::to_string(dtmfPt) + "\r\n"
				"a=rtpmap:0 PCMU/8000\r\n"
				"a=rtpmap:" + std::to_string(dtmfPt) + " telephone-event/8000\r\n";
		}
		else
		{
			body += "m=audio 10000 RTP/AVP 0\r\n"
				"a=rtpmap:0 PCMU/8000\r\n";
		}
		std::string raw =
			"INVITE sip:" + std::string(ConferenceRoom::EXT) + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKi" + callId + "\r\n"
			"From: <sip:" + from + "@server>;tag=ct" + callId + "\r\n"
			"To: <sip:" + std::string(ConferenceRoom::EXT) + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + from + "@" + ip + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	std::shared_ptr<SipMessage> makeInfoDigit(const std::string& from, const std::string& ip,
		const std::string& callId, char digit)
	{
		std::string body = std::string("Signal=") + digit + "\r\nDuration=100\r\n";
		std::string head =
			"INFO sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKinfo\r\n"
			"From: <sip:" + from + "@server>;tag=it\r\n"
			"To: <sip:server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INFO\r\n"
			"Content-Type: application/dtmf-relay\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
		return RequestsHandler::getMessageFromPool(head + body, addrFor(ip));
	}

	// An OPTIONS ping: the cheapest way to make handle() run a full pass, which is
	// what drains the DTMF ring. tick() also drains, but it self-throttles to 1 Hz
	// so calling it in a loop proves nothing.
	std::shared_ptr<SipMessage> makeOptions(const std::string& ip)
	{
		std::string raw =
			"OPTIONS sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKopt\r\n"
			"From: <sip:probe@server>;tag=pt\r\n"
			"To: <sip:server>\r\n"
			"Call-ID: opt-drain\r\n"
			"CSeq: 1 OPTIONS\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	bool contains(const std::vector<std::string>& v, const std::string& s)
	{
		for (const auto& x : v) if (x == s) return true;
		return false;
	}

	// Issue #284: DtmfSink is now a raw function pointer + void* ctx, not a
	// std::function, so these tests hand out trampolines reading ctx instead
	// of per-test capturing lambdas.
	void pushDigit(void* ctx, char digit, uint16_t /*durationMs*/)
	{
		static_cast<std::vector<char>*>(ctx)->push_back(digit);
	}

	void incrementCounter(void* ctx, char /*digit*/, uint16_t /*durationMs*/)
	{
		++*static_cast<int*>(ctx);
	}
}

// ── dispatchDtmf: one report per key press ──────────────────────────────────

TEST(Rfc4733Dispatch, ABurstOfPacketsForOneKeyPressReportsExactlyOnce)
{
	// A single key press is sent as a BURST — typically one packet every 20 ms
	// for the duration of the press, plus three copies of the end packet. Every
	// packet of that burst carries the RTP timestamp of the press's START, which
	// is what makes them recognisable as one press rather than a dozen.
	//
	// Getting this wrong does not fail quietly: *60 would become *6666660.
	RtpReceiver rx;
	std::vector<char> seen;
	ASSERT_TRUE(rx.setDtmfPayloadType(kDtmfPt, &pushDigit, &seen));

	for (uint16_t dur = 160; dur <= 960; dur += 160)
	{
		EXPECT_TRUE(rx.dispatchDtmf(packetFor(eventBody(6, false, dur), kDtmfPt, 5000)));
	}
	// The three end-of-event retransmissions RFC 4733 §2.5.1.2 asks for.
	for (int i = 0; i < 3; ++i)
	{
		EXPECT_TRUE(rx.dispatchDtmf(packetFor(eventBody(6, true, 960), kDtmfPt, 5000)));
	}

	ASSERT_EQ(seen.size(), 1u) << "one key press must produce exactly one digit";
	EXPECT_EQ(seen[0], '6');
}

TEST(Rfc4733Dispatch, ASecondPressOfTheSameKeyIsANewDigit)
{
	// Same key, new press — distinguished ONLY by the RTP timestamp. If dedupe
	// keyed on the digit instead, "77" would be impossible to dial.
	RtpReceiver rx;
	std::vector<char> seen;
	ASSERT_TRUE(rx.setDtmfPayloadType(kDtmfPt, &pushDigit, &seen));

	rx.dispatchDtmf(packetFor(eventBody(7, false, 160), kDtmfPt, 1000));
	rx.dispatchDtmf(packetFor(eventBody(7, true,  480), kDtmfPt, 1000));
	rx.dispatchDtmf(packetFor(eventBody(7, false, 160), kDtmfPt, 9000));
	rx.dispatchDtmf(packetFor(eventBody(7, true,  480), kDtmfPt, 9000));

	ASSERT_EQ(seen.size(), 2u);
	EXPECT_EQ(seen[0], '7');
	EXPECT_EQ(seen[1], '7');
}

TEST(Rfc4733Dispatch, ReportsOnTheFirstPacketSeenEvenWhenTheStartIsLost)
{
	// Loss tolerance is why the dedupe reports on the first packet SEEN rather
	// than waiting for E=1 or requiring the burst's first packet. UDP drops the
	// opening packet of a burst routinely; the digit must still arrive.
	RtpReceiver rx;
	std::vector<char> seen;
	ASSERT_TRUE(rx.setDtmfPayloadType(kDtmfPt, &pushDigit, &seen));

	// Only the final end-of-event packet survives the network.
	rx.dispatchDtmf(packetFor(eventBody(11, true, 800), kDtmfPt, 4242));   // '#'

	ASSERT_EQ(seen.size(), 1u) << "a press whose opening packets were lost must still register";
	EXPECT_EQ(seen[0], '#');
}

TEST(Rfc4733Dispatch, AudioAndUnknownPayloadTypesAreNotClaimed)
{
	// dispatchDtmf() returning false is what tells runLoop() "this is not mine" —
	// so a false positive here would eat audio.
	RtpReceiver rx;
	int fired = 0;
	ASSERT_TRUE(rx.setDtmfPayloadType(kDtmfPt, &incrementCounter, &fired));

	EXPECT_FALSE(rx.dispatchDtmf(packetFor(eventBody(1, true, 160), 0, 100)))
		<< "PCMU audio must never be claimed by the DTMF path";
	EXPECT_FALSE(rx.dispatchDtmf(packetFor(eventBody(1, true, 160), 13, 100)))
		<< "comfort noise is not telephone-event";
	EXPECT_EQ(fired, 0);
}

TEST(Rfc4733Dispatch, NothingIsClaimedUntilAPayloadTypeIsNegotiated)
{
	// The state every receiver was permanently stuck in before this change: no
	// caller ever armed one, so kDtmfPayloadTypeUnset was the only value it held
	// and every telephone-event packet fell through to "a codec we do not speak".
	RtpReceiver rx;
	EXPECT_FALSE(rx.dispatchDtmf(packetFor(eventBody(1, true, 160), kDtmfPt, 100)))
		<< "an unarmed receiver must not claim telephone-event packets";
}

TEST(Rfc4733Dispatch, NonDigitEventsAndMalformedBodiesAreConsumedButYieldNoDigit)
{
	// Both are on the negotiated PT, so they ARE ours to consume — they just are
	// not keypad symbols. Passing them up would inject junk into a feature code.
	RtpReceiver rx;
	int fired = 0;
	ASSERT_TRUE(rx.setDtmfPayloadType(kDtmfPt, &incrementCounter, &fired));

	EXPECT_TRUE(rx.dispatchDtmf(packetFor(eventBody(16, true, 160), kDtmfPt, 100)))
		<< "hook flash (event 16) is valid RFC 4733 and ours to swallow";

	RtpReceiver::RtpPacket shortPkt{};
	shortPkt.payloadType = kDtmfPt;
	shortPkt.timestamp   = 200;
	static const uint8_t twoBytes[2] = {1, 0};
	shortPkt.payload    = twoBytes;
	shortPkt.payloadLen = sizeof(twoBytes);
	EXPECT_TRUE(rx.dispatchDtmf(shortPkt)) << "right PT, truncated body: still ours";

	EXPECT_EQ(fired, 0) << "neither may produce a digit";
}

// ── End to end: a digit off the media task drives a feature code ────────────

TEST(Rfc4733EndToEnd, StarSixtyOverRtpSetsDndExactlyAsItDoesOverInfo)
{
	// THE test for this change. `*60` is Selective Call Rejection; it is the same
	// sequence DtmfClassCodes_test drives over SIP INFO. Before this, a phone in
	// its factory-default RFC 4733 mode could press these keys all day and the
	// board would never see them.
	RequestsHandler handler(kServerIp, 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	handler.handle(makeRegister("471", "192.168.47.71", "reg-471"));
	handler.handle(makeConfInvite("471", "192.168.47.71", "conf-471"));

	ASSERT_FALSE(contains(handler.getDndExtensions(), "471"));

	// What a media task does when it decodes a press. The Call-ID is the wire
	// form the session table is keyed by.
	const std::string callId = "Call-ID: conf-471";
	for (char c : std::string("*60"))
	{
		handler.queueDtmfDigit(callId, c);
	}
	// Nothing has run on the SIP thread yet — the ring is a hand-off, not an
	// action.
	ASSERT_FALSE(contains(handler.getDndExtensions(), "471"))
		<< "queueing must not act; the SIP thread owns the feature-code machine";

	handler.handle(makeOptions("192.168.47.99"));   // any SIP pass drains the ring

	EXPECT_TRUE(contains(handler.getDndExtensions(), "471"))
		<< "*60 pressed on a stock RFC 4733 handset must set DND, the same way "
		   "the same keys do over SIP INFO";
	EXPECT_EQ(handler.dtmfDigitsDropped(), 0u);
}

TEST(Rfc4733EndToEnd, APhoneSendingBothInfoAndRtpForOnePressCountsItOnce)
{
	// Grandstream's "SIP INFO + RFC2833" DTMF mode sends BOTH for every key, and
	// it is a setting people leave switched on. Without de-duplication `*60`
	// accumulates as `**6600` and matches nothing — so turning RFC 4733 on would
	// have BROKEN feature codes for exactly the phones that were already working.
	RequestsHandler handler(kServerIp, 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	handler.handle(makeRegister("472", "192.168.47.72", "reg-472"));
	handler.handle(makeConfInvite("472", "192.168.47.72", "conf-472"));

	const std::string callId = "Call-ID: conf-472";
	for (char c : std::string("*60"))
	{
		// INFO arrives first and is acted on inside handle()...
		handler.handle(makeInfoDigit("472", "192.168.47.72", "conf-472", c));
		// ...and the RTP twin of the same press lands immediately after.
		handler.queueDtmfDigit(callId, c);
		handler.handle(makeOptions("192.168.47.99"));
	}

	EXPECT_TRUE(contains(handler.getDndExtensions(), "472"))
		<< "the duplicated keypresses must still add up to exactly *60";
}

TEST(Rfc4733EndToEnd, ADigitForADialogThatHasEndedIsDroppedSilently)
{
	// A press can be in flight across a hang-up: captured on the media task, and
	// by the time the SIP thread drains, the call is gone. Creating an
	// accumulator for a dead Call-ID would just leave litter for sweepStale().
	RequestsHandler handler(kServerIp, 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	handler.handle(makeRegister("473", "192.168.47.73", "reg-473"));

	handler.queueDtmfDigit("Call-ID: a-call-that-never-existed", '5');
	handler.handle(makeOptions("192.168.47.99"));

	EXPECT_EQ(handler.dtmfDigitsDropped(), 0u)
		<< "dropping an orphaned digit is not a ring overflow and must not count as one";
}

TEST(Rfc4733EndToEnd, AFloodOfDigitsDropsTheOldestAndSaysSo)
{
	// The media task must never block on the SIP thread — a stalled RTP task
	// costs the call's audio, while a dropped digit costs one keypress. The ring
	// therefore sheds rather than waits, and counts what it shed so a "I pressed
	// a key and nothing happened" report has something behind it.
	RequestsHandler handler(kServerIp, 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	handler.handle(makeRegister("474", "192.168.47.74", "reg-474"));
	handler.handle(makeConfInvite("474", "192.168.47.74", "conf-474"));

	const std::string callId = "Call-ID: conf-474";
	const int overflow = 6;
	for (int i = 0; i < POCKETDIAL_DTMF_INBOX + overflow; ++i)
	{
		handler.queueDtmfDigit(callId, '1');
	}

	EXPECT_EQ(handler.dtmfDigitsDropped(), static_cast<uint64_t>(overflow))
		<< "every press past the ring's depth must be counted, not silently lost";

	// And the ring itself recovers — an overflow must not wedge the path.
	//
	// Asserted on a SECOND dialog rather than by re-dialling on the flooded one,
	// because the sixteen surviving '1's are now sitting in that call's digit
	// accumulator, so "*60" there would accumulate as "1111111111111111*60" and
	// match nothing until DtmfAccum::TIMEOUT_MS clears it. That is pre-existing
	// behaviour shared with SIP INFO — the accumulator resyncs on the inter-digit
	// timeout, not on a leading '*' — and is deliberately not what this test is
	// about.
	handler.handle(makeOptions("192.168.47.99"));
	handler.handle(makeRegister("476", "192.168.47.76", "reg-476"));
	handler.handle(makeConfInvite("476", "192.168.47.76", "conf-476"));
	for (char c : std::string("*60"))
	{
		handler.queueDtmfDigit("Call-ID: conf-476", c);
	}
	handler.handle(makeOptions("192.168.47.99"));

	EXPECT_TRUE(contains(handler.getDndExtensions(), "476"))
		<< "after an overflow the ring must still deliver a fresh dialog's digits";
	EXPECT_EQ(handler.dtmfDigitsDropped(), static_cast<uint64_t>(overflow))
		<< "the drop counter must not keep climbing once the flood is over";
}

TEST(Rfc4733EndToEnd, APhoneThatOffersNoTelephoneEventIsUnaffected)
{
	// Under-claiming is the safe direction: a phone whose SDP has no
	// telephone-event line must leave the leg exactly as DTMF-deaf as it was
	// before this change, with SIP INFO still working.
	RequestsHandler handler(kServerIp, 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	handler.handle(makeRegister("475", "192.168.47.75", "reg-475"));
	handler.handle(makeConfInvite("475", "192.168.47.75", "conf-475", /*dtmfPt=*/-1));

	// INFO is unaffected by any of this and must still drive the feature code.
	for (char c : std::string("*60"))
	{
		handler.handle(makeInfoDigit("475", "192.168.47.75", "conf-475", c));
	}
	EXPECT_TRUE(contains(handler.getDndExtensions(), "475"))
		<< "SIP INFO must keep working for a phone that offers no RFC 4733";
}

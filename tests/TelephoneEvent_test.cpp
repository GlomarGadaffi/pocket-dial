#include <gtest/gtest.h>
#include "RtpReceiver.hpp"
#include "RequestsHandler.hpp"
#include "SipMessage.hpp"
#include <cstdint>
#include <string>
#include <vector>

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

// ── RFC 4733 telephone-event (DTMF over RTP) ────────────────────────────────
// Why this matters here specifically: an ordinary extension-to-extension call's
// RTP is peer-to-peer and never reaches the board, so RFC 4733 is only ever
// decodable on a SERVER-TERMINATED leg (440 tone, 555 anchor, 888 conference,
// and anything the voicemail/IVR roadmap adds). Before this decoder existed the
// receive loop dropped every non-PCMU packet as "wrong codec", so a phone in its
// default DTMF mode could not drive a server-side menu at all.
//
// The payload is four bytes (RFC 4733 §2.3):
//
//    0                   1                   2                   3
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     event     |E|R| volume    |          duration             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

namespace {

std::vector<uint8_t> eventPayload(uint8_t event, bool end, uint8_t volume, uint16_t duration)
{
    return {
        event,
        static_cast<uint8_t>((end ? 0x80 : 0x00) | (volume & 0x3F)),
        static_cast<uint8_t>(duration >> 8),
        static_cast<uint8_t>(duration & 0xFF),
    };
}

}  // namespace

TEST(TelephoneEvent, ParsesAllFourFields)
{
    const auto p = eventPayload(/*event=*/5, /*end=*/true, /*volume=*/10, /*duration=*/1600);
    RtpReceiver::DtmfEvent ev;
    ASSERT_TRUE(RtpReceiver::parseTelephoneEvent(p.data(), p.size(), ev));
    EXPECT_EQ(ev.event, 5);
    EXPECT_TRUE(ev.end);
    EXPECT_EQ(ev.volume, 10);
    EXPECT_EQ(ev.duration, 1600);
}

TEST(TelephoneEvent, DurationIsNetworkByteOrder)
{
    // 0x1234 must read back as 4660, not byte-swapped to 0x3412. Getting this
    // backwards would not fail loudly -- it would just report absurd durations.
    const auto p = eventPayload(1, false, 0, 0x1234);
    RtpReceiver::DtmfEvent ev;
    ASSERT_TRUE(RtpReceiver::parseTelephoneEvent(p.data(), p.size(), ev));
    EXPECT_EQ(ev.duration, 0x1234);
}

TEST(TelephoneEvent, ReservedBitIsNotFoldedIntoVolume)
{
    // Bit 6 of byte 1 is R (reserved) and must be masked off. A sender that sets
    // it would otherwise read back as volume 0x40+ -- outside the 6-bit field.
    std::vector<uint8_t> p = eventPayload(3, /*end=*/false, /*volume=*/0x3F, 0);
    p[1] = static_cast<uint8_t>(p[1] | 0x40);   // set R
    RtpReceiver::DtmfEvent ev;
    ASSERT_TRUE(RtpReceiver::parseTelephoneEvent(p.data(), p.size(), ev));
    EXPECT_EQ(ev.volume, 0x3F);
    EXPECT_FALSE(ev.end);
}

TEST(TelephoneEvent, EndBitIsIndependentOfVolume)
{
    const auto noEnd = eventPayload(7, false, 0x3F, 0);
    const auto isEnd = eventPayload(7, true,  0x00, 0);
    RtpReceiver::DtmfEvent a, b;
    ASSERT_TRUE(RtpReceiver::parseTelephoneEvent(noEnd.data(), noEnd.size(), a));
    ASSERT_TRUE(RtpReceiver::parseTelephoneEvent(isEnd.data(), isEnd.size(), b));
    EXPECT_FALSE(a.end);
    EXPECT_EQ(a.volume, 0x3F);
    EXPECT_TRUE(b.end);
    EXPECT_EQ(b.volume, 0x00);
}

TEST(TelephoneEvent, RejectsShortPayloadAndLeavesOutputUntouched)
{
    RtpReceiver::DtmfEvent ev;
    ev.event = 0xAB;   // sentinel: must survive a failed parse
    const uint8_t threeBytes[3] = { 1, 0, 0 };
    EXPECT_FALSE(RtpReceiver::parseTelephoneEvent(threeBytes, sizeof(threeBytes), ev));
    EXPECT_EQ(ev.event, 0xAB);

    EXPECT_FALSE(RtpReceiver::parseTelephoneEvent(nullptr, 4, ev));
    EXPECT_EQ(ev.event, 0xAB);

    EXPECT_FALSE(RtpReceiver::parseTelephoneEvent(threeBytes, 0, ev));
    EXPECT_EQ(ev.event, 0xAB);
}

TEST(TelephoneEvent, AcceptsOversizePayloadReadingOnlyTheFirstEvent)
{
    // RFC 4733 permits multiple events in one payload. We decode the first; a
    // longer buffer must not be rejected as malformed.
    std::vector<uint8_t> p = eventPayload(9, false, 5, 800);
    const auto second = eventPayload(4, true, 5, 800);
    p.insert(p.end(), second.begin(), second.end());
    RtpReceiver::DtmfEvent ev;
    ASSERT_TRUE(RtpReceiver::parseTelephoneEvent(p.data(), p.size(), ev));
    EXPECT_EQ(ev.event, 9);
    EXPECT_EQ(ev.duration, 800);
}

// ── Event code -> keypad character (RFC 4733 §3.2, table 7) ─────────────────

TEST(TelephoneEvent, MapsTheSixteenDtmfSymbols)
{
    for (uint8_t d = 0; d <= 9; ++d)
    {
        EXPECT_EQ(RtpReceiver::dtmfEventToChar(d), static_cast<char>('0' + d))
            << "event " << static_cast<unsigned>(d);
    }
    EXPECT_EQ(RtpReceiver::dtmfEventToChar(10), '*');
    EXPECT_EQ(RtpReceiver::dtmfEventToChar(11), '#');
    EXPECT_EQ(RtpReceiver::dtmfEventToChar(12), 'A');
    EXPECT_EQ(RtpReceiver::dtmfEventToChar(13), 'B');
    EXPECT_EQ(RtpReceiver::dtmfEventToChar(14), 'C');
    EXPECT_EQ(RtpReceiver::dtmfEventToChar(15), 'D');
}

TEST(TelephoneEvent, NonDigitEventsAreNotKeys)
{
    // 16 is hook flash; 17+ are the tone events (dial tone, busy, ringback, ...).
    // A feature-code parser must never receive these as if they were keypresses.
    EXPECT_EQ(RtpReceiver::dtmfEventToChar(16), '\0');
    EXPECT_EQ(RtpReceiver::dtmfEventToChar(17), '\0');
    EXPECT_EQ(RtpReceiver::dtmfEventToChar(40), '\0');
    EXPECT_EQ(RtpReceiver::dtmfEventToChar(255), '\0');
}

// ── Payload-type arming ─────────────────────────────────────────────────────

TEST(TelephoneEvent, RefusesToArmOnThePcmuPayloadType)
{
    // Arming on PT 0 would shadow audio -- and the receive loop matches PCMU
    // first anyway, so accepting it would silently do nothing. Better to refuse
    // than to leave the caller believing DTMF is armed.
    RtpReceiver rx;
    EXPECT_FALSE(rx.setDtmfPayloadType(RtpReceiver::PAYLOAD_TYPE_PCMU,
                                       [](char, uint16_t) {}));
}

TEST(TelephoneEvent, ArmsOnADynamicPayloadType)
{
    RtpReceiver rx;
    // 101 is the common choice but the value is negotiated, not fixed -- the API
    // must accept whatever the peer advertised.
    EXPECT_TRUE(rx.setDtmfPayloadType(101, [](char, uint16_t) {}));
    EXPECT_TRUE(rx.setDtmfPayloadType(96,  [](char, uint16_t) {}));
    EXPECT_TRUE(rx.setDtmfPayloadType(127, [](char, uint16_t) {}));
    // Disarming is legal and is how a call teardown releases the sink.
    EXPECT_TRUE(rx.setDtmfPayloadType(RtpReceiver::kDtmfPayloadTypeUnset,
                                      nullptr));
}

// ── Reading the negotiated PT out of an offer ───────────────────────────────
// The PT is dynamic, so the answer must echo whatever the OFFER used. Picking a
// number of our own would violate RFC 3264 (an answer may only contain payload
// types the offer contained) and the phone would ignore the stream.

namespace {

std::string inviteWithSdp(const std::string& body)
{
    return
        "INVITE sip:888@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 192.168.7.50:5060;branch=z9hG4bKte\r\n"
        "From: <sip:500@server>;tag=f1\r\n"
        "To: <sip:888@server>\r\n"
        "Call-ID: te-1\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
}

SipMessage makeInvite(const std::string& body)
{
    sockaddr_in src{};
    src.sin_family = AF_INET;
    return SipMessage(inviteWithSdp(body), src);
}

}  // namespace

TEST(TelephoneEvent, ReadsTheOfferedPayloadType)
{
    const SipMessage m = makeInvite(
        "v=0\r\no=- 1 1 IN IP4 192.168.7.50\r\ns=-\r\n"
        "c=IN IP4 192.168.7.50\r\nt=0 0\r\n"
        "m=audio 40000 RTP/AVP 0 8 101\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=rtpmap:8 PCMA/8000\r\n"
        "a=rtpmap:101 telephone-event/8000\r\n"
        "a=fmtp:101 0-15\r\n");
    EXPECT_EQ(m.getTelephoneEventPayloadType(), 101);
}

TEST(TelephoneEvent, ReadsANonStandardPayloadNumber)
{
    // Real phones do not all pick 101 -- pjsip commonly numbers it 120. Hardcoding
    // 101 anywhere would break exactly those.
    const SipMessage m = makeInvite(
        "v=0\r\no=- 1 1 IN IP4 192.168.7.50\r\ns=-\r\n"
        "c=IN IP4 192.168.7.50\r\nt=0 0\r\n"
        "m=audio 40000 RTP/AVP 0 120\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=rtpmap:120 telephone-event/8000\r\n");
    EXPECT_EQ(m.getTelephoneEventPayloadType(), 120);
}

TEST(TelephoneEvent, EncodingNameIsCaseInsensitive)
{
    // RFC 4566 §6: the encoding name is not case sensitive, and handsets do ship
    // upper-case spellings.
    const SipMessage m = makeInvite(
        "v=0\r\no=- 1 1 IN IP4 192.168.7.50\r\ns=-\r\n"
        "c=IN IP4 192.168.7.50\r\nt=0 0\r\n"
        "m=audio 40000 RTP/AVP 0 101\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=rtpmap:101 TELEPHONE-EVENT/8000\r\n");
    EXPECT_EQ(m.getTelephoneEventPayloadType(), 101);
}

TEST(TelephoneEvent, AbsentFromOfferReportsMinusOne)
{
    const SipMessage m = makeInvite(
        "v=0\r\no=- 1 1 IN IP4 192.168.7.50\r\ns=-\r\n"
        "c=IN IP4 192.168.7.50\r\nt=0 0\r\n"
        "m=audio 40000 RTP/AVP 0\r\n"
        "a=rtpmap:0 PCMU/8000\r\n");
    EXPECT_EQ(m.getTelephoneEventPayloadType(), -1);
}

// ── The answer must advertise it back ───────────────────────────────────────

TEST(TelephoneEvent, AnswerAdvertisesTheEchoedPayloadType)
{
    const std::string sdp =
        RequestsHandler::buildMediaSdp("192.168.7.1", 41000, /*sendrecv=*/true, 101);

    // The m= line must LIST it, not merely carry an rtpmap: a payload type absent
    // from the format list is not negotiated however many attributes describe it.
    EXPECT_NE(sdp.find("m=audio 41000 RTP/AVP 0 101\r\n"), std::string::npos) << sdp;
    EXPECT_NE(sdp.find("a=rtpmap:101 telephone-event/8000\r\n"), std::string::npos) << sdp;
    EXPECT_NE(sdp.find("a=fmtp:101 0-15\r\n"), std::string::npos) << sdp;
    EXPECT_NE(sdp.find("a=rtpmap:0 PCMU/8000\r\n"), std::string::npos) << sdp;
    EXPECT_NE(sdp.find("a=sendrecv\r\n"), std::string::npos) << sdp;
}

TEST(TelephoneEvent, AnswerEchoesWhateverNumberTheOfferUsed)
{
    const std::string sdp =
        RequestsHandler::buildMediaSdp("192.168.7.1", 41000, /*sendrecv=*/true, 120);
    EXPECT_NE(sdp.find("m=audio 41000 RTP/AVP 0 120\r\n"), std::string::npos) << sdp;
    EXPECT_NE(sdp.find("a=rtpmap:120 telephone-event/8000\r\n"), std::string::npos) << sdp;
    // and must not have invented the conventional number instead
    EXPECT_EQ(sdp.find("101"), std::string::npos) << sdp;
}

TEST(TelephoneEvent, AnswerStaysPcmuOnlyWithoutAnOffer)
{
    // The pre-existing behaviour must be byte-identical when the offer carried no
    // telephone-event (or when building our own offer), so nothing that relied on
    // a PCMU-only answer changes.
    const std::string sdp =
        RequestsHandler::buildMediaSdp("192.168.7.1", 41000, /*sendrecv=*/false);
    EXPECT_NE(sdp.find("m=audio 41000 RTP/AVP 0\r\n"), std::string::npos) << sdp;
    EXPECT_EQ(sdp.find("telephone-event"), std::string::npos) << sdp;
    EXPECT_EQ(sdp.find("a=fmtp:"), std::string::npos) << sdp;
    EXPECT_NE(sdp.find("a=sendonly\r\n"), std::string::npos) << sdp;
}

TEST(TelephoneEvent, AnswerRefusesToAdvertiseOnPayloadTypeZero)
{
    // PT 0 is PCMU. Echoing a bogus "telephone-event on 0" offer would shadow
    // audio; the builder must ignore it rather than emit a contradictory body.
    const std::string sdp =
        RequestsHandler::buildMediaSdp("192.168.7.1", 41000, /*sendrecv=*/true, 0);
    EXPECT_NE(sdp.find("m=audio 41000 RTP/AVP 0\r\n"), std::string::npos) << sdp;
    EXPECT_EQ(sdp.find("telephone-event"), std::string::npos) << sdp;
}

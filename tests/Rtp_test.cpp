#include <gtest/gtest.h>
#include "RtpSender.hpp"
#include "RequestsHandler.hpp"
#include "SipMessage.hpp"
#include "SipMessageTypes.h"
#include <vector>
#include <memory>
#include <string>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

// ── µ-law encoder: known-sample vectors ─────────────────────────────────────
// ITU-T G.711 µ-law reference points. The encoder folds sign into bit 7 and
// inverts the companded byte, so silence (0) encodes to 0xFF and full-scale
// negative encodes to 0x00. These exact values are how a real phone's decoder
// reconstructs the tone, so a wrong table = static/garbled audio on the wire.
TEST(Ulaw, KnownSamples) {
    // Digital silence → 0xFF (the canonical µ-law "zero").
    EXPECT_EQ(RtpSender::linearToUlaw(0), 0xFF);
    // Max positive full-scale → 0x80 (sign bit clear after inversion).
    EXPECT_EQ(RtpSender::linearToUlaw(32767), 0x80);
    // Max negative full-scale → 0x00.
    EXPECT_EQ(RtpSender::linearToUlaw(-32768), 0x00);
    // Sign symmetry: +N and -N must differ only in the sign bit (bit 7).
    uint8_t pos = RtpSender::linearToUlaw(1000);
    uint8_t neg = RtpSender::linearToUlaw(-1000);
    EXPECT_EQ(pos & 0x7F, neg & 0x7F);
    EXPECT_NE(pos & 0x80, neg & 0x80);
    // Every encoded byte is a valid 8-bit value (sanity over a sweep).
    for (int v = -32768; v <= 32767; v += 137) {
        uint8_t u = RtpSender::linearToUlaw(static_cast<int16_t>(v));
        EXPECT_LE(u, 0xFF);
    }
}

// ── RTP header field layout (RFC 3550 §5.1), big-endian on the wire ─────────
TEST(RtpHeader, FieldLayoutBigEndian) {
    uint8_t hdr[RtpSender::RTP_HEADER_BYTES] = {0};
    const uint16_t seq = 0x1234;
    const uint32_t ts  = 0xAABBCCDD;
    const uint32_t ssrc = 0x01020304;

    // Marker set, PT = 0 (PCMU).
    RtpSender::buildRtpHeader(hdr, /*marker=*/true, RtpSender::PAYLOAD_TYPE_PCMU,
                              seq, ts, ssrc);

    // Byte 0: V=2 (0b10), P=0, X=0, CC=0  → 0x80.
    EXPECT_EQ(hdr[0], 0x80);
    EXPECT_EQ((hdr[0] >> 6) & 0x03, 2);            // version == 2
    EXPECT_EQ((hdr[0] >> 5) & 0x01, 0);            // padding == 0
    EXPECT_EQ((hdr[0] >> 4) & 0x01, 0);            // extension == 0
    EXPECT_EQ(hdr[0] & 0x0F, 0);                   // CSRC count == 0

    // Byte 1: M=1, PT=0  → 0x80.
    EXPECT_EQ((hdr[1] >> 7) & 0x01, 1);            // marker bit
    EXPECT_EQ(hdr[1] & 0x7F, 0);                   // payload type 0

    // Seq big-endian.
    EXPECT_EQ(hdr[2], 0x12);
    EXPECT_EQ(hdr[3], 0x34);
    // Timestamp big-endian.
    EXPECT_EQ(hdr[4], 0xAA);
    EXPECT_EQ(hdr[5], 0xBB);
    EXPECT_EQ(hdr[6], 0xCC);
    EXPECT_EQ(hdr[7], 0xDD);
    // SSRC big-endian.
    EXPECT_EQ(hdr[8],  0x01);
    EXPECT_EQ(hdr[9],  0x02);
    EXPECT_EQ(hdr[10], 0x03);
    EXPECT_EQ(hdr[11], 0x04);

    // Marker cleared on a subsequent packet (only the first packet carries M=1).
    RtpSender::buildRtpHeader(hdr, /*marker=*/false, RtpSender::PAYLOAD_TYPE_PCMU,
                              static_cast<uint16_t>(seq + 1), ts + 160, ssrc);
    EXPECT_EQ((hdr[1] >> 7) & 0x01, 0);            // marker now 0
    EXPECT_EQ(hdr[2], 0x12);
    EXPECT_EQ(hdr[3], 0x35);                       // seq incremented
}

// ── 20 ms / 160-sample packetization constants ──────────────────────────────
TEST(RtpHeader, PacketSizing) {
    EXPECT_EQ(RtpSender::SAMPLES_PER_PKT, 160);
    EXPECT_EQ(RtpSender::RTP_HEADER_BYTES, 12);
    EXPECT_EQ(RtpSender::PACKET_BYTES, 12 + 160);
    EXPECT_EQ(RtpSender::PAYLOAD_TYPE_PCMU, 0);
}

// ── Tone synthesis produces continuous, non-trivial µ-law frames ────────────
TEST(Ulaw, ToneSynthIsContinuousAndNonSilent) {
    uint8_t frame[RtpSender::SAMPLES_PER_PKT];
    double phase = 0.0;
    RtpSender::synthTone(frame, RtpSender::SAMPLES_PER_PKT,
                         RtpSender::DEFAULT_TONE_HZ, phase);
    // A real tone is not constant silence: at least some bytes differ from 0xFF.
    int nonSilent = 0;
    for (uint8_t b : frame) if (b != 0xFF) ++nonSilent;
    EXPECT_GT(nonSilent, 0);
    // Phase advanced and stayed bounded in [0, 2π).
    EXPECT_GT(phase, 0.0);
    EXPECT_LT(phase, 6.2832);
}

// ── 440 media answer: SDP body + Content-Length correctness (777-bug class) ──
// The server's 200 OK for a 440 dial must advertise the SERVER's own media with a
// Content-Length that exactly equals the SDP body byte count, or UDP peers drop the
// answer as truncated and the caller never hears the tone. This mirrors the
// EnforceG711ResyncsContentLength regression but for the synthesized server SDP.
TEST(MediaAnswer, ServerSdpContentLengthMatchesBody) {
    const std::string serverIp = "192.168.4.1";
    const int rtpPort = 5062;

    std::string body = RequestsHandler::buildMediaSdp(serverIp, rtpPort);

    // The advertised media line is PCMU (PT 0) on the server's media port.
    EXPECT_NE(body.find("m=audio 5062 RTP/AVP 0\r\n"), std::string::npos);
    EXPECT_NE(body.find("c=IN IP4 192.168.4.1\r\n"), std::string::npos);
    EXPECT_NE(body.find("a=rtpmap:0 PCMU/8000\r\n"), std::string::npos);

    // Build a 200 OK carrying that body and verify syncContentLength() lands the
    // header on the real byte count (the path onMediaInvite uses on-device).
    sockaddr_in s{}; s.sin_addr.s_addr = inet_addr("127.0.0.1");
    std::string head =
        "SIP/2.0 200 OK\r\n"
        "Via: SIP/2.0/UDP 192.168.4.1:5060;branch=1\r\n"
        "From: <sip:100@server>\r\n"
        "To: <sip:440@server>;tag=abc\r\n"
        "Call-ID: mediacall\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:440@192.168.4.1:5060>\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage m(head + body, s);
    m.syncContentLength();

    const std::string out = m.toString();
    size_t sep = out.find("\r\n\r\n");
    ASSERT_NE(sep, std::string::npos);
    size_t actualBody = out.size() - (sep + 4);
    EXPECT_EQ(actualBody, body.size());
    EXPECT_EQ(std::string(m.getContentLength()),
              "Content-Length: " + std::to_string(actualBody));
}

// ── End-to-end: a real 440 INVITE through RequestsHandler::handle() ─────────
// Drives the actual onMediaInvite() body-assembly path (not the isolated builder)
// and asserts the emitted 200 OK is a well-formed SDP answer: server media line,
// exactly one Content-Type, and a Content-Length equal to the SDP body bytes.
namespace {
    struct Captured {
        std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> out;
    };
    // Build a minimal SDP INVITE to 440 from extension `from` at `srcIp`.
    std::shared_ptr<SipMessage> makeInvite440(const std::string& from,
                                              const std::string& srcIp,
                                              const std::string& callID) {
        sockaddr_in s{}; s.sin_family = AF_INET;
        s.sin_addr.s_addr = inet_addr(srcIp.c_str());
        s.sin_port = htons(5060);
        std::string body =
            "v=0\r\n"
            "o=- 0 0 IN IP4 " + srcIp + "\r\n"
            "s=-\r\n"
            "c=IN IP4 " + srcIp + "\r\n"
            "t=0 0\r\n"
            "m=audio 40000 RTP/AVP 0 8 101\r\n"
            "a=rtpmap:0 PCMU/8000\r\n";
        std::string head =
            "INVITE sip:440@server SIP/2.0\r\n"
            "Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bK1\r\n"
            "From: <sip:" + from + "@server>;tag=ft\r\n"
            "To: <sip:440@server>\r\n"
            "Call-ID: " + callID + "\r\n"
            "CSeq: 1 INVITE\r\n"
            "Contact: <sip:" + from + "@" + srcIp + ":5060>\r\n"
            "Content-Type: application/sdp\r\n"
            "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
        return RequestsHandler::getMessageFromPool(head + body, s);
    }
    std::shared_ptr<SipMessage> makeRegister(const std::string& from,
                                             const std::string& srcIp,
                                             const std::string& callID) {
        sockaddr_in s{}; s.sin_family = AF_INET;
        s.sin_addr.s_addr = inet_addr(srcIp.c_str());
        s.sin_port = htons(5060);
        std::string raw =
            "REGISTER sip:server SIP/2.0\r\n"
            "Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKr\r\n"
            "From: <sip:" + from + "@server>;tag=rt\r\n"
            "To: <sip:" + from + "@server>\r\n"
            "Call-ID: " + callID + "\r\n"
            "CSeq: 1 REGISTER\r\n"
            "Contact: <sip:" + from + "@" + srcIp + ":5060>;expires=3600\r\n"
            "Content-Length: 0\r\n\r\n";
        return RequestsHandler::getMessageFromPool(raw, s);
    }
}

TEST(MediaAnswer, EndToEnd440InviteEmitsServerSdpAnswer) {
    Captured cap;
    RequestsHandler handler("192.168.4.1", 5060,
        [&cap](const sockaddr_in& dest, std::shared_ptr<SipMessage> msg) {
            cap.out.emplace_back(dest, msg);
        });

    // Register the caller (onInvite 403s unregistered callers).
    handler.handle(makeRegister("100", "192.168.4.50", "reg-1"));
    cap.out.clear();

    // Dial 440.
    handler.handle(makeInvite440("100", "192.168.4.50", "media-1"));

    // Find the 200 OK answer in the outbox.
    std::shared_ptr<SipMessage> ok;
    for (auto& e : cap.out) {
        auto st = e.second->getStatusInfo();
        if (st.has_value() && st->code == 200) { ok = e.second; break; }
    }
    ASSERT_TRUE(ok != nullptr) << "no 200 OK emitted for 440 dial";

    const std::string raw = ok->toString();
    // Server media advertised (PCMU on the server's RTP port 5062, server IP).
    EXPECT_NE(raw.find("m=audio 5062 RTP/AVP 0"), std::string::npos);
    EXPECT_NE(raw.find("c=IN IP4 192.168.4.1"), std::string::npos);

    // Exactly ONE Content-Type header (no duplicate from the cloned INVITE).
    size_t first = raw.find("application/sdp");
    ASSERT_NE(first, std::string::npos);
    EXPECT_EQ(raw.find("application/sdp", first + 1), std::string::npos);

    // Content-Length equals the actual SDP body byte count (777-bug class).
    size_t sep = raw.find("\r\n\r\n");
    ASSERT_NE(sep, std::string::npos);
    size_t bodyLen = raw.size() - (sep + 4);
    EXPECT_EQ(std::string(ok->getContentLength()),
              "Content-Length: " + std::to_string(bodyLen));
    EXPECT_GT(bodyLen, 0u);

    // A second concurrent 440 dial is rejected 486 Busy Here (single-stream cap).
    cap.out.clear();
    handler.handle(makeInvite440("100", "192.168.4.50", "media-2"));
    bool saw486 = false;
    for (auto& e : cap.out) {
        auto st = e.second->getStatusInfo();
        if (st.has_value() && st->code == 486) saw486 = true;
    }
    EXPECT_TRUE(saw486) << "2nd concurrent 440 dial should be 486 Busy Here";

    // BYE the first call: stream stops, freeing the slot for a later dial.
    {
        sockaddr_in s{}; s.sin_family = AF_INET;
        s.sin_addr.s_addr = inet_addr("192.168.4.50"); s.sin_port = htons(5060);
        std::string bye =
            "BYE sip:440@server SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 192.168.4.50:5060;branch=z9hG4bKb\r\n"
            "From: <sip:100@server>;tag=ft\r\n"
            "To: <sip:440@server>;tag=st\r\n"
            "Call-ID: media-1\r\n"
            "CSeq: 2 BYE\r\n"
            "Content-Length: 0\r\n\r\n";
        cap.out.clear();
        handler.handle(RequestsHandler::getMessageFromPool(bye, s));
    }
    // After BYE, a fresh 440 dial is accepted again (200 OK).
    cap.out.clear();
    handler.handle(makeInvite440("100", "192.168.4.50", "media-3"));
    bool saw200Again = false;
    for (auto& e : cap.out) {
        auto st = e.second->getStatusInfo();
        if (st.has_value() && st->code == 200) saw200Again = true;
    }
    EXPECT_TRUE(saw200Again) << "after BYE the media slot should be free again";
}

// Issue #304: 440's tone is synthesized and G.711 mu-law encoded only
// (RtpSender hardcodes PCMU) and buildMediaSdp's answer is PCMU-only
// regardless of what was offered, so a PCMA-only caller must be refused
// rather than answered with a payload type it never offered.
TEST(MediaAnswer, PcmaOnlyOfferGets488NotAnAnswerItCannotProduce) {
    Captured cap;
    RequestsHandler handler("192.168.4.1", 5060,
        [&cap](const sockaddr_in& dest, std::shared_ptr<SipMessage> msg) {
            cap.out.emplace_back(dest, msg);
        });

    handler.handle(makeRegister("101", "192.168.4.51", "reg-2"));
    cap.out.clear();

    sockaddr_in s{}; s.sin_family = AF_INET;
    s.sin_addr.s_addr = inet_addr("192.168.4.51"); s.sin_port = htons(5060);
    std::string body =
        "v=0\r\n"
        "o=- 0 0 IN IP4 192.168.4.51\r\n"
        "s=-\r\n"
        "c=IN IP4 192.168.4.51\r\n"
        "t=0 0\r\n"
        "m=audio 40000 RTP/AVP 8\r\n"
        "a=rtpmap:8 PCMA/8000\r\n";
    std::string head =
        "INVITE sip:440@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 192.168.4.51:5060;branch=z9hG4bKp\r\n"
        "From: <sip:101@server>;tag=pt\r\n"
        "To: <sip:440@server>\r\n"
        "Call-ID: media-pcma\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:101@192.168.4.51:5060>\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
    handler.handle(RequestsHandler::getMessageFromPool(head + body, s));

    bool saw488 = false, saw200 = false;
    for (auto& e : cap.out) {
        auto st = e.second->getStatusInfo();
        if (!st.has_value()) continue;
        if (st->code == 488) saw488 = true;
        if (st->code == 200) saw200 = true;
    }
    EXPECT_TRUE(saw488) << "PCMA-only offer to 440 was not refused with 488";
    EXPECT_FALSE(saw200) << "PCMA-only offer to 440 was answered 200 OK";
}

// ── Single-stream cap: the host stub still enforces one concurrent stream ────
TEST(MediaAnswer, SingleStreamCap) {
    RtpSender tx;
    EXPECT_FALSE(tx.isActive());
    EXPECT_TRUE(tx.start("192.168.4.20", 4000, "callA"));
    EXPECT_TRUE(tx.isActive());
    EXPECT_EQ(tx.activeCallId(), "callA");

    // Second start while active is rejected (the 486 path).
    EXPECT_FALSE(tx.start("192.168.4.21", 4002, "callB"));
    EXPECT_EQ(tx.activeCallId(), "callA");

    // A stale stop for a different Call-ID is ignored; the matching one stops.
    EXPECT_FALSE(tx.stop("callB"));
    EXPECT_TRUE(tx.isActive());
    EXPECT_TRUE(tx.stop("callA"));
    EXPECT_FALSE(tx.isActive());
    EXPECT_EQ(tx.activeCallId(), "");

    // Idempotent: stopping an idle sender is a no-op.
    EXPECT_FALSE(tx.stop("callA"));
}

// Issue #108: on the Linux media path, only stop() joined the sender thread —
// no destructor was visible in that patch. std::thread's destructor calls
// std::terminate on a still-joinable thread, so destroying an RtpSender while
// a stream is active (process shutdown mid-diagnostic-call, or any future
// owner with a shorter lifetime than RequestsHandler) would crash the process.
// Reaching the end of this test at all — rather than the binary aborting — is
// the assertion; ~RtpSender() must stop (and, on Linux, join) any live stream.
TEST(MediaAnswer, DestructorStopsActiveStreamWithoutCrash) {
    {
        RtpSender tx;
        EXPECT_TRUE(tx.start("192.168.4.22", 4004, "callD"));
        EXPECT_TRUE(tx.isActive());
        // No stop() call: ~RtpSender() runs here, at scope exit, on a live
        // stream.
    }
    SUCCEED();
}

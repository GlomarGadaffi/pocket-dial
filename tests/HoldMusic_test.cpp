#include <gtest/gtest.h>

#include "HoldMusic.hpp"
#include "RtpReceiver.hpp"
#include "SipWireUtil.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

// HoldMusic — music on hold for parked callers (#162).
//
// The pacing task and socket are ESP-only, so what is testable here is the part
// where a bug is silent and maddening: the WAV parser (wrong offset = full-scale
// noise), the cursor wrap (off-by-one = a click once per loop), and the gain table
// (sign fold = a crack instead of clipping).

namespace {

// Build a WAVE_FORMAT_MULAW file the way a real converter does: an 18-byte fmt
// chunk plus a fact chunk, NOT the 44-byte canonical-PCM layout. A reader that
// assumes 44 bytes lands mid-header on exactly this shape.
std::vector<uint8_t> makeUlawWav(uint32_t rate, uint16_t channels, size_t dataBytes,
                                 uint16_t fmtTag = 7, bool withFact = true,
                                 uint8_t fill = 0xFF)
{
    auto put32 = [](std::vector<uint8_t>& v, uint32_t x) {
        v.push_back(uint8_t(x & 0xFF));        v.push_back(uint8_t((x >> 8) & 0xFF));
        v.push_back(uint8_t((x >> 16) & 0xFF)); v.push_back(uint8_t((x >> 24) & 0xFF));
    };
    auto put16 = [](std::vector<uint8_t>& v, uint16_t x) {
        v.push_back(uint8_t(x & 0xFF)); v.push_back(uint8_t((x >> 8) & 0xFF));
    };
    auto putTag = [](std::vector<uint8_t>& v, const char* t) {
        v.insert(v.end(), t, t + 4);
    };

    std::vector<uint8_t> body;
    putTag(body, "WAVE");

    putTag(body, "fmt ");
    put32(body, 18);
    put16(body, fmtTag);
    put16(body, channels);
    put32(body, rate);
    put32(body, rate * channels);   // byte rate
    put16(body, channels);          // block align
    put16(body, 8);                 // bits per sample
    put16(body, 0);                 // cbSize

    if (withFact) {
        putTag(body, "fact");
        put32(body, 4);
        put32(body, uint32_t(dataBytes));
    }

    putTag(body, "data");
    put32(body, uint32_t(dataBytes));
    body.insert(body.end(), dataBytes, fill);
    if (dataBytes & 1u) body.push_back(0);

    std::vector<uint8_t> out;
    putTag(out, "RIFF");
    put32(out, uint32_t(body.size()));
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

}  // namespace

// ── WAV parsing ─────────────────────────────────────────────────────────────

TEST(HoldMusic, ParsesAMulawWavAndFindsTheDataChunk)
{
    const auto wav = makeUlawWav(8000, 1, 1600);
    size_t off = 0, len = 0;
    ASSERT_TRUE(HoldMusic::parseUlawWav(wav.data(), wav.size(), off, len));
    EXPECT_EQ(len, 1600u);
    // The data must start where the chunk says, NOT at a hardcoded 44.
    ASSERT_LE(off + len, wav.size());
    EXPECT_EQ(wav[off], 0xFF);
}

TEST(HoldMusic, DoesNotAssumeTheCanonicalFortyFourByteHeader)
{
    // A mu-law WAV's fmt chunk is 18 bytes and it carries a fact chunk, so the
    // data offset is NOT 44. Pinning this is the whole point: a "skip 44" reader
    // plays part of the header as audio and the rest shifted by a few bytes.
    const auto wav = makeUlawWav(8000, 1, 800);
    size_t off = 0, len = 0;
    ASSERT_TRUE(HoldMusic::parseUlawWav(wav.data(), wav.size(), off, len));
    EXPECT_NE(off, 44u) << "test fixture no longer exercises the non-44 case";
}

TEST(HoldMusic, SkipsUnknownChunksBeforeData)
{
    // Converters routinely insert LIST/INFO. Walking the chunk list must step over
    // them rather than giving up or mistaking them for audio.
    auto wav = makeUlawWav(8000, 1, 320);
    // splice a LIST chunk in front of "data"
    const std::string needle = "data";
    auto it = std::search(wav.begin(), wav.end(), needle.begin(), needle.end());
    ASSERT_NE(it, wav.end());
    std::vector<uint8_t> list = { 'L','I','S','T', 8,0,0,0, 'I','N','F','O','x','y','z','w' };
    wav.insert(it, list.begin(), list.end());
    // RIFF size is now stale, but the parser is driven by chunk walking, and it
    // must bound itself by the buffer length rather than trusting that field.
    size_t off = 0, len = 0;
    ASSERT_TRUE(HoldMusic::parseUlawWav(wav.data(), wav.size(), off, len));
    EXPECT_EQ(len, 320u);
}

TEST(HoldMusic, RejectsWrongFormatLoudlyRatherThanPlayingNoise)
{
    size_t off = 0, len = 0;
    // PCM (tag 1) rather than mu-law: read as mu-law this is full-scale noise.
    const auto pcm = makeUlawWav(8000, 1, 800, /*fmtTag=*/1);
    EXPECT_FALSE(HoldMusic::parseUlawWav(pcm.data(), pcm.size(), off, len));

    // 44.1 kHz: would play 5.5x too fast.
    const auto fast = makeUlawWav(44100, 1, 800);
    EXPECT_FALSE(HoldMusic::parseUlawWav(fast.data(), fast.size(), off, len));

    // Stereo: interleaved channels read as mono is a garbled mess.
    const auto stereo = makeUlawWav(8000, 2, 800);
    EXPECT_FALSE(HoldMusic::parseUlawWav(stereo.data(), stereo.size(), off, len));
}

TEST(HoldMusic, RejectsTruncatedAndNonRiffInput)
{
    size_t off = 0, len = 0;
    EXPECT_FALSE(HoldMusic::parseUlawWav(nullptr, 100, off, len));

    const uint8_t junk[64] = {0};
    EXPECT_FALSE(HoldMusic::parseUlawWav(junk, sizeof(junk), off, len));

    const auto wav = makeUlawWav(8000, 1, 1600);
    EXPECT_FALSE(HoldMusic::parseUlawWav(wav.data(), 20, off, len));   // header only
}

TEST(HoldMusic, RejectsAClipShorterThanOneTick)
{
    // Less than 160 bytes means the pacing task has nothing whole to send.
    size_t off = 0, len = 0;
    const auto tiny = makeUlawWav(8000, 1, 64);
    EXPECT_FALSE(HoldMusic::parseUlawWav(tiny.data(), tiny.size(), off, len));
}

TEST(HoldMusic, LeavesOutputsUntouchedOnFailure)
{
    size_t off = 12345, len = 67890;
    const auto pcm = makeUlawWav(8000, 1, 800, /*fmtTag=*/1);
    EXPECT_FALSE(HoldMusic::parseUlawWav(pcm.data(), pcm.size(), off, len));
    EXPECT_EQ(off, 12345u);
    EXPECT_EQ(len, 67890u);
}

// ── Cursor wrap: the radio-station loop point ───────────────────────────────

TEST(HoldMusic, CursorAdvancesByExactlyOneTick)
{
    EXPECT_EQ(HoldMusic::advanceCursor(0, 16000), HoldMusic::BYTES_PER_TICK);
    EXPECT_EQ(HoldMusic::advanceCursor(160, 16000), 320u);
}

TEST(HoldMusic, CursorWrapsWithoutLosingTheTail)
{
    // The killer case: a clip length that is NOT a whole number of ticks. Clamping
    // to zero on overflow would silently drop the last partial frame every lap --
    // a click once per loop, which gets reported as "it sounds slightly off" and
    // never found. Modulo keeps the loop seamless and phase-correct.
    const size_t clip = 1000;                 // 6.25 ticks
    size_t c = 960;                           // one tick short of the end
    c = HoldMusic::advanceCursor(c, clip);
    EXPECT_EQ(c, 120u) << "must carry the remainder across the loop point";

    // And the total distance travelled over a full lap is exactly the clip length.
    size_t pos = 0;
    size_t travelled = 0;
    for (int i = 0; i < 25; ++i) {
        pos = HoldMusic::advanceCursor(pos, clip);
        travelled += HoldMusic::BYTES_PER_TICK;
    }
    EXPECT_EQ(pos, travelled % clip);
}

TEST(HoldMusic, CursorIsSafeOnAnEmptyClip)
{
    EXPECT_EQ(HoldMusic::advanceCursor(0, 0), 0u);
    EXPECT_EQ(HoldMusic::advanceCursor(500, 0), 0u);
}

// ── Gain table ──────────────────────────────────────────────────────────────

TEST(HoldMusic, UnityGainPreservesTheDecodedValue)
{
    uint8_t t[256];
    HoldMusic::buildGainTable(0.0f, t);
    // NOT byte-identity, and that is correct rather than a compromise: mu-law is a
    // redundant code. 0x7F and 0xFF both decode to 0 (pinned by RtpReceiver_test's
    // UlawDecode.KnownSamples), so a decode/re-encode round trip necessarily
    // collapses each redundant pair onto one canonical code. The property that
    // matters for audio is that the SAMPLE VALUE is unchanged.
    for (int i = 0; i < 256; ++i) {
        EXPECT_EQ(RtpReceiver::mulawDecode(t[i]), RtpReceiver::mulawDecode(uint8_t(i)))
            << "code " << i << " changed value at unity gain";
    }
}

TEST(HoldMusic, UnityGainIsSkippedEntirelyAtRuntime)
{
    // Because of that redundancy, running the table at unity would silently
    // re-canonicalise every byte of the clip for no benefit. The pacing task
    // therefore branches on _gainIsUnity and does a straight memcpy instead --
    // which is the whole reason the clip is stored as mu-law. This test documents
    // the invariant the implementation relies on: at unity the table is a no-op on
    // VALUE, so skipping it cannot change what the listener hears.
    uint8_t t[256];
    HoldMusic::buildGainTable(0.0f, t);
    int changedBytes = 0;
    for (int i = 0; i < 256; ++i) if (t[i] != uint8_t(i)) ++changedBytes;
    // Only the redundant codes may move, and they must still decode identically.
    for (int i = 0; i < 256; ++i) {
        if (t[i] != uint8_t(i)) {
            EXPECT_EQ(RtpReceiver::mulawDecode(t[i]), RtpReceiver::mulawDecode(uint8_t(i)))
                << "code " << i << " is not merely a redundant-pair collapse";
        }
    }
    EXPECT_LT(changedBytes, 8) << "unity gain should touch only redundant codes";
}

TEST(HoldMusic, PositiveGainRaisesAmplitude)
{
    uint8_t t[256];
    HoldMusic::buildGainTable(6.0f, t);
    // A mid-level code should decode louder after the table than before it.
    const uint8_t code = 0xD5;
    const int16_t before = RtpReceiver::mulawDecode(code);
    const int16_t after  = RtpReceiver::mulawDecode(t[code]);
    ASSERT_GT(before, 0);
    EXPECT_GT(after, before);
}

TEST(HoldMusic, LoudGainClipsRatherThanFoldingSign)
{
    // The trap: scaling in float and casting to int16 without clamping wraps a
    // loud positive sample to a large NEGATIVE one, which is heard as a crack
    // rather than as clipping. Every entry must keep its sign.
    uint8_t t[256];
    HoldMusic::buildGainTable(40.0f, t);
    for (int i = 0; i < 256; ++i) {
        const int16_t before = RtpReceiver::mulawDecode(uint8_t(i));
        const int16_t after  = RtpReceiver::mulawDecode(t[i]);
        if (before > 0)      EXPECT_GT(after, 0) << "code " << i << " folded negative";
        else if (before < 0) EXPECT_LT(after, 0) << "code " << i << " folded positive";
    }
}

TEST(HoldMusic, SilenceCodeIsMulawZeroNotByteZero)
{
    // 0x00 is FULL-SCALE NEGATIVE in mu-law. Filling a gap with it would be a loud
    // click; 0xFF is the code that decodes to zero.
    EXPECT_EQ(RtpReceiver::mulawDecode(HoldMusic::kUlawSilence), 0);
    EXPECT_NE(RtpReceiver::mulawDecode(0x00), 0);
}

// ── The park answer ─────────────────────────────────────────────────────────

TEST(HoldMusic, SendonlyAnswerAdvertisesARealPortAndDirection)
{
    const std::string sdp = sipwire::makeSendonlySdp("192.168.9.1", 41000);
    EXPECT_NE(sdp.find("m=audio 41000 RTP/AVP 0\r\n"), std::string::npos) << sdp;
    EXPECT_NE(sdp.find("a=sendonly\r\n"), std::string::npos) << sdp;
    EXPECT_NE(sdp.find("a=rtpmap:0 PCMU/8000\r\n"), std::string::npos) << sdp;
    EXPECT_NE(sdp.find("c=IN IP4 192.168.9.1\r\n"), std::string::npos) << sdp;
    // sendrecv would invite the parked phone to stream audio nothing reads.
    EXPECT_EQ(sdp.find("a=sendrecv"), std::string::npos) << sdp;
    // and it must NOT be the old discard-port silent answer
    EXPECT_EQ(sdp.find("m=audio 9 "), std::string::npos) << sdp;
}

// ── Reading the parked party's RTP endpoint ─────────────────────────────────

namespace {
sockaddr_in from(const char* ip)
{
    sockaddr_in s{};
    s.sin_family = AF_INET;
    s.sin_addr.s_addr = inet_addr(ip);
    return s;
}
}  // namespace

TEST(HoldMusic, ReadsConnectionAddressAndPortFromSdp)
{
    const std::string sdp =
        "v=0\r\no=- 1 1 IN IP4 192.168.9.50\r\ns=-\r\n"
        "c=IN IP4 192.168.9.50\r\nt=0 0\r\n"
        "m=audio 40002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
    std::string ip; uint16_t port = 0;
    ASSERT_TRUE(sipwire::parseRtpTarget(sdp, from("10.0.0.7"), ip, port));
    EXPECT_EQ(ip, "192.168.9.50");
    EXPECT_EQ(port, 40002);
}

TEST(HoldMusic, FallsBackToTheSignallingSourceWhenConnectionIsUnusable)
{
    // 0.0.0.0 is the legacy RFC 2543 hold form some handsets still send, and a
    // NATed phone advertises a private c= it cannot receive on. The address the
    // SIP message actually arrived from is the one known to work.
    const std::string sdp =
        "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\n"
        "c=IN IP4 0.0.0.0\r\nt=0 0\r\n"
        "m=audio 40004 RTP/AVP 0\r\n";
    std::string ip; uint16_t port = 0;
    ASSERT_TRUE(sipwire::parseRtpTarget(sdp, from("10.0.0.7"), ip, port));
    EXPECT_EQ(ip, "10.0.0.7");
    EXPECT_EQ(port, 40004);
}

TEST(HoldMusic, RefusesPortsThatMeanNoAudio)
{
    std::string ip; uint16_t port = 0;
    // port 9 = discard (the old silent hold answer); port 0 = stream disabled.
    const std::string nine =
        "v=0\r\nc=IN IP4 192.168.9.50\r\nm=audio 9 RTP/AVP 0\r\na=inactive\r\n";
    EXPECT_FALSE(sipwire::parseRtpTarget(nine, from("10.0.0.7"), ip, port));

    const std::string zero =
        "v=0\r\nc=IN IP4 192.168.9.50\r\nm=audio 0 RTP/AVP 0\r\n";
    EXPECT_FALSE(sipwire::parseRtpTarget(zero, from("10.0.0.7"), ip, port));

    const std::string none = "v=0\r\nc=IN IP4 192.168.9.50\r\n";
    EXPECT_FALSE(sipwire::parseRtpTarget(none, from("10.0.0.7"), ip, port));
}

TEST(HoldMusic, DoesNotWrapAnOversizePortIntoAValidOne)
{
    // 65536 truncated to uint16 would become 0; 70000 would become 4464 -- a
    // plausible-looking port we would then transmit to.
    std::string ip; uint16_t port = 0;
    const std::string big =
        "v=0\r\nc=IN IP4 192.168.9.50\r\nm=audio 70000 RTP/AVP 0\r\n";
    EXPECT_FALSE(sipwire::parseRtpTarget(big, from("10.0.0.7"), ip, port));
}

// ── Listener table ──────────────────────────────────────────────────────────

TEST(HoldMusic, RefusesListenersUntilStarted)
{
    HoldMusic moh;
    EXPECT_FALSE(moh.isLoaded());
    // Never hand out a listener id for a stream that is not running: park would
    // then answer with a port that stays silent, which is worse than answering
    // a=inactive and being honest about it.
    EXPECT_EQ(moh.addListener("192.168.9.50", 40002), -1);
    EXPECT_EQ(moh.listenerCount(), 0u);
}

TEST(HoldMusic, RemoveListenerIsSafeOnOutOfRangeIds)
{
    // releaseSlot() calls this with whatever the slot held, including -1 for a
    // park that never got audio.
    HoldMusic moh;
    moh.removeListener(-1);
    moh.removeListener(9999);
    EXPECT_EQ(moh.listenerCount(), 0u);
}

TEST(HoldMusic, ListenerCapacityMatchesTheParkOrbitCount)
{
    // Every parked call can be listening at once, and none of them should be the
    // one that silently gets nothing.
    EXPECT_EQ(HoldMusic::kMaxListeners, size_t(POCKETDIAL_PARK_SLOTS));
}

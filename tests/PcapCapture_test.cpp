// Tests for the /api/pcap ring buffer + libpcap serializer (src/SIP/PcapCapture.hpp,
// Issue #33). Wire-level: the point of this class is producing bytes Wireshark can
// open, so assertions check the actual framing rather than just "it didn't crash".

#include <gtest/gtest.h>

#include "AllocCounter.hpp"
#include "PcapCapture.hpp"
#include "SipMessage.hpp"
#include "RequestsHandler.hpp"
#include "HttpServer.hpp"
#include "AdminAuth.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <array>
#include <chrono>
#include <memory>
#include <thread>

namespace
{
	sockaddr_in addr(const char* ip, uint16_t port)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_port   = htons(port);
		::inet_pton(AF_INET, ip, &a.sin_addr);
		return a;
	}

	// Pulls the global-header snaplen/network fields out so a test can assert on
	// them without hand-parsing the whole file.
	uint32_t leU32At(const std::string& buf, size_t off)
	{
		return static_cast<uint32_t>(static_cast<unsigned char>(buf[off])) |
		       (static_cast<uint32_t>(static_cast<unsigned char>(buf[off + 1])) << 8) |
		       (static_cast<uint32_t>(static_cast<unsigned char>(buf[off + 2])) << 16) |
		       (static_cast<uint32_t>(static_cast<unsigned char>(buf[off + 3])) << 24);
	}

	bool canConnect(int port)
	{
#if defined(_WIN32) || defined(_WIN64)
		SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
		if (s == INVALID_SOCKET) return false;
#else
		int s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0) return false;
#endif
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_port = htons(static_cast<uint16_t>(port));
		inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
		int rc = connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a));
#if defined(_WIN32) || defined(_WIN64)
		closesocket(s);
#else
		close(s);
#endif
		return rc == 0;
	}

	// Minimal blocking HTTP GET over a raw socket — mirrors the pattern
	// AdminHttpGate_test.cpp uses for POST. Returns the full raw response
	// (status line + headers + body). `cookie`, when non-empty, is sent as the
	// session cookie -- /api/trace and /api/diagnostics/pcap require a
	// logged-in session now (there is no more "unprovisioned, no session
	// needed" bypass).
	std::string httpGetRaw(int port, const std::string& path, const std::string& cookie = "")
	{
#if defined(_WIN32) || defined(_WIN64)
		SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
		if (s == INVALID_SOCKET) return "";
#else
		int s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0) return "";
#endif
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_port = htons(static_cast<uint16_t>(port));
		inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
		if (connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0)
		{
#if defined(_WIN32) || defined(_WIN64)
			closesocket(s);
#else
			close(s);
#endif
			return "";
		}
		std::string cookieHeader = cookie.empty() ? "" : ("Cookie: " + cookie + "\r\n");
		std::string req = "GET " + path + " HTTP/1.1\r\n"
			"Host: 127.0.0.1\r\n" + cookieHeader + "Connection: close\r\n\r\n";
		send(s, req.c_str(), static_cast<int>(req.size()), 0);
		std::string resp;
		char buf[512];
		int n;
		while ((n = recv(s, buf, sizeof(buf), 0)) > 0)
		{
			resp.append(buf, static_cast<size_t>(n));
		}
#if defined(_WIN32) || defined(_WIN64)
		closesocket(s);
#else
		close(s);
#endif
		return resp;
	}
}

TEST(PcapCapture, EmptyRingProducesValidGlobalHeaderOnly)
{
	PcapCapture cap;
	std::string file = cap.toPcapFile("192.168.1.10", 5060);

	ASSERT_EQ(file.size(), 24u);   // global header only, no records
	// Magic number 0xa1b2c3d4 written little-endian.
	EXPECT_EQ(static_cast<unsigned char>(file[0]), 0xd4);
	EXPECT_EQ(static_cast<unsigned char>(file[1]), 0xc3);
	EXPECT_EQ(static_cast<unsigned char>(file[2]), 0xb2);
	EXPECT_EQ(static_cast<unsigned char>(file[3]), 0xa1);
	EXPECT_EQ(leU32At(file, 20), 1u) << "LINKTYPE_ETHERNET";
}

TEST(PcapCapture, CapturedPayloadBytesAppearVerbatimInOutput)
{
	PcapCapture cap;
	const sockaddr_in peer = addr("192.168.1.50", 5060);
	const std::string invite = "INVITE sip:101@192.168.1.10 SIP/2.0\r\nCall-ID: abc123@peer\r\n";

	cap.record(/*outbound=*/false, peer, invite);
	std::string file = cap.toPcapFile("192.168.1.10", 5060);

	// Global header (24) + one record header (16) + Ethernet(14)+IPv4(20)+UDP(8)
	// + the payload appended verbatim.
	ASSERT_EQ(file.size(), 24u + 16u + 14u + 20u + 8u + invite.size());
	EXPECT_NE(file.find(invite), std::string::npos)
		<< "raw SIP bytes must appear unmodified in the synthesized frame";
}

TEST(PcapCapture, DirectionSelectsWhichSideIsSource)
{
	PcapCapture cap;
	const sockaddr_in peer = addr("192.168.1.50", 5061);

	cap.record(/*outbound=*/false, peer, "inbound-marker");   // peer -> local
	cap.record(/*outbound=*/true,  peer, "outbound-marker");  // local -> peer
	std::string file = cap.toPcapFile("192.168.1.10", 5060);

	// Both payloads present; a byte-exact IP-header assertion would duplicate the
	// class's own arithmetic, so this just pins that both directions are
	// captured and don't collide/overwrite each other.
	EXPECT_NE(file.find("inbound-marker"), std::string::npos) << file;
	EXPECT_NE(file.find("outbound-marker"), std::string::npos) << file;
}

TEST(PcapCapture, RingDropsOldestPastCapacity)
{
	PcapCapture cap;
	const sockaddr_in peer = addr("192.168.1.50", 5060);

	// "!" delimiter after the index so e.g. "pkt-4!" can't false-match inside
	// "pkt-40!" the way a bare "pkt-4" substring search would.
	auto marker = [](unsigned i) { return "pkt-" + std::to_string(i) + "!"; };

	const unsigned total = static_cast<unsigned>(POCKETDIAL_PCAP_RING_SIZE) + 5;
	for (unsigned i = 0; i < total; ++i)
	{
		cap.record(false, peer, marker(i));
	}
	ASSERT_EQ(cap.size(), static_cast<std::size_t>(POCKETDIAL_PCAP_RING_SIZE));

	std::string file = cap.toPcapFile("192.168.1.10", 5060);
	for (unsigned i = 0; i < 5; ++i)
	{
		EXPECT_EQ(file.find(marker(i)), std::string::npos)
			<< "index " << i << " should have been evicted";
	}
	EXPECT_NE(file.find(marker(5)), std::string::npos) << "oldest surviving entry";
	EXPECT_NE(file.find(marker(total - 1)), std::string::npos) << "newest entry must survive";
}

TEST(PcapCapture, ClearEmptiesTheRing)
{
	PcapCapture cap;
	cap.record(false, addr("192.168.1.50", 5060), "x");
	ASSERT_EQ(cap.size(), 1u);
	cap.clear();
	EXPECT_EQ(cap.size(), 0u);
	EXPECT_EQ(cap.toPcapFile("192.168.1.10", 5060).size(), 24u);
}

// ── traceRecords() (GET /api/trace's data source, Issue #32) ───────────────────

TEST(PcapCapture, TraceRecordsReflectSeqDirectionPeerAndText)
{
	PcapCapture cap;
	const sockaddr_in inPeer  = addr("192.168.1.50", 5060);
	const sockaddr_in outPeer = addr("192.168.1.51", 5061);

	cap.record(false, inPeer,  "REGISTER sip:server SIP/2.0");
	cap.record(true,  outPeer, "SIP/2.0 200 OK");

	auto recs = cap.traceRecords();
	ASSERT_EQ(recs.size(), 2u);

	EXPECT_EQ(recs[0].seq, 0u);
	EXPECT_FALSE(recs[0].outbound);
	EXPECT_EQ(recs[0].peer, "192.168.1.50:5060");
	EXPECT_EQ(recs[0].text, "REGISTER sip:server SIP/2.0");

	EXPECT_EQ(recs[1].seq, 1u);
	EXPECT_TRUE(recs[1].outbound);
	EXPECT_EQ(recs[1].peer, "192.168.1.51:5061");
	EXPECT_EQ(recs[1].text, "SIP/2.0 200 OK");
}

TEST(PcapCapture, TraceRecordSeqStaysMonotonicAcrossEviction)
{
	PcapCapture cap;
	const sockaddr_in peer = addr("192.168.1.50", 5060);
	const unsigned total = static_cast<unsigned>(POCKETDIAL_PCAP_RING_SIZE) + 3;
	for (unsigned i = 0; i < total; ++i)
	{
		cap.record(false, peer, "pkt");
	}
	auto recs = cap.traceRecords();
	ASSERT_EQ(recs.size(), static_cast<std::size_t>(POCKETDIAL_PCAP_RING_SIZE));
	// The oldest surviving entry is the 4th packet sent (index 3, 0-based) —
	// its seq must reflect that it's the 4th ever recorded, not the 1st of
	// what's currently in the ring, so a client's high-water mark stays valid
	// after entries roll off rather than seeing seq "restart".
	EXPECT_EQ(recs.front().seq, 3u);
	EXPECT_EQ(recs.back().seq, total - 1);
}

// ── RequestsHandler wiring (GET /api/pcap's actual data source) ────────────────

TEST(PcapCapture, RequestsHandlerCapturesBothDirectionsOfARealPacket)
{
	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});

	EXPECT_EQ(handler.getPcapCapture().size(), 24u) << "empty ring before any traffic";

	const sockaddr_in src = addr("192.168.4.50", 5060);
	const std::string raw =
		"REGISTER sip:server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.4.50:5060;branch=z9hG4bKr\r\n"
		"From: <sip:101@server>;tag=rt\r\n"
		"To: <sip:101@server>\r\n"
		"Call-ID: pcap-test-1\r\n"
		"CSeq: 1 REGISTER\r\n"
		"Contact: <sip:101@192.168.4.50:5060>;expires=3600\r\n"
		"Content-Length: 0\r\n\r\n";
	handler.handle(RequestsHandler::getMessageFromPool(raw, src));

	std::string file = handler.getPcapCapture();
	EXPECT_GT(file.size(), 24u) << "at least the inbound REGISTER must be captured";
	EXPECT_NE(file.find("REGISTER sip:server"), std::string::npos)
		<< "inbound packet bytes must appear verbatim";
	// A REGISTER always gets SOME response — accepted (200), challenged (401) or
	// rejected (403/etc, e.g. an unprovisioned extension under Secure mode,
	// which is the registrar's default) — captured by drainOutbox() regardless
	// of which. This deliberately doesn't assert which status: that's the
	// registrar's admission policy, not this ring buffer's concern.
	EXPECT_NE(file.find("SIP/2.0 "), std::string::npos) << "outbound response must be captured";
}

// Issue #105: the inbound capture must store the bytes recvfrom() actually
// delivered, not a re-serialization of the parsed message. SipMessage::toString()
// always writes CRLF line endings and joins the parsed pieces back together — it
// does not restore whatever line-ending convention or malformed-but-tolerated
// layout the wire bytes actually used. A message with bare-LF endings and compact
// header forms (v:/f:/t:/i:) is valid SIP that the parser tolerates (SEC-02) but
// round-trips through toString() into a different byte sequence, making it a
// direct fixture for the fidelity bug: the capture must equal the ORIGINAL raw
// text, not request->toString().
TEST(PcapCapture, InboundCaptureStoresExactWireBytesNotReserializedMessage)
{
	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});

	const sockaddr_in src = addr("192.168.4.50", 5060);
	const std::string raw =
		"REGISTER sip:server SIP/2.0\n"
		"v: SIP/2.0/UDP 192.168.4.50:5060;branch=z9hG4bKcompact\n"
		"f: <sip:105@server>;tag=rt105\n"
		"t: <sip:105@server>\n"
		"i: pcap-wire-fidelity-1\n"
		"CSeq: 1 REGISTER\n"
		"Contact: <sip:105@192.168.4.50:5060>;expires=3600\n"
		"Content-Length: 0\n\n";

	auto request = RequestsHandler::getMessageFromPool(raw, src);
	ASSERT_TRUE(request != nullptr);
	ASSERT_TRUE(request->isValidMessage());
	// Fixture sanity: if toString() happened to reproduce `raw` byte-for-byte,
	// this test couldn't tell the two capture paths apart.
	ASSERT_NE(request->toString(), raw)
		<< "fixture must actually re-serialize differently via toString(), or "
		   "this test can't distinguish wire bytes from the parsed re-render";

	// Mirrors what SipServer::onNewMessage() now does: pass the exact bytes
	// recvfrom() delivered alongside the already-parsed message.
	handler.handle(request, raw);

	auto recs = handler.getTraceRecords();
	ASSERT_GE(recs.size(), 1u);
	EXPECT_EQ(recs[0].text, raw)
		<< "inbound capture must store the exact wire bytes, not a "
		   "re-serialization of the parsed message";

	std::string file = handler.getPcapCapture();
	EXPECT_NE(file.find(raw), std::string::npos)
		<< "the raw wire text (LF endings, compact headers) must appear "
		   "verbatim in the pcap frame";
}

// The default (no rawBytes passed) must keep behaving exactly as before: a
// message built/handled without wire bytes in hand — an in-process call, or any
// existing test calling handle() with one argument — still gets a toString()
// capture. This is what keeps every pre-#105 handle(msg) call site correct with
// zero changes.
TEST(PcapCapture, InboundCaptureFallsBackToToStringWhenNoRawBytesGiven)
{
	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});

	const sockaddr_in src = addr("192.168.4.51", 5060);
	const std::string raw =
		"REGISTER sip:server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.4.51:5060;branch=z9hG4bKfallback\r\n"
		"From: <sip:106@server>;tag=rt106\r\n"
		"To: <sip:106@server>\r\n"
		"Call-ID: pcap-fallback-1\r\n"
		"CSeq: 1 REGISTER\r\n"
		"Contact: <sip:106@192.168.4.51:5060>;expires=3600\r\n"
		"Content-Length: 0\r\n\r\n";

	auto request = RequestsHandler::getMessageFromPool(raw, src);
	ASSERT_TRUE(request != nullptr);
	const std::string expected = request->toString();

	handler.handle(request);   // no rawBytes argument, same as pre-#105 call sites

	auto recs = handler.getTraceRecords();
	ASSERT_GE(recs.size(), 1u);
	EXPECT_EQ(recs[0].text, expected);
}

TEST(PcapCapture, RequestsHandlerGetTraceRecordsMirrorsGetPcapCapture)
{
	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	EXPECT_TRUE(handler.getTraceRecords().empty());

	const sockaddr_in src = addr("192.168.4.50", 5060);
	const std::string raw =
		"REGISTER sip:server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.4.50:5060;branch=z9hG4bKr2\r\n"
		"From: <sip:102@server>;tag=rt2\r\n"
		"To: <sip:102@server>\r\n"
		"Call-ID: pcap-test-2\r\n"
		"CSeq: 1 REGISTER\r\n"
		"Contact: <sip:102@192.168.4.50:5060>;expires=3600\r\n"
		"Content-Length: 0\r\n\r\n";
	handler.handle(RequestsHandler::getMessageFromPool(raw, src));

	auto recs = handler.getTraceRecords();
	ASSERT_GE(recs.size(), 1u);
	EXPECT_FALSE(recs[0].outbound);
	EXPECT_EQ(recs[0].peer, "192.168.4.50:5060");
	EXPECT_NE(recs[0].text.find("REGISTER sip:server"), std::string::npos);
}

// ── Issue #101(D): the capture path must stop allocating once the ring is full ──
//
// Issue #416: the ring is fixed-size storage inside PcapCapture, so recording a
// packet must never touch the heap. This is desmo's no-allocation-after-init rule
// on the SIP hot path, and the lazily-grown, capacity-ratcheting std::string ring
// it replaced was a suspect for #328's internal-DRAM drift.

namespace
{
	uint32_t readU32LE(const std::string& s, std::size_t at)
	{
		return static_cast<uint32_t>(static_cast<unsigned char>(s[at])) |
		       (static_cast<uint32_t>(static_cast<unsigned char>(s[at + 1])) << 8) |
		       (static_cast<uint32_t>(static_cast<unsigned char>(s[at + 2])) << 16) |
		       (static_cast<uint32_t>(static_cast<unsigned char>(s[at + 3])) << 24);
	}
	uint16_t readU16BE(const std::string& s, std::size_t at)
	{
		return static_cast<uint16_t>((static_cast<unsigned char>(s[at]) << 8) |
		                             static_cast<unsigned char>(s[at + 1]));
	}
}

TEST(PcapCapture, RecordingAllocatesNothingAfterConstruction) {
	auto cap = std::make_unique<PcapCapture>();   // 16 x ~2 KB: keep it off the test's stack
	const sockaddr_in peer = addr("10.0.0.9", 5060);
	// Every payload is built BEFORE the guard: small, SSO-sized, a full slot, and
	// one past the slot, so the truncating path is inside the counted block too.
	const std::string small = "OPTIONS sip:x SIP/2.0\r\n\r\n";
	const std::string invite(1500, 'i');
	const std::string exact(PcapCapture::kSlotBytes, 'e');
	const std::string oversize(PcapCapture::kSlotBytes + 300, 'o');
	SipMessage msg("INVITE sip:200@10.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.9:5060\r\n"
	               "To: <sip:200@10.0.0.1>\r\nFrom: <sip:100@10.0.0.1>;tag=a\r\n"
	               "Call-ID: c1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n", peer);

	AllocGuard guard;
	// Three times round the ring, so filling, wrapping and overwriting are all counted.
	for (std::size_t i = 0; i < PcapCapture::kRingSize * 3; ++i)
	{
		cap->record(false, peer, small);
		cap->record(true,  peer, invite);
		cap->record(false, peer, exact);
		cap->record(true,  peer, oversize);
		cap->recordWith(true, peer, [&msg](char* buf, std::size_t n) { return msg.serializeInto(buf, n); });
	}
	EXPECT_EQ(guard.delta(), 0u) << "PcapCapture::record()/recordWith() touched the heap";
	EXPECT_EQ(cap->size(), PcapCapture::kRingSize);
}

TEST(PcapCapture, SerializeIntoAllocatesNothingAndMatchesToString) {
	const sockaddr_in peer = addr("10.0.0.9", 5060);
	SipMessage msg("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.0.9:5060\r\nTo: <sip:a@b>;tag=t\r\n"
	               "From: <sip:c@d>;tag=f\r\nCall-ID: z\r\nCSeq: 2 INVITE\r\n"
	               "Content-Type: application/sdp\r\nContent-Length: 4\r\n\r\nv=0\n", peer);
	const std::string expected = msg.toString();
	std::array<char, 4096> buf{};

	AllocGuard guard;
	const std::size_t full = msg.serializeInto(buf.data(), buf.size());
	EXPECT_EQ(guard.delta(), 0u);
	ASSERT_EQ(full, expected.size());
	EXPECT_EQ(std::string(buf.data(), full), expected);

	// Truncated: writes exactly `cap` bytes, still reports the full length, and
	// leaves everything past `cap` untouched.
	std::array<char, 40> small;
	small.fill('#');
	const std::size_t cap = 25;
	EXPECT_EQ(msg.serializeInto(small.data(), cap), expected.size());
	EXPECT_EQ(std::string(small.data(), cap), expected.substr(0, cap));
	EXPECT_EQ(small[cap], '#');
}

TEST(PcapCapture, OversizeMessageIsTruncatedAndFlaggedNotReallocated) {
	auto cap = std::make_unique<PcapCapture>();
	const sockaddr_in peer = addr("10.0.0.9", 5060);
	const std::size_t extra = 300;
	std::string big(PcapCapture::kSlotBytes + extra, 'x');
	big.replace(0, 5, "HEAD:");
	cap->record(true, peer, big);
	cap->record(false, peer, "fits");

	auto recs = cap->traceRecords();
	ASSERT_EQ(recs.size(), 2u);
	EXPECT_TRUE(recs[0].truncated);
	EXPECT_EQ(recs[0].text.size(), PcapCapture::kSlotBytes);
	EXPECT_EQ(recs[0].text, big.substr(0, PcapCapture::kSlotBytes));
	EXPECT_FALSE(recs[1].truncated);
	EXPECT_EQ(recs[1].text, "fits");

	// In the pcap file the truncation is visible the standard way: incl_len is
	// what was kept, orig_len and the IP/UDP length fields are the real size.
	const std::string file = cap->toPcapFile("10.0.0.1", 5060);
	const std::size_t rec0 = 24;
	const uint32_t incl = readU32LE(file, rec0 + 8);
	const uint32_t orig = readU32LE(file, rec0 + 12);
	EXPECT_EQ(incl, 14u + 20u + 8u + PcapCapture::kSlotBytes);
	EXPECT_EQ(orig, incl + extra);
	const std::size_t ip = rec0 + 16 + 14;
	EXPECT_EQ(readU16BE(file, ip + 2), 20u + 8u + big.size());       // IPv4 total length
	EXPECT_EQ(readU16BE(file, ip + 20 + 4), 8u + big.size());        // UDP length

	// The following record starts exactly after the kept bytes, so the file still parses.
	const std::size_t rec1 = rec0 + 16 + incl;
	EXPECT_EQ(readU32LE(file, rec1 + 8), readU32LE(file, rec1 + 12));
	EXPECT_EQ(file.size(), rec1 + 16 + readU32LE(file, rec1 + 8));
}

TEST(PcapCapture, AMessageExactlyOneSlotLongIsNotFlaggedTruncated) {
	auto cap = std::make_unique<PcapCapture>();
	const std::string exact(PcapCapture::kSlotBytes, 'e');
	cap->record(false, addr("10.0.0.9", 5060), exact);
	auto recs = cap->traceRecords();
	ASSERT_EQ(recs.size(), 1u);
	EXPECT_FALSE(recs[0].truncated);
	EXPECT_EQ(recs[0].text, exact);
}

// The ring must not grow past its cap, and clear() must restart ordering.
TEST(PcapCapture, RingSizeSaturatesAtCapacityAndClearResetsOrdering) {
	PcapCapture cap;
	const sockaddr_in peer = addr("10.0.0.9", 5060);

	for (size_t i = 0; i < POCKETDIAL_PCAP_RING_SIZE * 3; ++i)
	{
		cap.record(false, peer, "PING " + std::to_string(i));
	}
	EXPECT_EQ(cap.size(), POCKETDIAL_PCAP_RING_SIZE);

	// Still oldest-first after multiple wraps, and holding the LAST ring-size
	// packets — storage order and capture order have diverged by now, so this is
	// really checking that every reader goes through the ring head.
	auto recs = cap.traceRecords();
	ASSERT_EQ(recs.size(), POCKETDIAL_PCAP_RING_SIZE);
	const size_t firstKept = POCKETDIAL_PCAP_RING_SIZE * 3 - POCKETDIAL_PCAP_RING_SIZE;
	for (size_t i = 0; i < recs.size(); ++i)
	{
		EXPECT_EQ(recs[i].text, "PING " + std::to_string(firstKept + i)) << "index " << i;
		if (i > 0) EXPECT_GT(recs[i].seq, recs[i - 1].seq) << "index " << i;
	}

	// clear() has to reset the head too, or the next fill reads out rotated.
	cap.clear();
	EXPECT_EQ(cap.size(), 0u);
	cap.record(false, peer, "AFTER-CLEAR-0");
	cap.record(false, peer, "AFTER-CLEAR-1");
	auto after = cap.traceRecords();
	ASSERT_EQ(after.size(), 2u);
	EXPECT_EQ(after[0].text, "AFTER-CLEAR-0");
	EXPECT_EQ(after[1].text, "AFTER-CLEAR-1");
}

// The pcap file itself must also come out in capture order after a wrap: the
// serializer walks the same ring and writes one record per entry, oldest first.
TEST(PcapCapture, PcapFileStaysInCaptureOrderAfterWrap) {
	PcapCapture cap;
	const sockaddr_in peer = addr("10.0.0.9", 5060);
	for (size_t i = 0; i < POCKETDIAL_PCAP_RING_SIZE + 3; ++i)
	{
		cap.record(false, peer, "SEQ" + std::to_string(i) + "-payload");
	}

	const std::string file = cap.toPcapFile("10.0.0.1", 5060);
	// Oldest surviving packet is #3; it must appear before #4, and so on.
	size_t prev = 0;
	for (size_t i = 3; i < POCKETDIAL_PCAP_RING_SIZE + 3; ++i)
	{
		const std::string needle = "SEQ" + std::to_string(i) + "-payload";
		const size_t at = file.find(needle);
		ASSERT_NE(at, std::string::npos) << needle << " missing from pcap";
		EXPECT_GT(at, prev) << needle << " out of capture order";
		prev = at;
	}
	// And the evicted ones are gone.
	EXPECT_EQ(file.find("SEQ0-payload"), std::string::npos);
	EXPECT_EQ(file.find("SEQ2-payload"), std::string::npos);
}

// Now that #105 lets GET /api/trace carry the exact wire bytes of an inbound
// packet (not a toString() re-render), a malformed-but-tolerated packet
// containing a raw control byte must not break the JSON response — jsonEscape()
// in HttpServer.cpp must escape every C0 control byte (RFC 8259 §7), not just
// the five with named escapes (\", \\, \n, \r, \t).
//
// Ports: this file owns 18115-18119 (issue #213 — every HTTP test file gets
// a disjoint block; see CONTRIBUTING_FIRMWARE.md for the full table).
TEST(PcapCapture, ApiTraceEscapesRawControlBytesFromWireCapture)
{
	// /api/trace requires a logged-in session (requireAdmin) -- go straight to
	// AdminAuth for one rather than a full HTTP login round trip, which isn't
	// what this test is about. Explicit rather than relying on whatever state
	// an earlier test in this binary left AdminAuth in.
	AdminAuth::clearCredential();
	ASSERT_TRUE(AdminAuth::setLoginCredential("admin", "realpassword123"));
	std::string sessionCookie = "pd_session=" + AdminAuth::createSession();

	RequestsHandler handler("127.0.0.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18115, nullptr);
	server.attachHandler(&handler);
	server.start();

	const sockaddr_in src = addr("192.168.4.60", 5060);
	// A \x01 control byte sitting inside an otherwise well-formed header value
	// (e.g. what a malformed-but-tolerated Call-ID might carry) — the kind of
	// byte toString() would never reproduce but the raw wire capture will.
	const std::string raw =
		"REGISTER sip:server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.4.60:5060;branch=z9hG4bKctrl\r\n"
		"From: <sip:107@server>;tag=rt107\r\n"
		"To: <sip:107@server>\r\n"
		"Call-ID: ctrlbyte-\x01-test\r\n"
		"CSeq: 1 REGISTER\r\n"
		"Contact: <sip:107@192.168.4.60:5060>;expires=3600\r\n"
		"Content-Length: 0\r\n\r\n";

	auto request = RequestsHandler::getMessageFromPool(raw, src);
	ASSERT_TRUE(request != nullptr);
	handler.handle(request, raw);

	const std::string resp = httpGetRaw(18115, "/api/trace", sessionCookie);
	ASSERT_NE(resp.find("200"), std::string::npos) << "expected a 200 OK, got: " << resp;

	size_t bodyStart = resp.find("\r\n\r\n");
	ASSERT_NE(bodyStart, std::string::npos);
	const std::string body = resp.substr(bodyStart + 4);

	EXPECT_EQ(body.find('\x01'), std::string::npos)
		<< "raw control byte must not appear unescaped in the JSON body: " << body;
	EXPECT_NE(body.find("\\u0001"), std::string::npos)
		<< "control byte must be escaped as \\u0001: " << body;
}

// ── GET /api/diagnostics/pcap (Issue #33) ───────────────────────────────────
//
// The canonical path the original feature request asked for. It routes to the
// exact same sendApiPcap() handler as /api/pcap (see HttpServer.cpp) — no
// second capture mechanism, no second allocation path — so this test drives it
// over a real socket the way a `curl -o dump.pcap` client would, and checks
// the actual bytes on the wire: the 24-byte global header's magic number, and
// one full 16-byte record header + synthesized frame for a captured packet.
TEST(PcapCapture, ApiDiagnosticsPcapServesValidGlobalHeaderAndOneRecordOverRealSocket)
{
	// /api/diagnostics/pcap requires a logged-in session (requireAdmin) -- go
	// straight to AdminAuth for one, same as HttpTraceCommand_test.cpp's
	// equivalent test. Explicit rather than relying on whatever AdminAuth
	// state an earlier test in the same binary left behind.
	AdminAuth::clearCredential();
	ASSERT_TRUE(AdminAuth::setLoginCredential("admin", "realpassword123"));
	std::string sessionCookie = "pd_session=" + AdminAuth::createSession();

	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18116, nullptr);
	server.attachHandler(&handler);
	server.start();

	for (int i = 0; i < 50 && !canConnect(18116); ++i)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	ASSERT_TRUE(canConnect(18116));

	const sockaddr_in src = addr("192.168.4.80", 5060);
	const std::string raw =
		"REGISTER sip:server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.4.80:5060;branch=z9hG4bKdiag\r\n"
		"From: <sip:108@server>;tag=rt108\r\n"
		"To: <sip:108@server>\r\n"
		"Call-ID: diagnostics-pcap-test\r\n"
		"CSeq: 1 REGISTER\r\n"
		"Contact: <sip:108@192.168.4.80:5060>;expires=3600\r\n"
		"Content-Length: 0\r\n\r\n";
	handler.handle(RequestsHandler::getMessageFromPool(raw, src));

	const std::string resp = httpGetRaw(18116, "/api/diagnostics/pcap", sessionCookie);
	ASSERT_NE(resp.find("200"), std::string::npos) << resp;
	ASSERT_NE(resp.find("application/vnd.tcpdump.pcap"), std::string::npos) << resp;
	ASSERT_NE(resp.find("Content-Disposition: attachment"), std::string::npos) << resp;

	const size_t bodyStart = resp.find("\r\n\r\n");
	ASSERT_NE(bodyStart, std::string::npos);
	const std::string body = resp.substr(bodyStart + 4);

	// Global header: at least the 24 bytes must be present, magic number
	// 0xa1b2c3d4 written little-endian, LINKTYPE_ETHERNET = 1.
	ASSERT_GE(body.size(), 24u + 16u) << "expected a global header plus at least one record";
	EXPECT_EQ(static_cast<unsigned char>(body[0]), 0xd4);
	EXPECT_EQ(static_cast<unsigned char>(body[1]), 0xc3);
	EXPECT_EQ(static_cast<unsigned char>(body[2]), 0xb2);
	EXPECT_EQ(static_cast<unsigned char>(body[3]), 0xa1);
	EXPECT_EQ(leU32At(body, 20), 1u) << "LINKTYPE_ETHERNET";

	// First per-packet record header (16 bytes right after the global header):
	// ts_sec, ts_usec, incl_len, orig_len. incl_len must equal orig_len (this
	// capture never truncates), and the frame it describes — Ethernet(14) +
	// IPv4(20) + UDP(8) + payload — must actually fit in what follows, and
	// must contain the captured REGISTER's raw bytes verbatim.
	const uint32_t inclLen = leU32At(body, 24 + 8);
	const uint32_t origLen = leU32At(body, 24 + 12);
	EXPECT_EQ(inclLen, origLen);
	EXPECT_GE(inclLen, 14u + 20u + 8u) << "frame must be at least Eth+IPv4+UDP headers";
	// A REGISTER always draws some response (200/401/403/etc, captured
	// outbound too), so at least a second record follows this one — assert
	// the first record's declared length actually fits inside the body rather
	// than assuming exactly one record.
	ASSERT_GE(body.size(), 24u + 16u + inclLen)
		<< "first record's frame must fit within the response body";
	EXPECT_NE(body.find("REGISTER sip:server"), std::string::npos)
		<< "captured SIP bytes must appear verbatim in the record's frame";
}

// #328 follow-up. Every other test in this file references
// POCKETDIAL_PCAP_RING_SIZE symbolically, so they pass at any value and none of
// them would notice the DEFAULT going back up. That default is the whole point:
// this ring holds a full copy of every SIP message in and out, in INTERNAL
// DRAM, unconditionally, and by design never shrinks.
//
// #278 measured it at ~52 KB steady state on .244 at 64 slots and confirmed
// shrinking it conserved 91% of the drain -- then shipped only the override
// plumbing and left the default at 64, which no build overrides. A 2026-09-21
// heap_trace attribution run found the inbound (RequestsHandler::handle) and
// outbound (drainOutbox) capture sites are the two single largest internal-DRAM
// consumers on an idle board.
//
// So this test exists to make raising the default fail loudly with the reason
// attached, rather than quietly re-spending tens of KB of the ~80 KB this board
// has -- the same headroom whose absence lets ~12 concurrent HTTP requests
// (#368) or a few minutes of hold music (#328) knock out the W5500's DMA
// bounce buffer.
TEST(PcapCapture, DefaultRingSizeStaysOffTheInternalDramBudget)
{
	EXPECT_LE(POCKETDIAL_PCAP_RING_SIZE, 16)
		<< "the pcap ring holds full SIP messages in internal DRAM and never "
		   "shrinks; #278 measured 64 slots at ~52 KB. Raising this spends "
		   "internal DRAM the board does not have -- override it per-build "
		   "(-DPOCKETDIAL_PCAP_RING_SIZE=N) instead of moving the default.";

	// Still more depth than the RING_SIZE=8 treatment #278 actually validated,
	// so this is not a silent slide toward "capture nothing" either.
	EXPECT_GE(POCKETDIAL_PCAP_RING_SIZE, 8)
		<< "below 8 gives less post-incident capture than #278's own experiment";
}

// SmtpDialogue_test.cpp — issue #159 acceptance: "SMTP dialogue state machine
// against a fake server (greeting, EHLO capability parsing, each AUTH
// variant, 4xx/5xx handling, DATA dot-stuffing, timeouts)".
//
// Two layers of coverage:
//   1. Pure unit tests of the exported helpers (base64, EHLO capability
//      parsing, address splitting, dot-stuffing, the chunked base64 writer,
//      the RFC 5322 date formatter) -- no socket at all.
//   2. End-to-end tests that drive SmtpDialogue::run() against a REAL
//      SmtpClient::SmtpTransport connected over loopback TCP to a small
//      scripted fake SMTP server, the same "drive the real thing over a real
//      socket" pattern AdminHttpGate_test.cpp uses for HttpServer. This is
//      the plain-TCP transport code path -- identical on host and device
//      (see SmtpClient.hpp); only implicit-TLS connect and the STARTTLS
//      upgrade are ESP-only, and this file's StartTls test pins what the
//      HOST build does when asked to use them: fail cleanly, not crash.
//
// Ports: this file owns 18200-18229 (raw sockets, not HttpServer -- see
// CONTRIBUTING_FIRMWARE.md's port table; renumbered from 18130 during a merge
// with #227, which independently claimed 18130-18159 for TwoRoleAuth_test.cpp/
// ConfigExportImport_test.cpp before this file's PR landed -- two PRs picking
// the "next free block" in parallel is exactly the class of collision
// CONTRIBUTING_FIRMWARE.md's table exists to prevent, and it still happened,
// because neither PR could see the other's in-flight choice). ~17
// ScriptedServer instances via the auto-incrementing g_nextPort below, sized
// with headroom per CONTRIBUTING_FIRMWARE.md's own advice for a file with
// "more than a couple" real-socket instances.

#include <gtest/gtest.h>
#include "SmtpDialogue.hpp"
#include "SmtpClient.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define PD_TEST_CLOSESOCK(s) closesocket(s)
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define PD_TEST_CLOSESOCK(s) close(s)
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <functional>
#include <string>
#include <thread>
#include <vector>

namespace
{
	std::atomic<int> g_nextPort{18200};

#if defined(_WIN32) || defined(_WIN64)
	struct WsaInit
	{
		WsaInit() { WSADATA w; WSAStartup(MAKEWORD(2, 2), &w); }
	};
	WsaInit g_wsaInit;
#else
	// A scripted server thread's send() can legitimately race a client that
	// has already given up (a timeout test's client closes and returns while
	// the server thread is still mid-script) -- on real POSIX that raises
	// SIGPIPE, whose default action KILLS THE WHOLE PROCESS, taking every
	// other gtest case in this binary down with it (observed: one such race
	// reported the entire ctest run as a single "(SIGPIPE)" failure). Ignore
	// it so a write to a closed peer just fails with EPIPE/-1 like any other
	// socket error, the same way production code must already treat it.
	struct SigpipeIgnore
	{
		SigpipeIgnore() { std::signal(SIGPIPE, SIG_IGN); }
	};
	SigpipeIgnore g_sigpipeIgnore;
#endif

	int startListener(int port)
	{
		int s = static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
		if (s < 0) return -1;
		int yes = 1;
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr.sin_port = htons(static_cast<uint16_t>(port));
		if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) { PD_TEST_CLOSESOCK(s); return -1; }
		if (listen(s, 1) != 0) { PD_TEST_CLOSESOCK(s); return -1; }
		return s;
	}

	int acceptOne(int listenFd)
	{
		sockaddr_in peer{};
#if defined(_WIN32) || defined(_WIN64)
		int peerLen = sizeof(peer);
#else
		socklen_t peerLen = sizeof(peer);
#endif
		return static_cast<int>(accept(listenFd, reinterpret_cast<sockaddr*>(&peer), &peerLen));
	}

	void srvSend(int fd, const std::string& line)
	{
		std::string wire = line + "\r\n";
		send(fd, wire.data(), static_cast<int>(wire.size()), 0);
	}

	// Reads one CRLF/LF-terminated line from the fake server's side. Simple
	// and blocking -- this harness only ever talks to our own well-behaved
	// client, so it does not need SmtpTransport's own robustness.
	std::string srvRecvLine(int fd)
	{
		std::string buf;
		char c;
		for (;;)
		{
			int n = recv(fd, &c, 1, 0);
			if (n <= 0) return buf;
			if (c == '\n')
			{
				if (!buf.empty() && buf.back() == '\r') buf.pop_back();
				return buf;
			}
			buf += c;
		}
	}

	// Reads the whole DATA block (everything up to and including the "\r\n.\r\n"
	// terminator), returning it WITHOUT the terminator, for assertions on the
	// exact bytes the client streamed.
	std::string srvRecvData(int fd)
	{
		std::string all;
		char c;
		for (;;)
		{
			int n = recv(fd, &c, 1, 0);
			if (n <= 0) break;
			all += c;
			if (all.size() >= 5 && all.compare(all.size() - 5, 5, "\r\n.\r\n") == 0)
			{
				return all.substr(0, all.size() - 5);
			}
		}
		return all;
	}

	// Runs `script(clientFd)` against exactly one accepted connection on a
	// fresh port, in a background thread, and returns the port + a joiner.
	// The caller connects a SmtpTransport to 127.0.0.1:<port> and drives
	// SmtpDialogue::run() while this thread plays the server side.
	struct ScriptedServer
	{
		int port;
		int listenFd;
		std::thread th;

		explicit ScriptedServer(std::function<void(int)> script)
		{
			port = g_nextPort.fetch_add(1);
			listenFd = startListener(port);
			EXPECT_GE(listenFd, 0) << "failed to bind 127.0.0.1:" << port;
			th = std::thread([this, script]() {
				int c = acceptOne(listenFd);
				if (c >= 0)
				{
					script(c);
					PD_TEST_CLOSESOCK(c);
				}
			});
		}
		~ScriptedServer()
		{
			if (th.joinable()) th.join();
			if (listenFd >= 0) PD_TEST_CLOSESOCK(listenFd);
		}
	};

	SmtpDialogue::Config plainConfig(int port)
	{
		SmtpDialogue::Config cfg;
		cfg.host = "127.0.0.1";
		cfg.port = static_cast<uint16_t>(port);
		cfg.mode = SmtpDialogue::Mode::Plain;
		cfg.commandTimeoutMs = 2000;
		return cfg;
	}

	SmtpDialogue::Message basicMessage()
	{
		SmtpDialogue::Message m;
		m.from = "pbx@example.test";
		m.to = "ops@example.test";
		m.subject = "Test";
		m.textBody = "hello from pocket-dial";
		return m;
	}

	SmtpDialogue::SendResult sendOver(int port, const SmtpDialogue::Config& cfgIn, const SmtpDialogue::Message& msg)
	{
		SmtpClient::SmtpTransport transport;
		std::string err;
		SmtpDialogue::Config cfg = cfgIn;
		cfg.port = static_cast<uint16_t>(port);
		if (!transport.connect(cfg, /*allowPlain=*/true, "", false, err))
		{
			SmtpDialogue::SendResult r;
			r.code = SmtpDialogue::ResultCode::ConnectFailed;
			r.lastError = err;
			return r;
		}
		return SmtpDialogue::run(transport, cfg, msg);
	}

	// Standard happy-path server script up through a given point, common to
	// several tests: greeting, EHLO with STARTTLS+every AUTH mechanism
	// advertised.
	void serveGreetingAndEhlo(int c)
	{
		srvSend(c, "220 fake.smtp ESMTP ready");
		std::string ehlo = srvRecvLine(c);
		EXPECT_EQ(ehlo, "EHLO pocketdial");
		srvSend(c, "250-fake.smtp at your service");
		srvSend(c, "250-STARTTLS");
		srvSend(c, "250-AUTH LOGIN PLAIN XOAUTH2");
		srvSend(c, "250 SIZE 35882577");
	}

	// Feeds `data` back in small (default 5-byte) reads rather than one big
	// chunk, so the attachment E2E test below actually exercises
	// ChunkedBase64Writer's carry-bytes-across-calls path (the same reason
	// ChunkedBase64Writer_ByteAtATimeMatchesWholeInput above reads 1 byte at
	// a time) instead of just proving a single feed() call works.
	class StringAttachmentSource : public SmtpDialogue::AttachmentSource
	{
	public:
		explicit StringAttachmentSource(std::string data, size_t chunk = 5)
			: _data(std::move(data)), _chunk(chunk) {}

		size_t read(uint8_t* buf, size_t maxLen) override
		{
			size_t n = std::min({_chunk, maxLen, _data.size() - _pos});
			if (n == 0) return 0;
			std::memcpy(buf, _data.data() + _pos, n);
			_pos += n;
			return n;
		}

	private:
		std::string _data;
		size_t _pos = 0;
		size_t _chunk;
	};

	// Independent base64 decoder (deliberately NOT calling into SmtpDialogue's
	// own base64Encode) so the attachment E2E test below is a genuine
	// round-trip check, not a tautology against the code under test -- same
	// independence reasoning as GoogleServiceAuth_test.cpp's raw-OpenSSL
	// signature verification.
	std::string base64DecodeForTest(const std::string& in)
	{
		auto val = [](char c) -> int {
			if (c >= 'A' && c <= 'Z') return c - 'A';
			if (c >= 'a' && c <= 'z') return c - 'a' + 26;
			if (c >= '0' && c <= '9') return c - '0' + 52;
			if (c == '+') return 62;
			if (c == '/') return 63;
			return -1;
		};
		std::string out;
		int buf = 0, bits = 0;
		for (char c : in)
		{
			if (c == '=' || c == '\r' || c == '\n') continue;
			int v = val(c);
			if (v < 0) continue;
			buf = (buf << 6) | v;
			bits += 6;
			if (bits >= 8)
			{
				bits -= 8;
				out += static_cast<char>((buf >> bits) & 0xFF);
			}
		}
		return out;
	}
} // namespace

// ===========================================================================
// 1. Pure helpers -- no socket.
// ===========================================================================

TEST(SmtpDialogueHelpers, Base64EncodeKnownVectors)
{
	// RFC 4648 test vectors.
	auto enc = [](const std::string& s) {
		return SmtpDialogue::base64Encode(reinterpret_cast<const uint8_t*>(s.data()), s.size());
	};
	EXPECT_EQ(enc(""), "");
	EXPECT_EQ(enc("f"), "Zg==");
	EXPECT_EQ(enc("fo"), "Zm8=");
	EXPECT_EQ(enc("foo"), "Zm9v");
	EXPECT_EQ(enc("foob"), "Zm9vYg==");
	EXPECT_EQ(enc("fooba"), "Zm9vYmE=");
	EXPECT_EQ(enc("foobar"), "Zm9vYmFy");
}

TEST(SmtpDialogueHelpers, Base64UrlEncodeIsUnpaddedAndUrlSafe)
{
	// Bytes 0xFB 0xFF 0xBF encode to "+/+/" style bytes in standard base64
	// (chosen so the alphabet swap is actually observable), and base64url
	// must use '-'/'_' with no '=' padding regardless of input length.
	uint8_t data[] = {0xFB, 0xFF, 0xBF};
	std::string std64 = SmtpDialogue::base64Encode(data, sizeof(data));
	std::string url64 = SmtpDialogue::base64UrlEncode(data, sizeof(data));
	EXPECT_EQ(std64, "+/+/");
	EXPECT_EQ(url64, "-_-_");
	EXPECT_EQ(url64.find('='), std::string::npos);

	// One-byte input still gets no '=' padding in url mode.
	uint8_t one[] = {0x00};
	EXPECT_EQ(SmtpDialogue::base64UrlEncode(one, 1), "AA");
}

TEST(SmtpDialogueHelpers, ParseEhloCapabilities_StandardAuthLine)
{
	std::vector<std::string> lines = {
		"fake.smtp at your service",
		"STARTTLS",
		"AUTH LOGIN PLAIN XOAUTH2",
		"SIZE 35882577",
	};
	auto caps = SmtpDialogue::parseEhloCapabilities(lines);
	EXPECT_TRUE(caps.startTls);
	EXPECT_TRUE(caps.authPlain);
	EXPECT_TRUE(caps.authLogin);
	EXPECT_TRUE(caps.authXOAuth2);
}

TEST(SmtpDialogueHelpers, ParseEhloCapabilities_NoStartTlsNoAuth)
{
	std::vector<std::string> lines = {"fake.smtp", "SIZE 100"};
	auto caps = SmtpDialogue::parseEhloCapabilities(lines);
	EXPECT_FALSE(caps.startTls);
	EXPECT_FALSE(caps.authPlain);
	EXPECT_FALSE(caps.authLogin);
	EXPECT_FALSE(caps.authXOAuth2);
}

TEST(SmtpDialogueHelpers, ParseEhloCapabilities_PartialAuthSet)
{
	// A relay that only offers PLAIN must not be reported as supporting LOGIN/XOAUTH2.
	std::vector<std::string> lines = {"AUTH PLAIN"};
	auto caps = SmtpDialogue::parseEhloCapabilities(lines);
	EXPECT_TRUE(caps.authPlain);
	EXPECT_FALSE(caps.authLogin);
	EXPECT_FALSE(caps.authXOAuth2);
}

TEST(SmtpDialogueHelpers, SplitAddresses_TrimsAndDropsEmpties)
{
	auto v = SmtpDialogue::splitAddresses(" a@x.test ,, b@x.test,c@x.test ");
	ASSERT_EQ(v.size(), 3u);
	EXPECT_EQ(v[0], "a@x.test");
	EXPECT_EQ(v[1], "b@x.test");
	EXPECT_EQ(v[2], "c@x.test");
}

TEST(SmtpDialogueHelpers, SplitAddresses_SingleAddress)
{
	auto v = SmtpDialogue::splitAddresses("only@x.test");
	ASSERT_EQ(v.size(), 1u);
	EXPECT_EQ(v[0], "only@x.test");
}

TEST(SmtpDialogueHelpers, DotStuffBody_LeadingDotIsDoubled)
{
	// A line that starts with '.' anywhere in the body must be escaped, or a
	// naive SMTP server would read it as the DATA terminator.
	std::string in = "line one\r\n.line two\r\nline three";
	std::string out = SmtpDialogue::dotStuffBody(in);
	EXPECT_EQ(out, "line one\r\n..line two\r\nline three");
}

TEST(SmtpDialogueHelpers, DotStuffBody_LineThatIsExactlyADot)
{
	std::string in = "before\r\n.\r\nafter";
	std::string out = SmtpDialogue::dotStuffBody(in);
	EXPECT_EQ(out, "before\r\n..\r\nafter");
}

TEST(SmtpDialogueHelpers, DotStuffBody_BareLfNormalizedToCrlf)
{
	// The common case: a body assembled with '\n' alone (any non-Windows
	// source) must reach the wire as CRLF, RFC 5321 §2.3.8.
	std::string in = "one\ntwo\n.\nthree";
	std::string out = SmtpDialogue::dotStuffBody(in);
	EXPECT_EQ(out, "one\r\ntwo\r\n..\r\nthree");
}

TEST(SmtpDialogueHelpers, DotStuffBody_NoLeadingDotUnaffected)
{
	std::string in = "plain body\r\nwith no dots at line starts";
	EXPECT_EQ(SmtpDialogue::dotStuffBody(in), in);
}

TEST(SmtpDialogueHelpers, FormatRfc5322Date_ZeroMeansUnsynced)
{
	EXPECT_EQ(SmtpDialogue::formatRfc5322Date(0), "");
}

TEST(SmtpDialogueHelpers, FormatRfc5322Date_KnownVectors)
{
	// Ground truth: `date -u -d @1700000000` / `@1735689600`.
	EXPECT_EQ(SmtpDialogue::formatRfc5322Date(1700000000ULL), "Tue, 14 Nov 2023 22:13:20 +0000");
	EXPECT_EQ(SmtpDialogue::formatRfc5322Date(1735689600ULL), "Wed, 01 Jan 2025 00:00:00 +0000");
}

namespace
{
	bool collectSink(void* ctx, const char* data, size_t len)
	{
		static_cast<std::string*>(ctx)->append(data, len);
		return true;
	}
}

TEST(SmtpDialogueHelpers, ChunkedBase64Writer_SingleChunkMultipleOf3)
{
	std::string out;
	SmtpDialogue::ChunkedBase64Writer w(&collectSink, &out);
	std::vector<uint8_t> data = {'f', 'o', 'o', 'b', 'a', 'r'};
	ASSERT_TRUE(w.feed(data.data(), data.size()));
	ASSERT_TRUE(w.finish());
	EXPECT_EQ(out, "Zm9vYmFy\r\n");
}

TEST(SmtpDialogueHelpers, ChunkedBase64Writer_ByteAtATimeMatchesWholeInput)
{
	// Feeding one byte at a time (the worst case for the carry buffer) must
	// produce the exact same encoding as feeding it all at once -- this is
	// what makes it safe for an AttachmentSource that does short reads.
	std::string input = "The quick brown fox jumps over the lazy dog. 0123456789";
	std::string expectedB64 = SmtpDialogue::base64Encode(
		reinterpret_cast<const uint8_t*>(input.data()), input.size());

	std::string out;
	SmtpDialogue::ChunkedBase64Writer w(&collectSink, &out);
	for (unsigned char c : input)
	{
		ASSERT_TRUE(w.feed(reinterpret_cast<const uint8_t*>(&c), 1));
	}
	ASSERT_TRUE(w.finish());

	// Strip the CRLFs the writer inserted every 76 chars and compare against
	// the plain encoding of the whole input.
	std::string flattened;
	for (size_t i = 0; i < out.size(); ++i)
	{
		if (out[i] == '\r' || out[i] == '\n') continue;
		flattened += out[i];
	}
	EXPECT_EQ(flattened, expectedB64);
}

TEST(SmtpDialogueHelpers, ChunkedBase64Writer_WrapsAt76Chars)
{
	std::vector<uint8_t> data(100, 'A'); // 100 bytes -> 136 b64 chars unpadded-ish
	std::string out;
	SmtpDialogue::ChunkedBase64Writer w(&collectSink, &out);
	ASSERT_TRUE(w.feed(data.data(), data.size()));
	ASSERT_TRUE(w.finish());

	size_t pos = 0;
	std::vector<size_t> lineLens;
	while (pos < out.size())
	{
		size_t nl = out.find("\r\n", pos);
		ASSERT_NE(nl, std::string::npos);
		lineLens.push_back(nl - pos);
		pos = nl + 2;
	}
	ASSERT_GE(lineLens.size(), 2u);
	for (size_t i = 0; i + 1 < lineLens.size(); ++i)
	{
		EXPECT_EQ(lineLens[i], 76u) << "line " << i;
	}
	EXPECT_LE(lineLens.back(), 76u);
}

// ===========================================================================
// 2. End-to-end, against a real loopback fake SMTP server.
// ===========================================================================

TEST(SmtpDialogueE2E, GreetingRejected_4xx)
{
	ScriptedServer srv([](int c) {
		srvSend(c, "421 fake.smtp service not available");
	});
	auto res = sendOver(srv.port, plainConfig(srv.port), basicMessage());
	EXPECT_EQ(res.code, SmtpDialogue::ResultCode::GreetingRejected);
	EXPECT_EQ(res.smtpReplyCode, 421);
}

TEST(SmtpDialogueE2E, EhloRejected_5xx)
{
	ScriptedServer srv([](int c) {
		srvSend(c, "220 fake.smtp ready");
		srvRecvLine(c); // EHLO
		srvSend(c, "502 command not implemented");
	});
	auto res = sendOver(srv.port, plainConfig(srv.port), basicMessage());
	EXPECT_EQ(res.code, SmtpDialogue::ResultCode::EhloRejected);
	EXPECT_EQ(res.smtpReplyCode, 502);
}

TEST(SmtpDialogueE2E, PlainSend_NoAuth_FullConversation_DotStuffedAndTerminated)
{
	std::string capturedData;
	ScriptedServer srv([&capturedData](int c) {
		serveGreetingAndEhlo(c);
		EXPECT_EQ(srvRecvLine(c), "MAIL FROM:<pbx@example.test>");
		srvSend(c, "250 OK");
		EXPECT_EQ(srvRecvLine(c), "RCPT TO:<ops@example.test>");
		srvSend(c, "250 OK");
		EXPECT_EQ(srvRecvLine(c), "DATA");
		srvSend(c, "354 Start mail input");
		capturedData = srvRecvData(c);
		srvSend(c, "250 Queued");
		EXPECT_EQ(srvRecvLine(c), "QUIT");
		srvSend(c, "221 Bye");
	});

	SmtpDialogue::Message msg = basicMessage();
	msg.textBody = "line one\n.line two\nline three"; // bare LF + a leading dot
	auto res = sendOver(srv.port, plainConfig(srv.port), msg);

	EXPECT_EQ(res.code, SmtpDialogue::ResultCode::Ok);
	EXPECT_EQ(res.smtpReplyCode, 250);
	EXPECT_NE(capturedData.find("From: pbx@example.test\r\n"), std::string::npos);
	EXPECT_NE(capturedData.find("To: ops@example.test\r\n"), std::string::npos);
	EXPECT_NE(capturedData.find("Subject: Test\r\n"), std::string::npos);
	// Body reached the server dot-stuffed and CRLF-normalized.
	EXPECT_NE(capturedData.find("line one\r\n..line two\r\nline three"), std::string::npos);
}

// The streaming attachment writer (ChunkedBase64Writer, fed through
// AttachmentSource::read()) has unit coverage above but nothing that proves
// the bytes it emits actually survive SmtpDialogue::run()'s real MIME
// framing end to end. This test is that proof: a small text attachment,
// deliberately not a multiple of 3 bytes (forces base64 padding) and read
// back in 5-byte chunks (forces ChunkedBase64Writer's carry-across-calls
// path), sent over a real loopback socket, then independently base64-decoded
// out of the captured wire bytes and compared to the source.
TEST(SmtpDialogueE2E, PlainSend_WithAttachment_MimeFramingAndBase64RoundTrip)
{
	const std::string attachmentBytes = "This is a test attachment, 37 bytes"; // not a multiple of 3
	StringAttachmentSource source(attachmentBytes, /*chunk=*/5);
	SmtpDialogue::Attachment att;
	att.filename = "note.txt";
	att.contentType = "text/plain";
	att.source = &source;

	std::string capturedData;
	ScriptedServer srv([&capturedData](int c) {
		serveGreetingAndEhlo(c);
		EXPECT_EQ(srvRecvLine(c), "MAIL FROM:<pbx@example.test>");
		srvSend(c, "250 OK");
		EXPECT_EQ(srvRecvLine(c), "RCPT TO:<ops@example.test>");
		srvSend(c, "250 OK");
		EXPECT_EQ(srvRecvLine(c), "DATA");
		srvSend(c, "354 Start mail input");
		capturedData = srvRecvData(c);
		srvSend(c, "250 Queued");
		EXPECT_EQ(srvRecvLine(c), "QUIT");
		srvSend(c, "221 Bye");
	});

	SmtpDialogue::Message msg = basicMessage();
	msg.attachment = &att;
	auto res = sendOver(srv.port, plainConfig(srv.port), msg);

	ASSERT_EQ(res.code, SmtpDialogue::ResultCode::Ok);
	EXPECT_EQ(res.smtpReplyCode, 250);

	EXPECT_NE(capturedData.find("Content-Type: multipart/mixed; boundary=\"PDBOUNDARY\""), std::string::npos);
	EXPECT_NE(capturedData.find("Content-Type: text/plain; name=\"note.txt\""), std::string::npos);
	EXPECT_NE(capturedData.find("Content-Transfer-Encoding: base64"), std::string::npos);
	EXPECT_NE(capturedData.find("Content-Disposition: attachment; filename=\"note.txt\""), std::string::npos);
	EXPECT_NE(capturedData.find("--PDBOUNDARY--"), std::string::npos);
	// The text/plain preamble part is still present and un-encoded.
	EXPECT_NE(capturedData.find(msg.textBody), std::string::npos);

	// Extract the base64 body: everything between the attachment part's
	// header block (ending "...filename=\"note.txt\"\r\n\r\n") and the closing
	// boundary ("\r\n--PDBOUNDARY--"), then decode it independently and
	// compare to the original bytes.
	std::string marker = "Content-Disposition: attachment; filename=\"note.txt\"\r\n\r\n";
	size_t startPos = capturedData.find(marker);
	ASSERT_NE(startPos, std::string::npos);
	startPos += marker.size();
	size_t endPos = capturedData.find("\r\n--PDBOUNDARY--", startPos);
	ASSERT_NE(endPos, std::string::npos);
	std::string encoded = capturedData.substr(startPos, endPos - startPos);

	// RFC 2045 §6.8 line wrapping: no encoded line exceeds 76 chars.
	{
		size_t lineStart = 0;
		while (lineStart < encoded.size())
		{
			size_t lineEnd = encoded.find("\r\n", lineStart);
			if (lineEnd == std::string::npos) lineEnd = encoded.size();
			EXPECT_LE(lineEnd - lineStart, 76u);
			lineStart = lineEnd + 2;
		}
	}

	EXPECT_EQ(base64DecodeForTest(encoded), attachmentBytes);
}

TEST(SmtpDialogueE2E, AuthPlain_Success)
{
	ScriptedServer srv([](int c) {
		serveGreetingAndEhlo(c);
		std::string line = srvRecvLine(c);
		EXPECT_EQ(line.compare(0, 11, "AUTH PLAIN "), 0);
		// AUTH PLAIN's payload is base64("\0" + user + "\0" + pass); decoding
		// it isn't needed here since AuthPlain_Rejected_535 below already pins
		// the failure path -- this test's job is the success path + framing.
		srvSend(c, "235 Authenticated");
		EXPECT_EQ(srvRecvLine(c), "MAIL FROM:<pbx@example.test>");
		srvSend(c, "250 OK");
		EXPECT_EQ(srvRecvLine(c), "RCPT TO:<ops@example.test>");
		srvSend(c, "250 OK");
		EXPECT_EQ(srvRecvLine(c), "DATA");
		srvSend(c, "354 go");
		srvRecvData(c);
		srvSend(c, "250 OK");
		srvRecvLine(c); // QUIT
		srvSend(c, "221 Bye");
	});

	auto cfg = plainConfig(srv.port);
	cfg.auth = SmtpDialogue::AuthMethod::Plain;
	cfg.username = "user@example.test";
	cfg.password = "s3cret";
	auto res = sendOver(srv.port, cfg, basicMessage());
	EXPECT_EQ(res.code, SmtpDialogue::ResultCode::Ok);
}

TEST(SmtpDialogueE2E, AuthPlain_Rejected_535)
{
	ScriptedServer srv([](int c) {
		serveGreetingAndEhlo(c);
		srvRecvLine(c); // AUTH PLAIN ...
		srvSend(c, "535 authentication failed");
	});
	auto cfg = plainConfig(srv.port);
	cfg.auth = SmtpDialogue::AuthMethod::Plain;
	cfg.username = "user@example.test";
	cfg.password = "wrong";
	auto res = sendOver(srv.port, cfg, basicMessage());
	EXPECT_EQ(res.code, SmtpDialogue::ResultCode::AuthRejected);
	EXPECT_EQ(res.smtpReplyCode, 535);
}

TEST(SmtpDialogueE2E, AuthLogin_Success)
{
	ScriptedServer srv([](int c) {
		serveGreetingAndEhlo(c);
		EXPECT_EQ(srvRecvLine(c), "AUTH LOGIN");
		srvSend(c, "334 VXNlcm5hbWU6");
		std::string userLine = srvRecvLine(c);
		const std::string expectedUser = "user@example.test";
		EXPECT_EQ(userLine, SmtpDialogue::base64Encode(
			reinterpret_cast<const uint8_t*>(expectedUser.data()), expectedUser.size()));
		srvSend(c, "334 UGFzc3dvcmQ6");
		srvRecvLine(c); // password b64
		srvSend(c, "235 Authenticated");
		EXPECT_EQ(srvRecvLine(c), "MAIL FROM:<pbx@example.test>");
		srvSend(c, "250 OK");
		EXPECT_EQ(srvRecvLine(c), "RCPT TO:<ops@example.test>");
		srvSend(c, "250 OK");
		EXPECT_EQ(srvRecvLine(c), "DATA");
		srvSend(c, "354 go");
		srvRecvData(c);
		srvSend(c, "250 OK");
		srvRecvLine(c);
		srvSend(c, "221 Bye");
	});
	auto cfg = plainConfig(srv.port);
	cfg.auth = SmtpDialogue::AuthMethod::Login;
	cfg.username = "user@example.test";
	cfg.password = "s3cret";
	auto res = sendOver(srv.port, cfg, basicMessage());
	EXPECT_EQ(res.code, SmtpDialogue::ResultCode::Ok);
}

TEST(SmtpDialogueE2E, AuthLogin_RejectedAtUsernameStep)
{
	ScriptedServer srv([](int c) {
		serveGreetingAndEhlo(c);
		srvRecvLine(c); // AUTH LOGIN
		srvSend(c, "334 VXNlcm5hbWU6");
		srvRecvLine(c); // username
		srvSend(c, "535 authentication failed");
	});
	auto cfg = plainConfig(srv.port);
	cfg.auth = SmtpDialogue::AuthMethod::Login;
	cfg.username = "user@example.test";
	cfg.password = "s3cret";
	auto res = sendOver(srv.port, cfg, basicMessage());
	EXPECT_EQ(res.code, SmtpDialogue::ResultCode::AuthRejected);
	EXPECT_EQ(res.smtpReplyCode, 535);
}

TEST(SmtpDialogueE2E, AuthXOAuth2_Success)
{
	ScriptedServer srv([](int c) {
		serveGreetingAndEhlo(c);
		std::string line = srvRecvLine(c);
		EXPECT_EQ(line.compare(0, 13, "AUTH XOAUTH2 "), 0);
		srvSend(c, "235 Authenticated");
		EXPECT_EQ(srvRecvLine(c), "MAIL FROM:<pbx@example.test>");
		srvSend(c, "250 OK");
		EXPECT_EQ(srvRecvLine(c), "RCPT TO:<ops@example.test>");
		srvSend(c, "250 OK");
		EXPECT_EQ(srvRecvLine(c), "DATA");
		srvSend(c, "354 go");
		srvRecvData(c);
		srvSend(c, "250 OK");
		srvRecvLine(c);
		srvSend(c, "221 Bye");
	});
	auto cfg = plainConfig(srv.port);
	cfg.auth = SmtpDialogue::AuthMethod::XOAuth2;
	cfg.username = "user@example.test";
	cfg.accessToken = "ya29.faketoken";
	auto res = sendOver(srv.port, cfg, basicMessage());
	EXPECT_EQ(res.code, SmtpDialogue::ResultCode::Ok);
}

TEST(SmtpDialogueE2E, AuthXOAuth2_RejectedWithChallenge_RespondsEmptyThenReadsFinalFailure)
{
	// draft-ietf-kitten-sasl-oauth §3.2.3: a 334 challenge carrying base64
	// JSON error detail, which the client must answer with a bare empty line
	// before the server sends the real (535) failure.
	ScriptedServer srv([](int c) {
		serveGreetingAndEhlo(c);
		srvRecvLine(c); // AUTH XOAUTH2 ...
		srvSend(c, "334 eyJzdGF0dXMiOiI0MDEifQ=="); // base64 of {"status":"401"}
		EXPECT_EQ(srvRecvLine(c), ""); // client's mandated empty response
		srvSend(c, "535 invalid token");
	});
	auto cfg = plainConfig(srv.port);
	cfg.auth = SmtpDialogue::AuthMethod::XOAuth2;
	cfg.username = "user@example.test";
	cfg.accessToken = "expired";
	auto res = sendOver(srv.port, cfg, basicMessage());
	EXPECT_EQ(res.code, SmtpDialogue::ResultCode::AuthRejected);
	EXPECT_EQ(res.smtpReplyCode, 535);
}

TEST(SmtpDialogueE2E, AuthNotSupported_WhenServerDoesNotAdvertiseIt)
{
	ScriptedServer srv([](int c) {
		srvSend(c, "220 fake.smtp ready");
		srvRecvLine(c); // EHLO
		srvSend(c, "250-fake.smtp");
		srvSend(c, "250 AUTH PLAIN"); // no LOGIN
	});
	auto cfg = plainConfig(srv.port);
	cfg.auth = SmtpDialogue::AuthMethod::Login;
	cfg.username = "u";
	cfg.password = "p";
	auto res = sendOver(srv.port, cfg, basicMessage());
	EXPECT_EQ(res.code, SmtpDialogue::ResultCode::AuthNotSupported);
}

TEST(SmtpDialogueE2E, MailFromRejected_550)
{
	ScriptedServer srv([](int c) {
		serveGreetingAndEhlo(c);
		srvRecvLine(c); // MAIL FROM
		srvSend(c, "550 relay not permitted");
	});
	auto res = sendOver(srv.port, plainConfig(srv.port), basicMessage());
	EXPECT_EQ(res.code, SmtpDialogue::ResultCode::MailFromRejected);
	EXPECT_EQ(res.smtpReplyCode, 550);
}

TEST(SmtpDialogueE2E, RcptToRejected_550)
{
	ScriptedServer srv([](int c) {
		serveGreetingAndEhlo(c);
		srvRecvLine(c); // MAIL FROM
		srvSend(c, "250 OK");
		srvRecvLine(c); // RCPT TO
		srvSend(c, "550 no such user");
	});
	auto res = sendOver(srv.port, plainConfig(srv.port), basicMessage());
	EXPECT_EQ(res.code, SmtpDialogue::ResultCode::RcptToRejected);
	EXPECT_EQ(res.smtpReplyCode, 550);
}

TEST(SmtpDialogueE2E, DataRejected_NoStartMailInput)
{
	ScriptedServer srv([](int c) {
		serveGreetingAndEhlo(c);
		srvRecvLine(c); srvSend(c, "250 OK");   // MAIL FROM
		srvRecvLine(c); srvSend(c, "250 OK");   // RCPT TO
		srvRecvLine(c); srvSend(c, "451 local error"); // DATA
	});
	auto res = sendOver(srv.port, plainConfig(srv.port), basicMessage());
	EXPECT_EQ(res.code, SmtpDialogue::ResultCode::DataRejected);
	EXPECT_EQ(res.smtpReplyCode, 451);
}

TEST(SmtpDialogueE2E, MessageRejectedAfterTerminator_5xx)
{
	ScriptedServer srv([](int c) {
		serveGreetingAndEhlo(c);
		srvRecvLine(c); srvSend(c, "250 OK"); // MAIL FROM
		srvRecvLine(c); srvSend(c, "250 OK"); // RCPT TO
		srvRecvLine(c); srvSend(c, "354 go"); // DATA
		srvRecvData(c);
		srvSend(c, "552 message too large");
	});
	auto res = sendOver(srv.port, plainConfig(srv.port), basicMessage());
	EXPECT_EQ(res.code, SmtpDialogue::ResultCode::MessageRejected);
	EXPECT_EQ(res.smtpReplyCode, 552);
}

TEST(SmtpDialogueE2E, Timeout_ServerNeverGreets)
{
	ScriptedServer srv([](int c) {
		// Hold the connection open without ever writing anything, long enough
		// for the client's short timeout to fire, then let the destructor's
		// join() proceed once the client has given up and closed its end.
		std::this_thread::sleep_for(std::chrono::milliseconds(600));
	});
	auto cfg = plainConfig(srv.port);
	cfg.commandTimeoutMs = 200;
	auto res = sendOver(srv.port, cfg, basicMessage());
	EXPECT_EQ(res.code, SmtpDialogue::ResultCode::Timeout);
}

TEST(SmtpDialogueE2E, StartTls_HostBuildCannotUpgrade_FailsCleanly)
{
	// The host transport has no TLS at all (see SmtpClient.hpp). A server
	// that legitimately offers STARTTLS therefore still yields a clean
	// TlsFailed on this build -- exercising the same code path a real server
	// REFUSING the upgrade would take, and proving the client never falls
	// back to sending credentials/mail in the clear when the upgrade fails.
	ScriptedServer srv([](int c) {
		serveGreetingAndEhlo(c);
		EXPECT_EQ(srvRecvLine(c), "STARTTLS");
		srvSend(c, "220 Go ahead");
		// No further bytes -- the client gives up in startTls() itself.
	});
	SmtpDialogue::Config cfg;
	cfg.host = "127.0.0.1";
	cfg.mode = SmtpDialogue::Mode::StartTls;
	cfg.commandTimeoutMs = 2000;
	auto res = sendOver(srv.port, cfg, basicMessage());
	EXPECT_EQ(res.code, SmtpDialogue::ResultCode::TlsFailed);
}

TEST(SmtpDialogueE2E, StartTls_NotAdvertised_RefusedBeforeAttempting)
{
	ScriptedServer srv([](int c) {
		srvSend(c, "220 fake.smtp ready");
		srvRecvLine(c); // EHLO
		srvSend(c, "250 fake.smtp"); // no STARTTLS line at all
	});
	SmtpDialogue::Config cfg;
	cfg.host = "127.0.0.1";
	cfg.mode = SmtpDialogue::Mode::StartTls;
	cfg.commandTimeoutMs = 2000;
	auto res = sendOver(srv.port, cfg, basicMessage());
	EXPECT_EQ(res.code, SmtpDialogue::ResultCode::TlsFailed);
	EXPECT_NE(res.lastError.find("STARTTLS"), std::string::npos);
}

TEST(SmtpDialogueE2E, PlainMode_RefusedByTransportWhenNotAllowed)
{
	// ConnectFailed comes back before any socket I/O at all when the caller
	// (EmailConfigStore-backed HTTP route, in production) has not opted into
	// plaintext -- this test drives SmtpTransport::connect() directly, the
	// one call site sendOver() doesn't cover with allowPlain=false.
	SmtpClient::SmtpTransport transport;
	SmtpDialogue::Config cfg;
	cfg.host = "127.0.0.1";
	cfg.port = 1; // never dialed -- connect() must refuse before this matters
	cfg.mode = SmtpDialogue::Mode::Plain;
	std::string err;
	EXPECT_FALSE(transport.connect(cfg, /*allowPlain=*/false, "", false, err));
	EXPECT_NE(err.find("LAN-relay"), std::string::npos);
}

// ---------------------------------------------------------------------
// XOAUTH2 token minting is the WORKER's job, not the caller's (#230 review).
//
// HttpServer::sendApiEmailTest() used to fetch the bearer token inline, on the
// per-connection HTTP handler thread -- an RSA-2048 signature plus a full TLS
// handshake on an IDF pthread with the 8192-byte default stack, while every
// other TLS-handshake path here runs on a task with a dedicated 12 KB PSRAM
// stack. The material now travels to the worker as SmtpClient::TokenRequest.
//
// That refactor moved the host build's "device-only" refusal out of the HTTP
// handler and into SmtpClient, where every caller sees the same answer. The
// behaviour was untested in EITHER location, so it is pinned here now -- it is
// the only host-observable part of the change.
// ---------------------------------------------------------------------

TEST(SmtpClientTokenRequest, AMintRequestIsRefusedOnHostRatherThanSilentlySendingUnauthenticated)
{
	SmtpDialogue::Config cfg;
	cfg.host = "smtp.example.test";
	cfg.port = 587;
	cfg.auth = SmtpDialogue::AuthMethod::XOAuth2;
	cfg.username = "user@example.test";
	// No accessToken: this send NEEDS a token minted.

	SmtpDialogue::Message msg;
	msg.from = "user@example.test";
	msg.to = "someone@example.test";

	SmtpClient::TokenRequest token;
	token.serviceAccountEmail = "sa@project.iam.gserviceaccount.com";
	token.subjectUser = "user@example.test";
	token.scope = "https://mail.google.com/";
	token.privateKeyPem = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n";

	SmtpDialogue::SendResult result;
	const bool dispatched = SmtpClient::sendAndWait(
		cfg, msg, /*allowPlain=*/false, /*caCertPem=*/"", /*insecureSkipVerify=*/false,
		/*waitMs=*/1000, result, token);

	EXPECT_FALSE(dispatched);
	// AuthRejected, not TransportError: nothing was ever dialled, the credential
	// is what could not be produced.
	EXPECT_EQ(result.code, SmtpDialogue::ResultCode::AuthRejected);
	EXPECT_NE(result.lastError.find("device-only"), std::string::npos)
		<< "the refusal must say WHY, since this is a build-capability limit and "
		   "not a server rejection: " << result.lastError;
}

TEST(SmtpClientTokenRequest, AnEmptyTokenRequestIsNotTreatedAsAMintRequest)
{
	// The App Password path, and any caller that already holds a token, must be
	// completely unaffected by the new parameter -- an empty TokenRequest means
	// "nothing to mint", NOT "mint with empty credentials". Getting this wrong
	// would have refused every non-OAuth send on host.
	SmtpDialogue::Config cfg;
	cfg.host = "";   // invalid on purpose: we want the DIALOGUE to be what objects
	cfg.auth = SmtpDialogue::AuthMethod::Plain;

	SmtpDialogue::Message msg;
	SmtpDialogue::SendResult result;
	SmtpClient::sendAndWait(cfg, msg, false, "", false, 1000, result, SmtpClient::TokenRequest{});

	EXPECT_NE(result.code, SmtpDialogue::ResultCode::AuthRejected)
		<< "an empty TokenRequest must not be mistaken for a mint request; this "
		   "send should fail on its own (missing) config instead";
}

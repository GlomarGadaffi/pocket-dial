// MohPreview_test.cpp — the MoH preview call (#194 Stage 2 / dashboard).
//
// "Play the hold music to extension N so I can hear it" is driven from the HTTP
// task, not the SIP receive thread, and that thread boundary is the whole story
// here. Everything below exists because of one hardware failure:
//
//   POST /api/moh/preview -> {"status":"ok","message":"ringing 1001"}
//   GET  /api/moh         -> {"preview":"1001", ...}
//   ...and the phone never rang. The SIP trace showed no INVITE at all.
//
// startMohPreview() had queued to _outbox, which handle()/tick() CLEAR at the
// start of every pass. The INVITE was wiped before anything drained it, and the
// API reported success because enqueueing had succeeded — nothing checked that
// the message actually left. Off-SIP-thread sends must use _asyncOutbox, which
// drainOutbox() merges in first.
//
// So the load-bearing assertion is not "startMohPreview returned true" — that
// was true throughout the bug. It is "the INVITE survives a tick()".

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "RequestsHandler.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(port);
		return a;
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

	// Minimal WAVE_FORMAT_MULAW file — 18-byte fmt chunk plus a fact chunk, the
	// shape a real converter emits (see HoldMusic_test.cpp, which covers the
	// parser itself in depth). Here it only needs to be loadable.
	std::string writeTempUlawWav(size_t dataBytes)
	{
		auto put32 = [](std::vector<uint8_t>& v, uint32_t x) {
			v.push_back(uint8_t(x & 0xFF));         v.push_back(uint8_t((x >> 8) & 0xFF));
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
		put16(body, 7);        // WAVE_FORMAT_MULAW
		put16(body, 1);        // mono
		put32(body, 8000);     // 8 kHz
		put32(body, 8000);     // byte rate
		put16(body, 1);        // block align
		put16(body, 8);        // bits
		put16(body, 0);        // cbSize
		putTag(body, "fact");
		put32(body, 4);
		put32(body, uint32_t(dataBytes));
		putTag(body, "data");
		put32(body, uint32_t(dataBytes));
		body.insert(body.end(), dataBytes, 0xFF);   // mu-law silence

		std::vector<uint8_t> file;
		putTag(file, "RIFF");
		put32(file, uint32_t(body.size()));
		file.insert(file.end(), body.begin(), body.end());

		std::string path = std::string(::testing::TempDir()) + "pd_moh_test.wav";
		std::ofstream out(path, std::ios::binary | std::ios::trunc);
		out.write(reinterpret_cast<const char*>(file.data()), std::streamsize(file.size()));
		out.close();
		return path;
	}

	std::string findSent(const std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>& sent,
	                     const std::string& needle)
	{
		for (auto it = sent.rbegin(); it != sent.rend(); ++it)
		{
			if (!it->second) continue;
			std::string raw = it->second->toString();
			if (raw.find(needle) != std::string::npos) return raw;
		}
		return {};
	}
}

// THE regression test. With the INVITE on _outbox this fails at the final
// assertion: startMohPreview() still returns true and the preview still reports
// active, but tick() wipes the queue and nothing ever reaches the phone.
TEST(MohPreview, InviteSurvivesATickBecauseItIsQueuedOffTheSipThread)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.40.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("1001", "192.168.40.10", "reg-moh-1001"));

	const std::string clip = writeTempUlawWav(8000);   // 1 second
	ASSERT_TRUE(handler.startHoldMusic(clip)) << "clip must load on the host build";

	sent.clear();

	// This is what POST /api/moh/preview does, on the HTTP task.
	ASSERT_TRUE(handler.startMohPreview("1001"));
	EXPECT_EQ(handler.mohPreviewExtension(), "1001");

	// ...and this is the SIP thread coming around afterwards. It clears _outbox
	// first, which is exactly what silently ate the INVITE.
	handler.tick();

	std::string invite = findSent(sent, "INVITE sip:1001@");
	ASSERT_FALSE(invite.empty())
		<< "the preview INVITE must survive tick() — queue it on _asyncOutbox, "
		   "not _outbox, when sending from the HTTP task";
	EXPECT_NE(invite.find("sip:moh@"), std::string::npos)
		<< "preview originates as the moh service identity:\n" << invite;
	EXPECT_NE(invite.find("a=sendonly"), std::string::npos)
		<< "preview offers server-sourced media, one-way:\n" << invite;

	std::remove(clip.c_str());
}

// A preview the extension DECLINES must be claimed, ACKed and released. Before
// handleMohPreviewFailure() existed, the 486 fell through to endHandle(), whose
// lookup of the preview's own From ("moh") matches no registered client — so the
// declining phone got a stray 404, and _mohPreview stayed active forever,
// blocking every later preview and leaking its listener slot.
TEST(MohPreview, DeclinedPreviewIsAckedAndReleasedWithoutAStray404)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.41.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in phone = addrFor("192.168.41.10");
	handler.handle(makeRegister("1002", "192.168.41.10", "reg-moh-1002"));

	const std::string clip = writeTempUlawWav(8000);
	ASSERT_TRUE(handler.startHoldMusic(clip));

	ASSERT_TRUE(handler.startMohPreview("1002"));
	handler.tick();

	std::string invite = findSent(sent, "INVITE sip:1002@");
	ASSERT_FALSE(invite.empty());

	// Pull the dialog identifiers back out of our own INVITE so the decline looks
	// like a real phone's, tags and all.
	auto headerLine = [&](const std::string& raw, const std::string& name) {
		size_t pos = 0;
		while (pos < raw.size())
		{
			size_t eol = raw.find("\r\n", pos);
			if (eol == std::string::npos) eol = raw.size();
			std::string line = raw.substr(pos, eol - pos);
			if (line.size() > name.size() && line.compare(0, name.size(), name) == 0) return line;
			pos = eol + 2;
		}
		return std::string{};
	};
	const std::string via  = headerLine(invite, "Via:");
	const std::string from = headerLine(invite, "From:");
	const std::string cid  = headerLine(invite, "Call-ID:");
	ASSERT_FALSE(via.empty()); ASSERT_FALSE(from.empty()); ASSERT_FALSE(cid.empty());

	sent.clear();

	std::string busy =
		"SIP/2.0 486 Busy Here\r\n" + via + "\r\n" + from + "\r\n"
		"To: <sip:1002@192.168.41.1>;tag=phonetag\r\n" + cid + "\r\n"
		"CSeq: 1 INVITE\r\n"
		"Content-Length: 0\r\n\r\n";
	handler.handle(RequestsHandler::getMessageFromPool(busy, phone));
	handler.tick();

	// Claimed: ACKed in the original INVITE transaction (RFC 3261 §17.1.1.3).
	EXPECT_FALSE(findSent(sent, "ACK sip:1002@").empty())
		<< "a declined preview must be ACKed, or the phone retransmits to Timer H";

	// Claimed: and NOT answered with a stray 404 off the "moh" From.
	EXPECT_TRUE(findSent(sent, "404 Not Found").empty())
		<< "declining a preview must not mint a 404 at the phone";

	// Released: the slot is free, so the next preview can run.
	EXPECT_TRUE(handler.mohPreviewExtension().empty())
		<< "a declined preview must release, not linger as a phantom dialog";

	std::remove(clip.c_str());
}

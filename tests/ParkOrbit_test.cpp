// Wire-level tests for the park-orbit state machine (src/SIP/ParkOrbit.cpp).
// The park paths had no host coverage at all, which is how a doubled Call-ID
// header survived in the retrieve re-INVITE from the pre-decomposition monolith.

#include <gtest/gtest.h>

#include <fstream>
#include <vector>

#include "FakePbxEnv.hpp"
#include "ParkOrbit.hpp"

namespace
{
	// `mediaIp` is the caller's own IP: it lands in the SDP c= line, which is what
	// the retrieve path swaps between the two legs.
	std::shared_ptr<SipMessage> inviteTo(const std::string& orbit, const std::string& fromExt,
		const std::string& callId, const sockaddr_in& src, const std::string& mediaIp)
	{
		const std::string body =
			"v=0\r\n"
			"o=- 1 1 IN IP4 " + mediaIp + "\r\n"
			"s=call\r\n"
			"c=IN IP4 " + mediaIp + "\r\n"
			"t=0 0\r\n"
			"m=audio 4000 RTP/AVP 0\r\n";
		const std::string raw =
			"INVITE sip:" + orbit + "@192.168.1.10 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + mediaIp + ":5060;branch=z9hG4bKcaller\r\n"
			"From: <sip:" + fromExt + "@192.168.1.10>;tag=callertag\r\n"
			"To: <sip:" + orbit + "@192.168.1.10>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:" + fromExt + "@" + mediaIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return std::make_shared<SipMessage>(raw, src);
	}
}

// Park a call on 700, then retrieve it from a second extension. The retrieve
// sends a re-INVITE to the parked party; its Call-ID must be the parked dialog's
// Call-ID exactly once — "Call-ID: Call-ID: x@host" is what the phone rejects.
TEST(ParkOrbit, RetrieveReinviteCarriesSingleCallIdHeader)
{
	FakePbxEnv env;
	ParkOrbit park(env);

	const sockaddr_in parkedAddr    = FakePbxEnv::addr("192.168.1.50", 5060);
	const sockaddr_in retrieverAddr = FakePbxEnv::addr("192.168.1.51", 5060);

	auto parkedClient    = std::make_shared<SipClient>("101", parkedAddr);
	auto retrieverClient = std::make_shared<SipClient>("102", retrieverAddr);

	ASSERT_EQ(park.orbitIndex("700"), 0);

	park.onInvite(inviteTo("700", "101", "parked-call-1@192.168.1.50", parkedAddr, "192.168.1.50"),
		parkedClient, 0);
	ASSERT_EQ(env.sent.size(), 1u);           // 200 OK (hold) to the parked party

	park.onInvite(inviteTo("700", "102", "retrieve-call-1@192.168.1.51", retrieverAddr, "192.168.1.51"),
		retrieverClient, 0);
	ASSERT_EQ(env.sent.size(), 3u);           // + 200 OK to retriever, + re-INVITE

	const std::string reinvite = env.sentRaw(2);
	EXPECT_EQ(reinvite.rfind("INVITE sip:101@", 0), 0u) << reinvite;
	EXPECT_EQ(FakePbxEnv::countOf(reinvite, "Call-ID:"), 1) << reinvite;
	EXPECT_NE(reinvite.find("Call-ID: parked-call-1@192.168.1.50\r\n"), std::string::npos)
		<< reinvite;
	// The re-INVITE must offer the retriever's SDP so media re-points at them.
	EXPECT_NE(reinvite.find("c=IN IP4 192.168.1.51"), std::string::npos) << reinvite;
}

// The parked party's 200 OK to that re-INVITE is ACKed, and the ACK likewise
// carries exactly one Call-ID header line.
TEST(ParkOrbit, ReinviteOkIsAckedWithSingleCallIdHeader)
{
	FakePbxEnv env;
	ParkOrbit park(env);

	const sockaddr_in parkedAddr    = FakePbxEnv::addr("192.168.1.50", 5060);
	const sockaddr_in retrieverAddr = FakePbxEnv::addr("192.168.1.51", 5060);

	park.onInvite(inviteTo("700", "101", "parked-call-2@192.168.1.50", parkedAddr, "192.168.1.50"),
		std::make_shared<SipClient>("101", parkedAddr), 0);
	park.onInvite(inviteTo("700", "102", "retrieve-call-2@192.168.1.51", retrieverAddr, "192.168.1.51"),
		std::make_shared<SipClient>("102", retrieverAddr), 0);
	const std::size_t before = env.sent.size();

	const std::string okRaw =
		"SIP/2.0 200 OK\r\n"
		"Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bKpark\r\n"
		"From: <sip:700@192.168.1.10:5060>;tag=servertag\r\n"
		"To: <sip:101@192.168.1.10>;tag=callertag\r\n"
		"Call-ID: parked-call-2@192.168.1.50\r\n"
		"CSeq: 2 INVITE\r\n"
		"Content-Length: 0\r\n\r\n";
	auto ok = std::make_shared<SipMessage>(okRaw, parkedAddr);

	EXPECT_TRUE(park.handleOk(ok));
	ASSERT_EQ(env.sent.size(), before + 1);

	const std::string ack = env.sentRaw(before);
	EXPECT_EQ(ack.rfind("ACK sip:", 0), 0u) << ack;
	EXPECT_EQ(FakePbxEnv::countOf(ack, "Call-ID:"), 1) << ack;
	EXPECT_EQ(FakePbxEnv::countOf(ack, "From:"), 1) << ack;
	EXPECT_EQ(FakePbxEnv::countOf(ack, "To:"), 1) << ack;
}

// The dashboard mirror is driven by a dirty flag rather than by each call site
// remembering to refresh, so every path that moves slot state must signal — and
// a state-neutral response must not.
TEST(ParkOrbit, ParkChangedFlagTracksSlotStateNotTraffic)
{
	FakePbxEnv env;
	ParkOrbit park(env);
	const sockaddr_in parkedAddr = FakePbxEnv::addr("192.168.1.50", 5060);

	EXPECT_FALSE(park.consumeParkChanged());   // nothing has happened yet

	park.onInvite(inviteTo("700", "101", "parked-call-4@192.168.1.50", parkedAddr, "192.168.1.50"),
		std::make_shared<SipClient>("101", parkedAddr), 0);
	EXPECT_TRUE(park.consumeParkChanged());    // a call landed in an orbit
	EXPECT_FALSE(park.consumeParkChanged());   // consuming resets it

	// A 200 OK that belongs to no park dialog changes nothing.
	const std::string strayOk =
		"SIP/2.0 200 OK\r\n"
		"Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bKstray\r\n"
		"From: <sip:700@192.168.1.10:5060>;tag=t\r\n"
		"To: <sip:101@192.168.1.10>;tag=u\r\n"
		"Call-ID: not-a-park-dialog@192.168.1.50\r\n"
		"CSeq: 2 INVITE\r\n"
		"Content-Length: 0\r\n\r\n";
	EXPECT_FALSE(park.handleOk(std::make_shared<SipMessage>(strayOk, parkedAddr)));
	EXPECT_FALSE(park.consumeParkChanged());

	// Teardown of the parked call frees the slot and must signal, even though it
	// reaches ParkOrbit through freeForCallId() rather than a park call site.
	park.freeForCallId("Call-ID: parked-call-4@192.168.1.50");
	EXPECT_TRUE(park.consumeParkChanged());
	EXPECT_TRUE(park.snapshotRows(std::chrono::steady_clock::now(), /*onlyParked=*/false).empty());
}

// Issue #127: a BYE from either leg of a retrieved park must relay to the
// other (RequestsHandler::onBye's peerCallID branch), but that relay only
// fires when both legs' own dialog headers were captured via
// setDialogHeaders() — the same convention CallPickup::complete() uses.
// ParkOrbit is the producer of that state; this pins it directly rather than
// relying on the harder-to-wire end-to-end office_smoke.py scenario that
// originally caught the regression.
TEST(ParkOrbit, RetrieveCapturesDialogHeadersOnBothLegsForByeRelay)
{
	FakePbxEnv env;
	ParkOrbit park(env);

	const sockaddr_in parkedAddr    = FakePbxEnv::addr("192.168.1.50", 5060);
	const sockaddr_in retrieverAddr = FakePbxEnv::addr("192.168.1.51", 5060);

	park.onInvite(inviteTo("700", "101", "parked-call-5@192.168.1.50", parkedAddr, "192.168.1.50"),
		std::make_shared<SipClient>("101", parkedAddr), 0);
	park.onInvite(inviteTo("700", "102", "retrieve-call-5@192.168.1.51", retrieverAddr, "192.168.1.51"),
		std::make_shared<SipClient>("102", retrieverAddr), 0);

	// findSession/insertSession key on the FULL "Call-ID: x@host" line (see
	// ParkOrbit::sendReinvite's comment on getCallID()), not the bare value.
	auto parked = env.findSession("Call-ID: parked-call-5@192.168.1.50");
	ASSERT_TRUE(parked);
	EXPECT_FALSE(parked->getDialogFrom().empty());
	EXPECT_FALSE(parked->getDialogTo().empty());
	EXPECT_NE(parked->getDialogFrom().find("101@"), std::string::npos) << parked->getDialogFrom();
	EXPECT_NE(parked->getDialogTo().find(";tag="), std::string::npos) << parked->getDialogTo();
	EXPECT_EQ(parked->getPeerCallID(), "Call-ID: retrieve-call-5@192.168.1.51");

	auto retriever = env.findSession("Call-ID: retrieve-call-5@192.168.1.51");
	ASSERT_TRUE(retriever);
	EXPECT_FALSE(retriever->getDialogFrom().empty());
	EXPECT_FALSE(retriever->getDialogTo().empty());
	EXPECT_NE(retriever->getDialogFrom().find("102@"), std::string::npos) << retriever->getDialogFrom();
	EXPECT_NE(retriever->getDialogTo().find(";tag="), std::string::npos) << retriever->getDialogTo();
	EXPECT_EQ(retriever->getPeerCallID(), "Call-ID: parked-call-5@192.168.1.50");
}

// Issue #389: the retrieve re-INVITE is a server request on the parked dialog,
// so it must be recorded there -- with the SAME CSeq that went on the wire --
// or the BYE that later ends this leg reuses it and the phone 500s it.
TEST(ParkOrbit, RetrieveRecordsItsReinviteCSeqOnTheParkedSession)
{
	FakePbxEnv env;
	ParkOrbit park(env);

	const sockaddr_in parkedAddr    = FakePbxEnv::addr("192.168.1.50", 5060);
	const sockaddr_in retrieverAddr = FakePbxEnv::addr("192.168.1.51", 5060);

	park.onInvite(inviteTo("700", "101", "parked-call-7@192.168.1.50", parkedAddr, "192.168.1.50"),
		std::make_shared<SipClient>("101", parkedAddr), 0);
	auto parked = env.findSession("Call-ID: parked-call-7@192.168.1.50");
	ASSERT_TRUE(parked);
	EXPECT_EQ(parked->lastServerCSeq(), 0u);   // parking alone sends the parker no request

	park.onInvite(inviteTo("700", "102", "retrieve-call-7@192.168.1.51", retrieverAddr, "192.168.1.51"),
		std::make_shared<SipClient>("102", retrieverAddr), 0);
	ASSERT_EQ(env.sent.size(), 3u);            // hold 200, retriever 200, re-INVITE
	const std::string reinvite = env.sentRaw(2);
	ASSERT_EQ(reinvite.rfind("INVITE sip:101@", 0), 0u) << reinvite;

	const auto at = reinvite.find("CSeq: ");
	ASSERT_NE(at, std::string::npos) << reinvite;
	const uint32_t wireCSeq = static_cast<uint32_t>(std::stoul(reinvite.substr(at + 6)));
	EXPECT_EQ(parked->lastServerCSeq(), wireCSeq);
	EXPECT_GT(parked->nextServerCSeq(), wireCSeq);
}

// A retrieve that cannot get a session must 503 the retriever and leave the
// orbit occupied rather than half-tearing-down the parked leg (#71).
TEST(ParkOrbit, RetrieveWithExhaustedSessionPoolLeavesSlotParked)
{
	FakePbxEnv env;
	ParkOrbit park(env);

	const sockaddr_in parkedAddr    = FakePbxEnv::addr("192.168.1.50", 5060);
	const sockaddr_in retrieverAddr = FakePbxEnv::addr("192.168.1.51", 5060);

	park.onInvite(inviteTo("700", "101", "parked-call-3@192.168.1.50", parkedAddr, "192.168.1.50"),
		std::make_shared<SipClient>("101", parkedAddr), 0);

	env.sessionPoolAvailable = false;
	park.onInvite(inviteTo("700", "102", "retrieve-call-3@192.168.1.51", retrieverAddr, "192.168.1.51"),
		std::make_shared<SipClient>("102", retrieverAddr), 0);

	EXPECT_NE(env.sentRaw(1).find("503 Service Unavailable"), std::string::npos)
		<< env.sentRaw(1);
	// Slot still holds the parked call: it shows up in the dashboard rows.
	auto rows = park.snapshotRows(std::chrono::steady_clock::now(), /*onlyParked=*/true);
	ASSERT_EQ(rows.size(), 1u);
	EXPECT_EQ(std::get<0>(rows[0]), "700");
	EXPECT_EQ(std::get<1>(rows[0]), "101");
}

namespace
{
	// A minimal 8 kHz mono mu-law WAV, so HoldMusic can be loaded and started on
	// the host (same shape HoldMusic_test.cpp and MediaBridge_test.cpp write).
	std::string writeMohClip(const char* filename)
	{
		auto put32 = [](std::vector<uint8_t>& v, uint32_t x) {
			for (int i = 0; i < 4; ++i) v.push_back(uint8_t(x >> (8 * i)));
		};
		auto put16 = [](std::vector<uint8_t>& v, uint16_t x) {
			v.push_back(uint8_t(x)); v.push_back(uint8_t(x >> 8));
		};
		auto putTag = [](std::vector<uint8_t>& v, const char* t) { v.insert(v.end(), t, t + 4); };
		const uint32_t dataBytes = HoldMusic::BYTES_PER_TICK * 4;
		std::vector<uint8_t> body;
		putTag(body, "WAVE");
		putTag(body, "fmt "); put32(body, 18);
		put16(body, 7); put16(body, 1); put32(body, 8000); put32(body, 8000);
		put16(body, 1); put16(body, 8); put16(body, 0);
		putTag(body, "fact"); put32(body, 4); put32(body, dataBytes);
		putTag(body, "data"); put32(body, dataBytes);
		body.insert(body.end(), dataBytes, 0xFF);
		std::vector<uint8_t> file;
		putTag(file, "RIFF"); put32(file, uint32_t(body.size()));
		file.insert(file.end(), body.begin(), body.end());
		const std::string path = std::string(::testing::TempDir()) + filename;
		std::ofstream out(path, std::ios::binary | std::ios::trunc);
		out.write(reinterpret_cast<const char*>(file.data()), std::streamsize(file.size()));
		return path;
	}
}

// #804: a park that times out with the parker gone BYEs the parked party and frees
// the orbit, but never ended the Session inserted at park time: the session slot,
// the virtual peer and the CDR leaked, and music on hold must not outlive it.
TEST(ParkOrbit, TimeoutWithTheParkerGoneEndsTheParkedSessionAndStopsTheMusic)
{
	FakePbxEnv env;
	ParkOrbit park(env);
	HoldMusic moh;
	ASSERT_TRUE(moh.loadClip(writeMohClip("pd_park_804_moh.wav")));
	ASSERT_TRUE(moh.start());
	park.setHoldMusic(&moh);

	const sockaddr_in parkedAddr = FakePbxEnv::addr("192.168.1.50", 5060);
	// The parker is the parked party itself and is not registered in `env`, so the
	// timeout finds nobody to ring back.
	park.onInvite(inviteTo("700", "101", "park-804a@192.168.1.50", parkedAddr, "192.168.1.50"),
		std::make_shared<SipClient>("101", parkedAddr), 0);
	ASSERT_TRUE(env.findSession("Call-ID: park-804a@192.168.1.50")) << "precondition: parked";
	ASSERT_EQ(moh.listenerCount(), 1u) << "precondition: music is playing to the parked phone";

	park.sweep(std::chrono::steady_clock::now() + std::chrono::hours(1));

	ASSERT_EQ(env.byeCalls.size(), 1u) << "the parked party is BYEd";
	EXPECT_TRUE(park.snapshotRows(std::chrono::steady_clock::now(), /*onlyParked=*/false).empty())
		<< "the orbit is freed";
	EXPECT_EQ(moh.listenerCount(), 0u) << "no music left running";
	ASSERT_EQ(env.endedCallIds.size(), 1u) << "the Session must be ended (CDR, pool slot)";
	EXPECT_EQ(env.endedCallIds[0], "Call-ID: park-804a@192.168.1.50");
	EXPECT_FALSE(env.findSession("Call-ID: park-804a@192.168.1.50"));
}

// The same leak on the other timeout: the parker was rung back and never answered.
TEST(ParkOrbit, UnansweredRingbackEndsTheParkedSession)
{
	FakePbxEnv env;
	ParkOrbit park(env);

	const sockaddr_in parkedAddr = FakePbxEnv::addr("192.168.1.50", 5060);
	const sockaddr_in parkerAddr = FakePbxEnv::addr("192.168.1.52", 5060);
	env.registered["102"] = std::make_shared<SipClient>("102", parkerAddr);

	// 101 is parked by 102 (the parker rung back on timeout).
	park.onInvite(inviteTo("700", "101", "park-804b@192.168.1.50", parkedAddr, "192.168.1.50"),
		env.registered["102"], 0);
	const auto t0 = std::chrono::steady_clock::now() + std::chrono::hours(1);

	park.sweep(t0);   // parked -> ringing back
	EXPECT_TRUE(env.endedCallIds.empty()) << "still ringing back: the parked dialog is alive";
	ASSERT_TRUE(env.findSession("Call-ID: park-804b@192.168.1.50"));

	park.sweep(t0 + std::chrono::seconds(31));   // the ring-back deadline passes

	EXPECT_EQ(env.byeCalls.size(), 1u);
	ASSERT_EQ(env.endedCallIds.size(), 1u) << "the Session must be ended";
	EXPECT_EQ(env.endedCallIds[0], "Call-ID: park-804b@192.168.1.50");
}

// onBye asks this to recognise a parked party's BYE without looking at To.
TEST(ParkOrbit, HoldsCallWhileParkedOnly)
{
	FakePbxEnv env;
	ParkOrbit park(env);
	const sockaddr_in parkedAddr = FakePbxEnv::addr("192.168.1.50", 5060);

	EXPECT_FALSE(park.holdsCall("Call-ID: park-804c@192.168.1.50"));
	park.onInvite(inviteTo("700", "101", "park-804c@192.168.1.50", parkedAddr, "192.168.1.50"),
		std::make_shared<SipClient>("101", parkedAddr), 0);
	EXPECT_TRUE(park.holdsCall("Call-ID: park-804c@192.168.1.50"));

	const sockaddr_in retrieverAddr = FakePbxEnv::addr("192.168.1.51", 5060);
	park.onInvite(inviteTo("700", "102", "retrieve-804c@192.168.1.51", retrieverAddr, "192.168.1.51"),
		std::make_shared<SipClient>("102", retrieverAddr), 0);
	EXPECT_FALSE(park.holdsCall("Call-ID: park-804c@192.168.1.50"))
		<< "a retrieved leg is a bridged call: its BYE takes the peer-relay path";
	EXPECT_FALSE(park.holdsCall("Call-ID: retrieve-804c@192.168.1.51"));
}

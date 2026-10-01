// RegistrarLearnLock_test.cpp — issue #440: Learn mode really locks an adopted
// extension to its device.
//
// Before #440, only a Secured extension was MAC-locked, so a board in Learn (the
// fresh-install default since #397/#441) let any new device take any adopted
// extension -- near-Open. These tests drive real REGISTERs through
// RequestsHandler::handle() in Learn mode, with the host ARP stub
// (ArpLookup::setMockMac) standing in for lwIP's table.
//
// The rules under test (Registrar::admitLearn):
//   lock on the SECOND sighting from the same resolved MAC, never the first,
//   and only for the extension's FIRST claim (no earlier device row holds it);
//   another MAC for a locked extension -> 403;
//   an ARP miss for a locked extension -> accepted from the extension's
//   registered IP:port (the owner's refresh; lwIP's ARP table is smaller than
//   the client pool), else 503 + Retry-After, never 403;
//   one MAC registering two extensions -> shared, never locked (NAT router);
//   a full table evicts an unlocked entry (offline first, then the oldest),
//   never a locked one.

#include <gtest/gtest.h>

#include "ArpLookup.hpp"
#include "FakePbxEnv.hpp"
#include "PoolConfig.hpp"
#include "Registrar.hpp"
#include "RequestsHandler.hpp"
#include "SipSecretStore.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace
{
	sockaddr_in addrFor(const std::string& ip, int port = 5060)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(static_cast<uint16_t>(port));
		return s;
	}

	std::string registerRaw(const std::string& ext, const std::string& ip, int port, int expires, int seq)
	{
		const std::string id = "r" + std::to_string(seq);
		const std::string hostPort = ip + ":" + std::to_string(port);
		return "REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + hostPort + ";branch=z9hG4bK" + id + "\r\n"
			"From: <sip:" + ext + "@server>;tag=t" + id + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + id + "@" + ip + "\r\n"
			"CSeq: " + std::to_string(seq) + " REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + hostPort + ">;expires=" + std::to_string(expires) + "\r\n"
			"Content-Length: 0\r\n\r\n";
	}

	ArpLookup::Mac macOf(uint8_t last)
	{
		return ArpLookup::Mac{0x02, 0x00, 0x00, 0x00, 0x00, last};
	}

	std::string hexOf(uint8_t last)
	{
		return ArpLookup::toHex12(macOf(last));
	}

	struct Wire
	{
		std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	};

	class LearnLockTest : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			ArpLookup::clearMockMacs();
			_handler = std::make_unique<RequestsHandler>("192.168.60.1", 5060,
				[this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
					_wire.sent.emplace_back(a, std::move(m));
				});
			_handler->setRegistrarMode(RequestsHandler::RegistrarMode::Learn);
		}
		void TearDown() override
		{
			ArpLookup::clearMockMacs();
			// Here, not in the test body: a failed ASSERT returns early and would
			// leak the secret into every later test.
			SipSecretStore::clearSecret("201");
		}

		// REGISTER `ext` from `ip`:`port`; returns the status line of the response.
		std::string registerFrom(const std::string& ext, const std::string& ip, int expires = 3600, int port = 5060)
		{
			const std::string raw = registerRaw(ext, ip, port, expires, ++_seq);
			_wire.sent.clear();
			_handler->handle(RequestsHandler::getMessageFromPool(raw, addrFor(ip, port)));
			for (const auto& [a, m] : _wire.sent)
			{
				if (!m) continue;
				const std::string s = m->toString();
				if (s.rfind("SIP/2.0 ", 0) == 0 && s.find("REGISTER") != std::string::npos)
					return s.substr(0, s.find("\r\n"));
			}
			return "";
		}

		std::string lastResponseText() const
		{
			for (const auto& [a, m] : _wire.sent)
				if (m && m->toString().rfind("SIP/2.0 ", 0) == 0) return m->toString();
			return "";
		}

		const Registrar::AdoptedDevice* device(const std::string& mac)
		{
			_devices = _handler->getAdoptedDevices();
			for (const auto& d : _devices)
				if (d.mac == mac) return &d;
			return nullptr;
		}

		// The address `ext` is registered at ("ip:port"), "" if it has no binding.
		std::string boundAddress(const std::string& ext)
		{
			_handler->forceNextTickForTest();   // getActiveClients() reads tick()'s snapshot
			_handler->tick();
			for (const auto& [number, address] : _handler->getActiveClients())
				if (number == ext) return address;
			return "";
		}

		// P (192.168.60.21, MAC ..21) registers 201 twice and holds its lock.
		void lockOwner()
		{
			ArpLookup::setMockMac(addrFor("192.168.60.21"), macOf(0x21));
			registerFrom("201", "192.168.60.21");
			registerFrom("201", "192.168.60.21");
			ASSERT_TRUE(device(hexOf(0x21)) && device(hexOf(0x21))->locked);
			ASSERT_EQ(boundAddress("201"), "192.168.60.21:5060");
		}

		Wire _wire;
		std::unique_ptr<RequestsHandler> _handler;
		std::vector<Registrar::AdoptedDevice> _devices;
		int _seq = 0;
	};
}

TEST_F(LearnLockTest, LocksOnTheSecondSightingNotTheFirst)
{
	ArpLookup::setMockMac(addrFor("192.168.60.21"), macOf(0x21));

	EXPECT_EQ(registerFrom("201", "192.168.60.21").substr(0, 11), "SIP/2.0 200");
	const auto* d = device(hexOf(0x21));
	ASSERT_NE(d, nullptr) << "first resolved REGISTER adopts the device";
	EXPECT_FALSE(d->locked) << "one sighting must never lock -- it could be a stray packet";

	EXPECT_EQ(registerFrom("201", "192.168.60.21").substr(0, 11), "SIP/2.0 200");
	d = device(hexOf(0x21));
	ASSERT_NE(d, nullptr);
	EXPECT_TRUE(d->locked) << "the phone's own refresh completes the lock";
}

TEST_F(LearnLockTest, AnArpMissNeverAdoptsOrLocks)
{
	// No mock entry: a first-packet miss, or a routed off-subnet phone forever.
	for (int i = 0; i < 4; ++i)
		EXPECT_EQ(registerFrom("202", "10.9.9.9").substr(0, 11), "SIP/2.0 200")
			<< "an unresolvable phone must never be refused on an unlocked extension";
	EXPECT_TRUE(_handler->getAdoptedDevices().empty())
		<< "nothing is adopted -- let alone locked -- without a resolved MAC";
}

TEST_F(LearnLockTest, AnotherDeviceCannotTakeALockedExtension)
{
	ArpLookup::setMockMac(addrFor("192.168.60.21"), macOf(0x21));
	ArpLookup::setMockMac(addrFor("192.168.60.66"), macOf(0x66));
	registerFrom("201", "192.168.60.21");
	registerFrom("201", "192.168.60.21");
	ASSERT_TRUE(device(hexOf(0x21)) && device(hexOf(0x21))->locked);

	EXPECT_EQ(registerFrom("201", "192.168.60.66").substr(0, 11), "SIP/2.0 403")
		<< "a new device must not take an extension Learn has locked (#440)";
	EXPECT_EQ(device(hexOf(0x66)), nullptr) << "the impostor is not adopted either";
	EXPECT_EQ(registerFrom("201", "192.168.60.21").substr(0, 11), "SIP/2.0 200")
		<< "the owner keeps registering";
}

TEST_F(LearnLockTest, AnArpMissOnALockedExtensionIsRetryableNotALockout)
{
	ASSERT_NO_FATAL_FAILURE(lockOwner());

	// A source that neither resolves nor is the registered binding: the owner
	// from a new address whose ARP entry is not there yet, or an off-link
	// impostor. The PBX cannot tell which, so it asks for a retry.
	ArpLookup::clearMockMacs();
	EXPECT_EQ(registerFrom("201", "192.168.60.77").substr(0, 11), "SIP/2.0 503")
		<< "unverifiable on a locked extension: ask for a retry, never 403 the owner";
	EXPECT_NE(lastResponseText().find("Retry-After: 5"), std::string::npos) << lastResponseText();
	EXPECT_EQ(registerFrom("201", "192.168.60.21", 3600, 5070).substr(0, 11), "SIP/2.0 503")
		<< "the registered IP with another port is not the registered address";
	ASSERT_TRUE(device(hexOf(0x21)) && device(hexOf(0x21))->locked) << "the lock is untouched";
	EXPECT_EQ(boundAddress("201"), "192.168.60.21:5060") << "a refused REGISTER never moves the binding";

	ArpLookup::setMockMac(addrFor("192.168.60.77"), macOf(0x21));
	EXPECT_EQ(registerFrom("201", "192.168.60.77").substr(0, 11), "SIP/2.0 200")
		<< "once the owner resolves, the retry succeeds";
}

// lwIP's ARP table (10 entries) is smaller than the client pool (32 phones, each
// OPTIONS-pinged every 5 s), so a locked phone's own refresh often misses, and
// its retry 5 s later can miss again. The extension's registered IP:port is the
// owner's: accept it and change nothing.
TEST_F(LearnLockTest, ALockedPhonesRefreshFromItsRegisteredAddressSurvivesArpMisses)
{
	ASSERT_NO_FATAL_FAILURE(lockOwner());
	ArpLookup::clearMockMacs();

	for (int i = 0; i < 5; ++i)
		EXPECT_EQ(registerFrom("201", "192.168.60.21").substr(0, 11), "SIP/2.0 200") << "miss " << i;
	const auto* d = device(hexOf(0x21));
	ASSERT_NE(d, nullptr);
	EXPECT_TRUE(d->locked) << "accepted on a miss, the lock is unchanged";
	EXPECT_EQ(d->extension, "201");
	EXPECT_FALSE(d->shared);
	EXPECT_EQ(boundAddress("201"), "192.168.60.21:5060");

	ArpLookup::setMockMac(addrFor("192.168.60.66"), macOf(0x66));
	EXPECT_EQ(registerFrom("201", "192.168.60.66").substr(0, 11), "SIP/2.0 403") << "the lock still holds";
}

// Review gap: a de-REGISTER the lock refuses must not touch the owner's binding,
// whether it comes from another device or from a source that does not resolve.
TEST_F(LearnLockTest, ARefusedDeregisterLeavesTheLockedOwnerRegistered)
{
	ASSERT_NO_FATAL_FAILURE(lockOwner());

	ArpLookup::setMockMac(addrFor("192.168.60.66"), macOf(0x66));
	EXPECT_EQ(registerFrom("201", "192.168.60.66", 0).substr(0, 11), "SIP/2.0 403");
	EXPECT_EQ(boundAddress("201"), "192.168.60.21:5060") << "another device's expires=0 unregistered the owner";

	EXPECT_EQ(registerFrom("201", "192.168.60.77", 0).substr(0, 11), "SIP/2.0 503");
	EXPECT_EQ(boundAddress("201"), "192.168.60.21:5060") << "an ARP-miss expires=0 unregistered the owner";
}

TEST_F(LearnLockTest, OneMacWithTwoExtensionsIsSharedAndNeverLocks)
{
	// Two phones behind one NAT router both resolve to the router's MAC.
	ArpLookup::setMockMac(addrFor("192.168.60.1"), macOf(0x01));
	ArpLookup::setMockMac(addrFor("192.168.60.30"), macOf(0x30));
	registerFrom("201", "192.168.60.1");
	registerFrom("202", "192.168.60.1");
	registerFrom("201", "192.168.60.1");
	registerFrom("202", "192.168.60.1");
	const auto* router = device(hexOf(0x01));
	ASSERT_NE(router, nullptr);
	EXPECT_TRUE(router->shared);
	EXPECT_FALSE(router->locked) << "a MAC that vouches for two extensions vouches for neither";

	EXPECT_EQ(registerFrom("201", "192.168.60.30").substr(0, 11), "SIP/2.0 200")
		<< "a shared MAC must not lock its extensions against anyone";
}

TEST_F(LearnLockTest, AFullTableEvictsTheOldestUnlockedNeverALockedDevice)
{
	// Fill the table: the two oldest entries unlocked, the rest locked.
	_handler->adoptDeviceForTest(hexOf(0x80), "300", Registrar::DeviceState::Learned, /*locked=*/false);
	_handler->adoptDeviceForTest(hexOf(0x81), "301", Registrar::DeviceState::Learned, /*locked=*/false);
	for (int i = 2; i < POCKETDIAL_MAX_CLIENTS; ++i)
		_handler->adoptDeviceForTest(hexOf(static_cast<uint8_t>(0x80 + i)), std::to_string(300 + i),
			Registrar::DeviceState::Learned, /*locked=*/true);
	ASSERT_EQ(_handler->getAdoptedDevices().size(), static_cast<size_t>(POCKETDIAL_MAX_CLIENTS));

	// Newcomer MACs sit OUTSIDE the seeded 0x80.. range (Crew, #487 review: 0x99
	// and 0x98 were already seeded, so nothing was new and nothing was evicted).
	ArpLookup::setMockMac(addrFor("192.168.60.99"), macOf(0x41));
	EXPECT_EQ(registerFrom("399", "192.168.60.99").substr(0, 11), "SIP/2.0 200")
		<< "a full table must not refuse every new phone forever";
	EXPECT_EQ(device(hexOf(0x80)), nullptr) << "the OLDEST unlocked entry is the one evicted";
	EXPECT_NE(device(hexOf(0x81)), nullptr) << "only one entry makes room for one newcomer";
	EXPECT_NE(device(hexOf(0x41)), nullptr);

	ArpLookup::setMockMac(addrFor("192.168.60.97"), macOf(0x42));
	EXPECT_EQ(registerFrom("397", "192.168.60.97").substr(0, 11), "SIP/2.0 200");
	EXPECT_EQ(device(hexOf(0x81)), nullptr) << "the next-oldest unlocked entry goes next";
	EXPECT_NE(device(hexOf(0x41)), nullptr) << "the newer unlocked entry outlives the older one";
	for (int i = 2; i < POCKETDIAL_MAX_CLIENTS; ++i)
		EXPECT_NE(device(hexOf(static_cast<uint8_t>(0x80 + i))), nullptr) << "a locked device was evicted";

	// Now every entry but the newcomers is locked; lock the newcomers too.
	registerFrom("399", "192.168.60.99");
	registerFrom("397", "192.168.60.97");
	ArpLookup::setMockMac(addrFor("192.168.60.98"), macOf(0x40));
	EXPECT_EQ(registerFrom("398", "192.168.60.98").substr(0, 11), "SIP/2.0 403")
		<< "with only locked devices left, refuse rather than release a lock";
}

// The review asked for the eviction ORDER, offline-first included. A Registrar
// with a fake environment, so the test can take a device offline.
TEST(LearnLockEviction, AnOfflineEntryGoesFirstThenTheOldest)
{
	struct ClearMocks { ~ClearMocks() { ArpLookup::clearMockMacs(); } } clearMocks;   // also on a failed ASSERT
	FakePbxEnv env;
	Registrar reg(env, Registrar::Mode::Learn);
	const auto macHex = [](uint8_t n) { return ArpLookup::toHex12({0x02, 0x00, 0x00, 0x00, 0x07, n}); };
	const auto present = [&reg](const std::string& mac) {
		for (const auto& d : reg.adoptedDevices())
			if (d.mac == mac) return true;
		return false;
	};
	reg.adoptDeviceForTest(macHex(0), "700");   // oldest, online
	reg.adoptDeviceForTest(macHex(1), "701");   // online
	reg.adoptDeviceForTest(macHex(2), "702");   // newest candidate, but offline
	reg.markOnline(macHex(2), false);
	for (int i = 3; i < POCKETDIAL_MAX_CLIENTS; ++i)
		reg.adoptDeviceForTest(macHex(static_cast<uint8_t>(i)), std::to_string(700 + i),
			Registrar::DeviceState::Learned, /*locked=*/true);

	const auto admitNew = [&](uint8_t n) {
		const std::string ip = "10.51.7." + std::to_string(n);
		const sockaddr_in src = FakePbxEnv::addr(ip.c_str(), 5060);
		ArpLookup::setMockMac(src, {0x02, 0x00, 0x00, 0x00, 0x08, n});
		std::string reason;
		const auto decision = reg.admitLearn(
			std::make_shared<SipMessage>(registerRaw(std::to_string(800 + n), ip, 5060, 3600, n), src),
			std::to_string(800 + n), reason);
		reg.markOnline(ArpLookup::toHex12({0x02, 0x00, 0x00, 0x00, 0x08, n}), true);   // as onRegister() does
		return decision;
	};

	ASSERT_EQ(admitNew(1), Registrar::AuthDecision::Accept);
	EXPECT_FALSE(present(macHex(2))) << "an offline entry goes before any online one";
	EXPECT_TRUE(present(macHex(0)) && present(macHex(1)));

	ASSERT_EQ(admitNew(2), Registrar::AuthDecision::Accept);
	EXPECT_FALSE(present(macHex(0))) << "then the oldest";
	EXPECT_TRUE(present(macHex(1)));

	ASSERT_EQ(admitNew(3), Registrar::AuthDecision::Accept);
	EXPECT_FALSE(present(macHex(1)));
	EXPECT_EQ(reg.adoptedDevices().size(), static_cast<size_t>(POCKETDIAL_MAX_CLIENTS));
}

TEST_F(LearnLockTest, SecuredDevicesBehaveAsBefore)
{
	_handler->adoptDeviceForTest(hexOf(0x21), "201", Registrar::DeviceState::Secured);
	ArpLookup::setMockMac(addrFor("192.168.60.66"), macOf(0x66));
	EXPECT_EQ(registerFrom("201", "192.168.60.66").substr(0, 11), "SIP/2.0 403")
		<< "a Secured extension stays locked to its device, as before #440";
}

// Crew's #487 review (MEDIUM 1): one REGISTER for another extension with a locked
// phone's source IP forged (so ARP returns its real MAC) used to release the lock
// and mark the MAC shared for good. A locked record never moves: the other
// extension is plain TOFU and the lock holds.
TEST_F(LearnLockTest, AForgedRegisterForAnotherExtensionCannotReleaseALock)
{
	ArpLookup::setMockMac(addrFor("192.168.60.21"), macOf(0x21));
	registerFrom("201", "192.168.60.21");
	registerFrom("201", "192.168.60.21");
	ASSERT_TRUE(device(hexOf(0x21)) && device(hexOf(0x21))->locked);

	EXPECT_EQ(registerFrom("202", "192.168.60.21").substr(0, 11), "SIP/2.0 200")
		<< "the other extension is admitted as TOFU";
	const auto* d = device(hexOf(0x21));
	ASSERT_NE(d, nullptr);
	EXPECT_EQ(d->extension, "201") << "a locked record must not move";
	EXPECT_TRUE(d->locked);
	EXPECT_FALSE(d->shared) << "a locked MAC is never marked shared by one packet";

	ArpLookup::setMockMac(addrFor("192.168.60.66"), macOf(0x66));
	EXPECT_EQ(registerFrom("201", "192.168.60.66").substr(0, 11), "SIP/2.0 403")
		<< "and the attacker still cannot take the locked extension";
}

// #507 finding 1 (Crew): an ARP miss must not admit a Secured extension. An
// off-subnet or never-ARP'd source always misses; it now has to prove the secret.
TEST_F(LearnLockTest, ASecuredExtensionFromAnArpMissIsChallengedNotAccepted)
{
	ASSERT_TRUE(SipSecretStore::setSecret("201", "s3cret-201"));
	_handler->adoptDeviceForTest(hexOf(0x21), "201", Registrar::DeviceState::Secured);
	ArpLookup::clearMockMacs();   // the source resolves to nothing

	EXPECT_EQ(registerFrom("201", "10.9.9.9").substr(0, 11), "SIP/2.0 401")
		<< "a Secured extension is authenticated on a miss, never waved through";
}

// The registered-address acceptance on an ARP miss is for Learn-LOCKED
// extensions only. A Secured one is digest-checked first, from its own
// registered address too, and a refused de-REGISTER leaves its binding alone.
TEST_F(LearnLockTest, ASecuredExtensionIsChallengedOnAMissEvenFromItsRegisteredAddress)
{
	ASSERT_TRUE(SipSecretStore::setSecret("201", "s3cret-201"));
	_handler->adoptDeviceForTest(hexOf(0x21), "201", Registrar::DeviceState::Secured);
	_handler->bindClientBypassingGuardsForTest("201", addrFor("192.168.60.21"));
	ASSERT_EQ(boundAddress("201"), "192.168.60.21:5060");
	ArpLookup::clearMockMacs();   // every lookup misses

	EXPECT_EQ(registerFrom("201", "192.168.60.21").substr(0, 11), "SIP/2.0 401")
		<< "the registered address never stands in for the digest";
	EXPECT_EQ(registerFrom("201", "192.168.60.21", 0).substr(0, 11), "SIP/2.0 401");
	EXPECT_EQ(registerFrom("201", "192.168.60.77", 0).substr(0, 11), "SIP/2.0 401");
	EXPECT_EQ(boundAddress("201"), "192.168.60.21:5060") << "an unauthenticated expires=0 unregistered the owner";
	const auto* d = device(hexOf(0x21));
	ASSERT_NE(d, nullptr);
	EXPECT_EQ(d->state, Registrar::DeviceState::Secured);
}

// Review MEDIUM: the lock went to the first device to register TWICE, not the
// first to claim the extension. Phone P registers 201 once; device N registers
// 201 and then de-registers it (two REGISTERs from N's own MAC). Pre-#440 N held
// 201 only until P's next refresh; it must not now lock P out.
TEST_F(LearnLockTest, ALaterClaimNeverTakesTheLockFromTheFirst)
{
	ArpLookup::setMockMac(addrFor("192.168.60.21"), macOf(0x21));
	ArpLookup::setMockMac(addrFor("192.168.60.66"), macOf(0x66));
	EXPECT_EQ(registerFrom("201", "192.168.60.21").substr(0, 11), "SIP/2.0 200");   // P claims 201

	EXPECT_EQ(registerFrom("201", "192.168.60.66").substr(0, 11), "SIP/2.0 200");   // N, TOFU
	EXPECT_EQ(registerFrom("201", "192.168.60.66", 0).substr(0, 11), "SIP/2.0 200");
	ASSERT_NE(device(hexOf(0x66)), nullptr);
	EXPECT_FALSE(device(hexOf(0x66))->locked) << "P's row still holds 201: N must not lock it";

	EXPECT_EQ(registerFrom("201", "192.168.60.21").substr(0, 11), "SIP/2.0 200") << "P keeps working";
	ASSERT_NE(device(hexOf(0x21)), nullptr);
	EXPECT_TRUE(device(hexOf(0x21))->locked) << "P's second registration locks 201 to P";
	EXPECT_EQ(registerFrom("201", "192.168.60.66").substr(0, 11), "SIP/2.0 403");
}

// Two rows can hold one extension (the owner's lock and a later claim that never
// locked). Secure and forget by EXTENSION act on the row that holds the lock.
TEST_F(LearnLockTest, SecureAndForgetByExtensionActOnTheLockHolder)
{
	ASSERT_TRUE(SipSecretStore::setSecret("201", "s3cret-201"));
	_handler->adoptDeviceForTest(hexOf(0x66), "201", Registrar::DeviceState::Learned, true);   // the lock
	_handler->adoptDeviceForTest(hexOf(0x21), "201");                                     // a later claim

	ASSERT_TRUE(_handler->secureDevice("201"));
	ASSERT_NE(device(hexOf(0x66)), nullptr);
	EXPECT_EQ(device(hexOf(0x66))->state, Registrar::DeviceState::Secured) << "secure promoted the wrong row";
	ASSERT_NE(device(hexOf(0x21)), nullptr);
	EXPECT_EQ(device(hexOf(0x21))->state, Registrar::DeviceState::Learned);

	ASSERT_TRUE(_handler->forgetDevice("201"));
	EXPECT_EQ(device(hexOf(0x66)), nullptr) << "forget by extension must release the lock holder";
	EXPECT_NE(device(hexOf(0x21)), nullptr);
}

// #507 finding 2 (Crew): a REGISTER for another extension from a Secured device's
// MAC (e.g. with its source IP forged) must not move that device's record off
// its Secured extension before any digest is checked.
TEST_F(LearnLockTest, AnUnauthenticatedRegisterCannotMoveASecuredDevicesExtension)
{
	ASSERT_TRUE(SipSecretStore::setSecret("201", "s3cret-201"));
	_handler->adoptDeviceForTest(hexOf(0x21), "201", Registrar::DeviceState::Secured);
	ArpLookup::setMockMac(addrFor("192.168.60.21"), macOf(0x21));

	// An ORDINARY extension: "999" is refused by the reserved-AOR guard before
	// admitLearn ever runs, which left this test green without the fix (Crew, #487).
	EXPECT_EQ(registerFrom("202", "192.168.60.21").substr(0, 11), "SIP/2.0 403")
		<< "the device authenticates for 202, which has no secret: Extension Not Provisioned";
	const auto* d = device(hexOf(0x21));
	ASSERT_NE(d, nullptr);
	EXPECT_EQ(d->extension, "201") << "the Secured record must not have moved";
	EXPECT_EQ(d->state, Registrar::DeviceState::Secured);

	// And the extension is still locked against another device.
	ArpLookup::setMockMac(addrFor("192.168.60.66"), macOf(0x66));
	EXPECT_EQ(registerFrom("201", "192.168.60.66").substr(0, 11), "SIP/2.0 403");
}

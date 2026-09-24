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
//   lock on the SECOND sighting from the same resolved MAC, never the first;
//   another MAC for a locked extension -> 403;
//   an ARP miss for a locked extension -> 503 + Retry-After, never 403;
//   one MAC registering two extensions -> shared, never locked (NAT router);
//   a full table evicts the oldest unlocked entry, never a locked one.

#include <gtest/gtest.h>

#include "ArpLookup.hpp"
#include "PoolConfig.hpp"
#include "RequestsHandler.hpp"

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
	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
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
		void TearDown() override { ArpLookup::clearMockMacs(); }

		// REGISTER `ext` from `ip`; returns the status line of the response.
		std::string registerFrom(const std::string& ext, const std::string& ip)
		{
			const std::string id = "r" + std::to_string(++_seq);
			const std::string raw =
				"REGISTER sip:server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bK" + id + "\r\n"
				"From: <sip:" + ext + "@server>;tag=t" + id + "\r\n"
				"To: <sip:" + ext + "@server>\r\n"
				"Call-ID: " + id + "@" + ip + "\r\n"
				"CSeq: " + std::to_string(_seq) + " REGISTER\r\n"
				"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
				"Content-Length: 0\r\n\r\n";
			_wire.sent.clear();
			_handler->handle(RequestsHandler::getMessageFromPool(raw, addrFor(ip)));
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
	ArpLookup::setMockMac(addrFor("192.168.60.21"), macOf(0x21));
	registerFrom("201", "192.168.60.21");
	registerFrom("201", "192.168.60.21");
	ASSERT_TRUE(device(hexOf(0x21)) && device(hexOf(0x21))->locked);

	// The owner's ARP entry aged out (or an off-link impostor): cannot tell yet.
	ArpLookup::clearMockMacs();
	EXPECT_EQ(registerFrom("201", "192.168.60.21").substr(0, 11), "SIP/2.0 503")
		<< "unverifiable on a locked extension: ask for a retry, never 403 the owner";
	EXPECT_NE(lastResponseText().find("Retry-After: 5"), std::string::npos) << lastResponseText();
	ASSERT_TRUE(device(hexOf(0x21)) && device(hexOf(0x21))->locked) << "the lock is untouched";

	ArpLookup::setMockMac(addrFor("192.168.60.21"), macOf(0x21));
	EXPECT_EQ(registerFrom("201", "192.168.60.21").substr(0, 11), "SIP/2.0 200")
		<< "once the owner resolves, the retry succeeds";
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
	// Fill the table: the first entry unlocked (oldest), the rest locked.
	_handler->adoptDeviceForTest(hexOf(0x80), "300", Registrar::DeviceState::Learned, /*locked=*/false);
	for (int i = 1; i < POCKETDIAL_MAX_CLIENTS; ++i)
		_handler->adoptDeviceForTest(hexOf(static_cast<uint8_t>(0x80 + i)), std::to_string(300 + i),
			Registrar::DeviceState::Learned, /*locked=*/true);
	ASSERT_EQ(_handler->getAdoptedDevices().size(), static_cast<size_t>(POCKETDIAL_MAX_CLIENTS));

	ArpLookup::setMockMac(addrFor("192.168.60.99"), macOf(0x99));
	EXPECT_EQ(registerFrom("399", "192.168.60.99").substr(0, 11), "SIP/2.0 200")
		<< "a full table must not refuse every new phone forever";
	EXPECT_EQ(device(hexOf(0x80)), nullptr) << "the oldest UNLOCKED entry is the one evicted";
	EXPECT_NE(device(hexOf(0x99)), nullptr);
	for (int i = 1; i < POCKETDIAL_MAX_CLIENTS; ++i)
		EXPECT_NE(device(hexOf(static_cast<uint8_t>(0x80 + i))), nullptr) << "a locked device was evicted";

	// Now every entry but the newcomer is locked; lock the newcomer too.
	registerFrom("399", "192.168.60.99");
	ArpLookup::setMockMac(addrFor("192.168.60.98"), macOf(0x98));
	EXPECT_EQ(registerFrom("398", "192.168.60.98").substr(0, 11), "SIP/2.0 403")
		<< "with only locked devices left, refuse rather than release a lock";
}

TEST_F(LearnLockTest, SecuredDevicesBehaveAsBefore)
{
	_handler->adoptDeviceForTest(hexOf(0x21), "201", Registrar::DeviceState::Secured);
	ArpLookup::setMockMac(addrFor("192.168.60.66"), macOf(0x66));
	EXPECT_EQ(registerFrom("201", "192.168.60.66").substr(0, 11), "SIP/2.0 403")
		<< "a Secured extension stays locked to its device, as before #440";
}

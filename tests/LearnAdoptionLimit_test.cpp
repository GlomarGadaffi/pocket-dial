// LearnAdoptionLimit_test.cpp — issue #515 items 2 and 3.
//
// Learn mode adopts any MAC it has not seen, and every adoption is one NVS write.
// An on-link host that answers ARP for many fake MACs could fill the device table
// (POCKETDIAL_MAX_CLIENTS) in one burst, and that survived reboot: every new phone
// then got "Device Table Full" until an admin forgot the entries one by one. Since
// #440 a full table evicts its oldest unlocked entry instead, so the burst would
// push out real, not-yet-locked phones; "Device Table Full" is left for a table of
// locked or Secured devices only.
//
//   item 2: a token bucket on NEW adoptions (Registrar::kAdoptBurst, one more per
//           kAdoptRefill). Past it a new MAC gets a retryable 503 + Retry-After.
//   item 3: Registrar::forgetLearned(), one action that drops every Learned device
//           and keeps the Secured ones (the HTTP route is pinned in AdminHttpGate).
//
// The host has no ARP table, so each test gives its source IPs a mock MAC
// (ArpLookup::setMockMac) and clears them in TearDown: the rest of the suite
// relies on the host's permanent ARP miss.

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "ArpLookup.hpp"
#include "FakePbxEnv.hpp"
#include "PoolConfig.hpp"
#include "Registrar.hpp"
#include "RequestsHandler.hpp"

namespace
{
	using Clock = std::chrono::steady_clock;
	using Decision = Registrar::AuthDecision;

	// 10.51.5.<n> is used by no other test.
	std::string ipFor(int n) { return "10.51.5." + std::to_string(n); }

	std::string registerRaw(const std::string& ext, const std::string& ip)
	{
		return "REGISTER sip:10.51.5.1 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bK515" + ext + "\r\n"
			"From: <sip:" + ext + "@10.51.5.1>;tag=t" + ext + "\r\n"
			"To: <sip:" + ext + "@10.51.5.1>\r\n"
			"Call-ID: learn515-" + ext + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
	}

	class LearnAdoptionLimit : public ::testing::Test
	{
	protected:
		void TearDown() override { ArpLookup::clearMockMacs(); }

		// Phone n: source 10.51.5.n, MAC 02:00:00:00:05:n, extension 5100+n.
		static std::string ext(int n) { return std::to_string(5100 + n); }
		static sockaddr_in phone(int n)
		{
			const sockaddr_in a = FakePbxEnv::addr(ipFor(n).c_str(), 5060);
			ArpLookup::setMockMac(a, {0x02, 0x00, 0x00, 0x00, 0x05, static_cast<uint8_t>(n)});
			return a;
		}

		Decision admit(Registrar& r, int n, Clock::time_point now)
		{
			std::string reason;
			return r.admitLearn(std::make_shared<SipMessage>(registerRaw(ext(n), ipFor(n)), phone(n)),
				ext(n), reason, now);
		}
	};
}

TEST_F(LearnAdoptionLimit, NewMacsPastTheBudgetGetA503WithRetryAfterAndAreNotAdopted)
{
	// Threat: a host answering ARP for many fake MACs adopts them (one NVS write
	// each) as fast as it can send REGISTERs. The budget caps the burst.
	FakePbxEnv env;
	Registrar reg(env, Registrar::Mode::Learn);
	const Clock::time_point t0{};

	for (int n = 1; n <= Registrar::kAdoptBurst; ++n)
		ASSERT_EQ(admit(reg, n, t0), Decision::Accept) << "phone " << n << " is within the budget";
	env.sent.clear();

	EXPECT_EQ(admit(reg, Registrar::kAdoptBurst + 1, t0), Decision::RetryLater);
	EXPECT_EQ(reg.adoptedDevices().size(), static_cast<size_t>(Registrar::kAdoptBurst));
	ASSERT_EQ(env.sent.size(), 1u);
	const std::string resp = env.sentRaw(0);
	EXPECT_EQ(resp.rfind("SIP/2.0 503 Service Unavailable\r\n", 0), 0u) << resp;
	EXPECT_NE(resp.find("Retry-After: 15\r\n"), std::string::npos) << resp;
}

TEST_F(LearnAdoptionLimit, ARefusedPhoneGetsInOnceItsRetryAfterHasPassed)
{
	// Threat: the limit must not become a new lockout. A refusal is retryable, and
	// Retry-After says exactly when the next adoption is possible.
	FakePbxEnv env;
	Registrar reg(env, Registrar::Mode::Learn);
	const Clock::time_point t0{};
	const int late = Registrar::kAdoptBurst + 1;

	for (int n = 1; n <= Registrar::kAdoptBurst; ++n) ASSERT_EQ(admit(reg, n, t0), Decision::Accept);

	env.sent.clear();
	EXPECT_EQ(admit(reg, late, t0 + Registrar::kAdoptRefill - std::chrono::seconds(1)), Decision::RetryLater);
	ASSERT_EQ(env.sent.size(), 1u);
	EXPECT_NE(env.sentRaw(0).find("Retry-After: 1\r\n"), std::string::npos) << env.sentRaw(0);

	env.sent.clear();
	EXPECT_EQ(admit(reg, late, t0 + Registrar::kAdoptRefill), Decision::Accept);
	EXPECT_TRUE(env.sent.empty()) << "an Accept sends nothing itself";
	EXPECT_EQ(reg.adoptedDevices().size(), static_cast<size_t>(late));
}

TEST_F(LearnAdoptionLimit, KnownMacsNeverSpendTheBudget)
{
	// Threat: after a reboot every phone re-REGISTERs within seconds. They are all
	// known (loaded from NVS), so none of them may be 503'd by the limit.
	FakePbxEnv env;
	Registrar reg(env, Registrar::Mode::Learn);
	const Clock::time_point t0{};

	for (int n = 1; n <= Registrar::kAdoptBurst; ++n) ASSERT_EQ(admit(reg, n, t0), Decision::Accept);
	for (int round = 0; round < 5; ++round)
		for (int n = 1; n <= Registrar::kAdoptBurst; ++n)
			EXPECT_EQ(admit(reg, n, t0), Decision::Accept) << "known phone " << n;

	// Positive control: the budget really is spent, so the Accepts above were
	// not just a bucket with tokens left.
	EXPECT_EQ(admit(reg, Registrar::kAdoptBurst + 1, t0), Decision::RetryLater);
}

TEST_F(LearnAdoptionLimit, AnOverBudgetNewMacOnAFullTableEvictsNothing)
{
	// Threat (#440 meets this budget): a full table makes room by evicting its
	// oldest unlocked device. If that ran before the token check, every new MAC
	// past the budget would still erase one device and then be 503'd, so a flood
	// could empty the table one refusal at a time.
	FakePbxEnv env;
	Registrar reg(env, Registrar::Mode::Learn);
	const Clock::time_point t0{};
	auto seeded = [](int i) { return ArpLookup::toHex12({0x02, 0x00, 0x00, 0x00, 0x06, static_cast<uint8_t>(i)}); };
	for (int i = 0; i < POCKETDIAL_MAX_CLIENTS; ++i) reg.adoptDeviceForTest(seeded(i), std::to_string(5200 + i));

	for (int n = 1; n <= Registrar::kAdoptBurst; ++n)
	{
		ASSERT_EQ(admit(reg, n, t0), Decision::Accept) << "phone " << n << " is within the budget";
		reg.markOnline(ArpLookup::toHex12({0x02, 0x00, 0x00, 0x00, 0x05, static_cast<uint8_t>(n)}), true);   // as onRegister() does
	}
	ASSERT_EQ(reg.adoptedDevices().size(), static_cast<size_t>(POCKETDIAL_MAX_CLIENTS)) << "each adoption evicted one";

	EXPECT_EQ(admit(reg, Registrar::kAdoptBurst + 1, t0), Decision::RetryLater);
	const auto left = reg.adoptedDevices();
	EXPECT_EQ(left.size(), static_cast<size_t>(POCKETDIAL_MAX_CLIENTS)) << "a refused adoption evicted a device";
	size_t seededLeft = 0;
	for (const auto& d : left)
		if (d.mac.rfind("0200000006", 0) == 0) ++seededLeft;
	EXPECT_EQ(seededLeft, static_cast<size_t>(POCKETDIAL_MAX_CLIENTS - Registrar::kAdoptBurst));
}

TEST_F(LearnAdoptionLimit, ForgetLearnedDropsEveryLearnedDeviceAndKeepsTheSecuredOne)
{
	// Threat: the one-step recovery must not unlock a Secured extension (a
	// forgotten Secured device would be re-learned by whoever REGISTERs next).
	FakePbxEnv env;
	Registrar reg(env, Registrar::Mode::Learn);
	reg.adoptDeviceForTest("020000000501", "5101");
	reg.adoptDeviceForTest("020000000502", "5102");
	reg.adoptDeviceForTest("020000000503", "5103");
	reg.adoptDeviceForTest("0200000005aa", "5110", Registrar::DeviceState::Secured);
	(void)reg.consumeDevicesChange();

	EXPECT_EQ(reg.forgetLearned(), 3u);

	const auto left = reg.adoptedDevices();
	ASSERT_EQ(left.size(), 1u);
	EXPECT_EQ(left[0].mac, "0200000005aa");
	EXPECT_EQ(left[0].state, Registrar::DeviceState::Secured);
	EXPECT_EQ(reg.consumeDevicesChange(), Registrar::Change::Structural) << "the dashboard mirror must rebuild";
	EXPECT_TRUE(reg.isExtensionSecured("5110"));
}

TEST_F(LearnAdoptionLimit, AnOverBudgetRegisterIsAnswered503AndNeverBound)
{
	// Threat: RetryLater is a new decision. If onRegister() treated it like
	// Accept, the refused phone would be bound (and answered 200) anyway.
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("10.51.5.1", 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });

	const int late = Registrar::kAdoptBurst + 1;
	for (int n = 1; n <= late; ++n)
	{
		if (n == late) sent.clear();
		handler.handle(RequestsHandler::getMessageFromPool(registerRaw(ext(n), ipFor(n)), phone(n)));
	}

	std::vector<std::string> responses;
	for (const auto& [addr, msg] : sent)
	{
		(void)addr;
		ASSERT_NE(msg, nullptr);
		const std::string raw = msg->toString();
		if (raw.rfind("SIP/2.0 ", 0) == 0) responses.push_back(raw.substr(0, raw.find("\r\n")));
	}
	ASSERT_EQ(responses.size(), 1u) << "exactly one answer to the refused REGISTER";
	EXPECT_EQ(responses[0], "SIP/2.0 503 Service Unavailable");

	handler.forceNextTickForTest();   // getActiveClients() reads the snapshot tick() publishes
	handler.tick();
	bool lateBound = false;
	size_t bound = 0;
	for (const auto& [number, address] : handler.getActiveClients())
	{
		(void)address;
		if (number == ext(late)) lateBound = true;
		if (number.rfind("51", 0) == 0) ++bound;
	}
	EXPECT_FALSE(lateBound) << "a 503'd REGISTER must not create a binding";
	EXPECT_EQ(bound, static_cast<size_t>(Registrar::kAdoptBurst)) << "positive control: the others did bind";
}

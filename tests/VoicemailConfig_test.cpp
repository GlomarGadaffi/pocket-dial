// VoicemailConfig_test.cpp — Issue #246 (voicemail Stage 3 of #194).
//
// Covers the extension-config-model slice: RequestsHandler::setVoicemail()/
// getVoicemailExtensions() must behave exactly like setDnd()/getDndExtensions()
// (same immediate-snapshot-refresh contract, Issue #77) except that it is
// meant to survive a reboot rather than being session-only — the NVS
// persistence itself is gated behind ESP_PLATFORM and untestable on host (same
// as every other PbxFeatureConfig table), so these tests exercise the
// in-memory/snapshot behavior that host tests CAN see.

#include <algorithm>

#include <gtest/gtest.h>
#include "RequestsHandler.hpp"

namespace
{
	bool contains(const std::vector<std::string>& v, const std::string& s)
	{
		for (const auto& x : v) if (x == s) return true;
		return false;
	}
}

TEST(VoicemailConfig, DisabledByDefault)
{
	RequestsHandler handler("192.168.6.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});

	EXPECT_FALSE(contains(handler.getVoicemailExtensions(), "301"));
}

TEST(VoicemailConfig, EnableReflectsImmediatelyInSnapshot)
{
	RequestsHandler handler("192.168.6.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});

	handler.setVoicemail("301", true);

	EXPECT_TRUE(contains(handler.getVoicemailExtensions(), "301"))
		<< "must be visible via the same snapshot the HTTP dashboard reads, "
		   "not just the internal map (Issue #77's immediate-refresh contract)";
}

TEST(VoicemailConfig, DisableClearsIt)
{
	RequestsHandler handler("192.168.6.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});

	handler.setVoicemail("302", true);
	ASSERT_TRUE(contains(handler.getVoicemailExtensions(), "302"));

	handler.setVoicemail("302", false);
	EXPECT_FALSE(contains(handler.getVoicemailExtensions(), "302"));
}

TEST(VoicemailConfig, DisablingAnExtensionNeverEnabledIsANoOp)
{
	RequestsHandler handler("192.168.6.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});

	handler.setVoicemail("303", false);
	EXPECT_FALSE(contains(handler.getVoicemailExtensions(), "303"));
}

TEST(VoicemailConfig, MultipleExtensionsTrackedIndependently)
{
	RequestsHandler handler("192.168.6.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});

	handler.setVoicemail("304", true);
	handler.setVoicemail("305", true);
	handler.setVoicemail("305", false);

	EXPECT_TRUE(contains(handler.getVoicemailExtensions(), "304"));
	EXPECT_FALSE(contains(handler.getVoicemailExtensions(), "305"));
}

TEST(VoicemailConfig, ReEnablingAnAlreadyEnabledExtensionIsIdempotent)
{
	RequestsHandler handler("192.168.6.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});

	handler.setVoicemail("306", true);
	handler.setVoicemail("306", true);

	auto snap = handler.getVoicemailExtensions();
	EXPECT_EQ(1, std::count(snap.begin(), snap.end(), "306"));
}

// DashboardResetText_test.cpp -- dashboard review #6. The Factory Reset confirm
// said it only erased saved Wi-Fi; the reset (HttpServer::sendApiFactoryReset)
// also wipes credentials, secrets, carrier slots, forwards, E911, DIDs, call
// history and voicemail. The page's JS is not host-executable; this pins the text.

#include <gtest/gtest.h>

#include <string>

#include "index_html.h"

TEST(DashboardResetText, TheFactoryResetConfirmListsEverythingItErases)
{
	std::string p;
	for (const auto& part : CGA_INDEX_HTML_PARTS) p.append(part.data, part.size);

	const size_t fn = p.find("function factoryReset(){");
	ASSERT_NE(fn, std::string::npos);
	const std::string body = p.substr(fn, p.find("\n}\n", fn) - fn);

	EXPECT_EQ(body.find("erases saved Wi-Fi config and reboots"), std::string::npos)
		<< "the old Wi-Fi-only wording is back";
	for (const char* item : {"admin login", "DTMF PIN", "carrier trunk", "Telephony API",
		"SIP password", "call forwards", "E911", "DID mappings", "call history", "voicemail",
		"saved Wi-Fi", "cannot be undone"})
	{
		EXPECT_NE(body.find(item), std::string::npos) << "confirm does not mention: " << item;
	}
}

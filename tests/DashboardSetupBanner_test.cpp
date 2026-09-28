// DashboardSetupBanner_test.cpp -- #644 (dashboard review #8). While needsSetup
// is true, SIP is held off (esp_main.cpp's provisioning gate), but the page said
// nothing outside the admin modal, and fetchAdminStatus() dropped every error in
// an empty catch. The page's JS is not host-executable; this pins the text.

#include <gtest/gtest.h>

#include <string>

#include "index_html.h"

TEST(DashboardSetupBanner, NeedsSetupShowsABannerAndStatusErrorsAreShown)
{
	std::string p;
	for (const auto& part : CGA_INDEX_HTML_PARTS) p.append(part.data, part.size);

	EXPECT_NE(p.find("<div class=\"e911\" id=\"setup-banner\" role=\"alert\""), std::string::npos)
		<< "no setup banner element";

	const size_t fn = p.find("function fetchAdminStatus(){");
	ASSERT_NE(fn, std::string::npos);
	const std::string body = p.substr(fn, p.find("\n}\n", fn) - fn);

	// positive control: this is the function that reads needsSetup
	ASSERT_NE(body.find("adminState.needsSetup=!!d.needsSetup"), std::string::npos);
	EXPECT_EQ(body.find(".catch(function(){})"), std::string::npos)
		<< "fetchAdminStatus swallows its errors again";
	EXPECT_NE(body.find("setupBanner(adminState.needsSetup?"), std::string::npos)
		<< "needsSetup does not drive the banner";
	EXPECT_NE(body.find("SIP stays off until a real admin login is set"), std::string::npos);
	EXPECT_NE(body.find("Could not read admin status: "), std::string::npos);
}

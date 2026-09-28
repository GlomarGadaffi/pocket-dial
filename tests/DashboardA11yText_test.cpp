// DashboardA11yText_test.cpp -- #642 (dashboard review #10). Wi-Fi scan rows were
// click-only <div>s, and .msg lines were not live regions. The page's JS is not
// host-executable; this pins the text.

#include <gtest/gtest.h>

#include <string>

#include "index_html.h"

static std::string page()
{
	std::string p;
	for (const auto& part : CGA_INDEX_HTML_PARTS) p.append(part.data, part.size);
	return p;
}

static std::string fnBody(const std::string& p, const char* sig)
{
	const size_t fn = p.find(sig);
	if (fn == std::string::npos) return "";
	return p.substr(fn, p.find("\n}\n", fn) - fn);
}

TEST(DashboardA11yText, WifiScanRowsAreButtons)
{
	const std::string body = fnBody(page(), "function renderWifi(nets){");
	ASSERT_FALSE(body.empty());
	// positive control: the row is still built here
	ASSERT_NE(body.find("row.className=\"wifi-net\""), std::string::npos);
	EXPECT_EQ(body.find("createElement(\"div\");row.className=\"wifi-net\""), std::string::npos)
		<< "Wi-Fi rows are click-only divs again";
	EXPECT_NE(body.find("createElement(\"button\");row.type=\"button\""), std::string::npos);
}

TEST(DashboardA11yText, MessagesAreLiveRegions)
{
	const std::string p = page();
	const std::string body = fnBody(p, "function setMsg(id,txt,cls){");
	ASSERT_FALSE(body.empty());
	EXPECT_NE(body.find("setAttribute(\"role\",cls===\"err\"?\"alert\":\"status\")"), std::string::npos)
		<< "setMsg does not mark errors role=alert / others role=status";
	EXPECT_NE(p.find("querySelectorAll(\".msg[id]\").forEach(function(e){e.setAttribute(\"role\",\"status\");})"),
		std::string::npos) << ".msg regions are not role=status before their first message";
}

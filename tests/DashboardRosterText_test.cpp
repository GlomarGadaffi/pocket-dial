// DashboardRosterText_test.cpp -- dashboard review #5. Logged out, /api/status
// hides the roster (rosterVisible false) but still sends clientCount, and
// /api/cdr answers 401. The page used to say "0/32" and "No calls recorded yet",
// which is false. The page's JS is not host-executable; this pins the wiring.

#include <gtest/gtest.h>

#include <string>

#include "index_html.h"

namespace
{
	std::string page()
	{
		std::string s;
		for (const auto& part : CGA_INDEX_HTML_PARTS) s.append(part.data, part.size);
		return s;
	}

	std::string functionBody(const std::string& p, const char* header)
	{
		const size_t at = p.find(header);
		if (at == std::string::npos) return {};
		return p.substr(at, p.find("\n}\n", at) - at);
	}
}

TEST(DashboardRosterText, LoggedOutTheBoardCountsPhonesAndTheCallLogAsksForLogin)
{
	const std::string p = page();

	const std::string board = functionBody(p, "function renderBoard(d){");
	ASSERT_FALSE(board.empty());
	EXPECT_NE(board.find("d.rosterVisible===false"), std::string::npos) << board;
	EXPECT_NE(board.find("phones registered. Log in to see them."), std::string::npos);

	const std::string rail = functionBody(p, "function updateRail(d){");
	ASSERT_FALSE(rail.empty());
	EXPECT_NE(rail.find("d.clientCount"), std::string::npos)
		<< "the jacks stat must use the public count when the roster is hidden";

	const std::string cdr = functionBody(p, "function fetchCdr(){");
	ASSERT_FALSE(cdr.empty());
	EXPECT_NE(cdr.find("r.ok"), std::string::npos) << cdr;
	EXPECT_NE(cdr.find("Log in to view the call log"), std::string::npos) << cdr;
}

// DashboardLearnText_test.cpp -- #643 (dashboard review #9). The Learn-mode hint
// said Learn locks an extension to the first phone. Registrar::admitLearn only
// refuses an extension that is Secured to a different MAC; a Learned device does
// not lock anything. The page's JS is not host-executable; this pins the text.

#include <gtest/gtest.h>

#include <string>

#include "index_html.h"

TEST(DashboardLearnText, LearnHintSaysOnlyASecuredDeviceLocksTheExtension)
{
	std::string p;
	for (const auto& part : CGA_INDEX_HTML_PARTS) p.append(part.data, part.size);

	const size_t at = p.find("<strong>Learn</strong> adopts an unknown phone on first contact");
	ASSERT_NE(at, std::string::npos);
	const std::string hint = p.substr(at, p.find("</div>", at) - at);

	EXPECT_EQ(hint.find("so nobody else can take it over"), std::string::npos)
		<< "the old 'Learn locks the extension' wording is back";
	EXPECT_NE(hint.find("only locked to that device once an admin secures it"), std::string::npos);
}

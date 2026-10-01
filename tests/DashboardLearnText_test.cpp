// DashboardLearnText_test.cpp -- #643 (dashboard review #9), updated for #440.
// The Learn-mode hint once said Learn locks an extension to the first phone, so
// nobody else can take it over. Since #440 Registrar::admitLearn locks an adopted
// extension to its MAC on that MAC's second REGISTER, but never for a phone it
// cannot resolve (another subnet) or a MAC that registered two extensions (phones
// behind one NAT router). The page's JS is not host-executable; this pins the text.

#include <gtest/gtest.h>

#include <string>

#include "index_html.h"

TEST(DashboardLearnText, LearnHintSaysTheLockComesWithTheNextRegistration)
{
	std::string p;
	for (const auto& part : CGA_INDEX_HTML_PARTS) p.append(part.data, part.size);

	const size_t at = p.find("<strong>Learn</strong> adopts an unknown phone on first contact");
	ASSERT_NE(at, std::string::npos);
	const std::string hint = p.substr(at, p.find("</div>", at) - at);

	EXPECT_EQ(hint.find("so nobody else can take it over"), std::string::npos)
		<< "the overclaim is back: Learn never locks a phone on another subnet or behind a shared NAT MAC";
	EXPECT_EQ(hint.find("only locked to that device once an admin secures it"), std::string::npos)
		<< "the pre-#440 wording is back: Learn now locks without an admin";
	EXPECT_NE(hint.find("locks the extension to that device on its next registration"), std::string::npos) << hint;
	EXPECT_NE(hint.find("another subnet"), std::string::npos) << hint;
}

// DashboardLearnText_test.cpp -- #643 (dashboard review #9), updated for #440.
// The Learn-mode hint once said Learn locks an extension to the first phone, so
// nobody else can take it over. Since #440 Registrar::admitLearn locks an adopted
// extension to its MAC on a later REGISTER from that MAC (at least 30 s after its
// first, #515), only if it was the extension's first claim (#487 review), never for
// a phone it cannot resolve (another subnet) or a MAC that registered two
// extensions (phones behind one NAT router). The page's JS is not
// host-executable; this pins the text.

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
	// #820 item 6: the lock goes to the extension's first claim, not to whichever
	// device registers it twice.
	EXPECT_NE(hint.find("if no other phone claimed it first"), std::string::npos) << hint;
}

// #882: the docs tell the operator to forget a shared or stale row, so the roster
// must show which row is locked, which is shared and which is plain TOFU. The
// state cell reads GET /api/registrar's `locked` and `shared`; a Secured row says
// "secured" and nothing more, since its state already means MAC-locked + digest.
TEST(DashboardLearnText, RosterShowsWhichRowIsLockedSharedOrPlainTofu)
{
	std::string p;
	for (const auto& part : CGA_INDEX_HTML_PARTS) p.append(part.data, part.size);

	const size_t at = p.find("function renderRegistrar(");
	ASSERT_NE(at, std::string::npos);
	const std::string render = p.substr(at, p.find("\n}\n", at) - at);

	EXPECT_NE(render.find("x.locked"), std::string::npos) << "the roster never reads the row's locked flag";
	EXPECT_NE(render.find("x.shared"), std::string::npos) << "the roster never reads the row's shared flag";
	for (const char* word : {"locked", "shared", "unlocked"})
		EXPECT_NE(render.find(std::string("\\u00b7 ") + word), std::string::npos)
			<< "the state cell never says '" << word << "'";

	const size_t note = p.find("id=\"reg-roster-note\"");
	ASSERT_NE(note, std::string::npos);
	const std::string hint = p.substr(note, p.find("</div>", note) - note);
	EXPECT_NE(hint.find("<strong>locked</strong>"), std::string::npos) << hint;
	EXPECT_NE(hint.find("<strong>shared</strong>"), std::string::npos) << hint;
	EXPECT_NE(hint.find("a NAT router, or a phone moved while unlocked"), std::string::npos) << hint;
}

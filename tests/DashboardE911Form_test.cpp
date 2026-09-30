// DashboardE911Form_test.cpp -- dashboard review #4 (#641). E911 notification
// could only be set by a raw PUT /api/e911-config; the banner named the API and
// no form called it. The page's JS is not host-executable; this pins the text.

#include <gtest/gtest.h>

#include <string>

#include "index_html.h"

TEST(DashboardE911Form, PbxModalHasAFormThatLoadsAndSavesTheE911Config)
{
	std::string p;
	for (const auto& part : CGA_INDEX_HTML_PARTS) p.append(part.data, part.size);

	for (const char* id : {"id=\"e911-exts\"", "id=\"e911-callback\"", "id=\"e911-location\""})
	{
		EXPECT_NE(p.find(id), std::string::npos) << "form field missing: " << id;
	}
	EXPECT_NE(p.find("fetch(\"/api/e911-config\""), std::string::npos) << "no GET of the current values";
	EXPECT_NE(p.find("put(\"/api/e911-config\""), std::string::npos) << "save does not go through put() (CSRF)";
	EXPECT_EQ(p.find("PUT /api/e911-config"), std::string::npos) << "banner still tells users to call the raw API";
}

TEST(DashboardE911Form, AFailedLoadDisablesSaveSoBlanksCannotOverwriteTheConfig)
{
	// CaveJay on #646: a silently failed GET left the fields empty, and Save
	// would then PUT blanks over the notify list. Save starts disabled and is
	// enabled only by a successful load.
	std::string p;
	for (const auto& part : CGA_INDEX_HTML_PARTS) p.append(part.data, part.size);

	EXPECT_NE(p.find("id=\"e911-save\" disabled"), std::string::npos) << "Save must start disabled";
	const size_t fn = p.find("function fetchE911(){");
	ASSERT_NE(fn, std::string::npos);
	const std::string body = p.substr(fn, p.find("\n}\n", fn) - fn);
	EXPECT_NE(body.find("$(\"e911-save\").disabled=false"), std::string::npos) << "a good load must enable Save:\n" << body;
	const size_t c = body.find(".catch(");
	ASSERT_NE(c, std::string::npos) << body;
	const std::string fail = body.substr(c);
	EXPECT_NE(fail.find("$(\"e911-save\").disabled=true"), std::string::npos) << "a failed load must disable Save:\n" << fail;
	EXPECT_NE(fail.find("setMsg(\"e911-msg\""), std::string::npos) << "a failed load must say so:\n" << fail;
}

// #792: with the 3CX anchor placing real calls (emergencyRoute "anchor"), 3CX
// carries the 911 call, so "nobody on site is notified" misleads. The banner
// text is its own element and applyE911() rewords it for that route only.
TEST(DashboardE911Form, TheBannerNamesTheAnchorAsTheCarrierWhenTheRouteIsAnchor)
{
	std::string p;
	for (const auto& part : CGA_INDEX_HTML_PARTS) p.append(part.data, part.size);

	// Positive control: the default sentence is still there for every other route.
	EXPECT_NE(p.find("A 911 call still routes out, but nobody on site is"), std::string::npos)
		<< "the default banner text must remain";
	EXPECT_NE(p.find("<span id=\"e911-banner-text\">"), std::string::npos) << "the banner text needs its own element";

	const size_t fn = p.find("function applyE911(d){");
	ASSERT_NE(fn, std::string::npos);
	const std::string body = p.substr(fn, p.find("
}
", fn) - fn);
	EXPECT_NE(body.find("$(\"e911-banner-text\")"), std::string::npos) << body;
	EXPECT_NE(body.find("d.emergencyRoute===\"anchor\""), std::string::npos)
		<< "the reword must key on the anchor route:
" << body;
	EXPECT_NE(body.find("3CX anchor"), std::string::npos) << body;
}

// #793 review: the anchor wording must not outlive the anchor route. The banner
// is one element on a page that stays open across a route change (anchor ->
// trunk fallback), so applyE911() has to put the original sentence back.
TEST(DashboardE911Form, TheBannerRestoresItsDefaultTextWhenTheRouteIsNotAnchor)
{
	std::string p;
	for (const auto& part : CGA_INDEX_HTML_PARTS) p.append(part.data, part.size);

	const size_t fn = p.find("function applyE911(d){");
	ASSERT_NE(fn, std::string::npos);
	const size_t end = p.find("/* #167", fn);
	ASSERT_NE(end, std::string::npos);
	const std::string body = p.substr(fn, end - fn);
	EXPECT_NE(body.find("t._def===undefined"), std::string::npos)
		<< "the default sentence must be remembered before it is overwritten:\n" << body;
	EXPECT_NE(body.find(":t._def"), std::string::npos)
		<< "every route but anchor must put the remembered sentence back:\n" << body;
}

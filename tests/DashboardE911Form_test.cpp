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

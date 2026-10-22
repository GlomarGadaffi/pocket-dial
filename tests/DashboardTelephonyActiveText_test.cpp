// DashboardTelephonyActiveText_test.cpp -- #1079. A slot can be the active (selected) one while
// disabled: "active" is the stored selection, "enabled" is what lets the boot path use it, and a
// disabled slot boots to loopback (#1060 disables a stored emergency route DN on load, the active
// byte stays). The page called such a slot "Active". The page's JS is not host-executable; this pins the text.

#include <gtest/gtest.h>

#include <string>

#include "index_html.h"

TEST(DashboardTelephonyActiveText, ADisabledActiveSlotIsNotCalledActive)
{
	std::string p;
	for (const auto& part : CGA_INDEX_HTML_PARTS) p.append(part.data, part.size);

	const size_t fn = p.find("function tnChipEl(s){");
	ASSERT_NE(fn, std::string::npos);
	const std::string chip = p.substr(fn, p.find("\n}\n", fn) - fn);
	EXPECT_NE(chip.find("Selected, disabled"), std::string::npos) << "no chip for a selected but disabled slot";

	const size_t rn = p.find("function tnRenderSlots(){");
	ASSERT_NE(rn, std::string::npos);
	const std::string render = p.substr(rn, p.find("\n}\n", rn) - rn);
	EXPECT_NE(render.find("disabled, loopback runs"), std::string::npos) << "summary does not say a disabled slot is not running";
}

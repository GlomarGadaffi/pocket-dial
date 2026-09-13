// JsonEscape_test.cpp — coverage for the header-only RFC 8259 string-content
// escaper (src/Helpers/JsonEscape.hpp), used at the Telephony anchor boundary to escape
// a caller-supplied makecall destination before it is concatenated into the JSON
// control-plane POST body (issue #56). The function returns ESCAPED CONTENT (no
// surrounding quotes). Pure/host-compilable, no deps.

#include <gtest/gtest.h>
#include <string>
#include "JsonEscape.hpp"

// ---- Ordinary text passes through unchanged ----
TEST(JsonEscapeTest, PlainTextPassthrough)
{
    EXPECT_EQ(jsonEscapeString(""), "");
    EXPECT_EQ(jsonEscapeString("1000"), "1000");
    EXPECT_EQ(jsonEscapeString("+15551234567"), "+15551234567");
    EXPECT_EQ(jsonEscapeString("sip:bob@example.com"), "sip:bob@example.com");
}

// ---- The two structurally dangerous characters are escaped ----
TEST(JsonEscapeTest, QuoteAndBackslashEscaped)
{
    EXPECT_EQ(jsonEscapeString("\""), "\\\"");
    EXPECT_EQ(jsonEscapeString("\\"), "\\\\");
    // A double quote is the JSON-injection primitive: it MUST NOT survive raw.
    EXPECT_EQ(jsonEscapeString("a\"b"), "a\\\"b");
}

// ---- The five short-form control escapes ----
TEST(JsonEscapeTest, ShortFormControlEscapes)
{
    EXPECT_EQ(jsonEscapeString("\b"), "\\b");
    EXPECT_EQ(jsonEscapeString("\f"), "\\f");
    EXPECT_EQ(jsonEscapeString("\n"), "\\n");
    EXPECT_EQ(jsonEscapeString("\r"), "\\r");
    EXPECT_EQ(jsonEscapeString("\t"), "\\t");
}

// ---- Other C0 control bytes become \u00XX (lowercase hex) ----
TEST(JsonEscapeTest, OtherControlBytesBecomeUnicodeEscape)
{
    EXPECT_EQ(jsonEscapeString(std::string("\x00", 1)), "\\u0000");
    EXPECT_EQ(jsonEscapeString("\x01"), "\\u0001");
    EXPECT_EQ(jsonEscapeString("\x1f"), "\\u001f");
    // 0x07 (BEL) has no short form -> .
    EXPECT_EQ(jsonEscapeString("\x07"), "\\u0007");
}

// ---- Bytes >= 0x20 (incl. raw UTF-8) pass through (RFC 8259 permits them) ----
TEST(JsonEscapeTest, HighBytesPassThrough)
{
    EXPECT_EQ(jsonEscapeString(" "), " ");           // 0x20 boundary
    EXPECT_EQ(jsonEscapeString("é"), "é");           // UTF-8 multibyte, unchanged
    EXPECT_EQ(jsonEscapeString(std::string("\xff")), std::string("\xff"));
}

// ---- The exact JSON-injection payload from issue #56 is neutralized ----
TEST(JsonEscapeTest, InjectionPayloadNeutralized)
{
    // An attacker-controlled destination trying to break out of the value and
    // inject a sibling key + an end-of-object.
    const std::string evil = "1\",\"injected\":\"x";
    const std::string esc  = jsonEscapeString(evil);
    // The body the anchor builds: {"destination":"<esc>"}
    const std::string body = "{\"destination\":\"" + esc + "\"}";
    // The injected key must NOT appear as a bare JSON key: every quote in the
    // payload is backslash-escaped, so the only UNescaped quotes are the two
    // structural delimiters the anchor itself wrote.
    EXPECT_EQ(body, "{\"destination\":\"1\\\",\\\"injected\\\":\\\"x\"}");

    // Stronger structural check: every double-quote in the escaped output MUST be
    // immediately preceded by a backslash (i.e. there is no UNescaped quote that
    // could close the JSON value). This is the property that defeats the injection.
    for (size_t i = 0; i < esc.size(); ++i)
    {
        if (esc[i] == '"')
        {
            ASSERT_GT(i, 0u) << "escaped output must not begin with a bare quote";
            EXPECT_EQ(esc[i - 1], '\\')
                << "every quote in escaped content must be backslash-escaped (pos " << i << ")";
        }
    }
}

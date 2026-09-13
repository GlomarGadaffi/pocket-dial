// UrlEncode_test.cpp — coverage for the header-only RFC 3986 percent-encoder
// (src/Helpers/UrlEncode.hpp). The unreserved set passes through unchanged; every
// other byte becomes %XX with UPPERCASE hex, bytes treated as unsigned so high
// bytes (e.g. 0xFF -> "%FF") encode correctly. Pure/host-compilable, no deps.

#include <gtest/gtest.h>
#include <string>
#include "UrlEncode.hpp"

// ---- Unreserved characters (A-Z a-z 0-9 - _ . ~) pass through verbatim ----
TEST(UrlEncodeTest, UnreservedPassthrough)
{
    EXPECT_EQ(urlEncode("AZaz09-_.~"), "AZaz09-_.~");
    EXPECT_EQ(urlEncode(""), "");
    // Sanity over the full alphanumeric span plus each unreserved punctuation mark.
    EXPECT_EQ(urlEncode("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
              "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    EXPECT_EQ(urlEncode("abcdefghijklmnopqrstuvwxyz"),
              "abcdefghijklmnopqrstuvwxyz");
    EXPECT_EQ(urlEncode("0123456789"), "0123456789");
}

// ---- Individual reserved/special characters encode to the correct %XX ----
TEST(UrlEncodeTest, ReservedCharsEncodeToUppercaseHex)
{
    EXPECT_EQ(urlEncode(" "), "%20");
    EXPECT_EQ(urlEncode("/"), "%2F");
    EXPECT_EQ(urlEncode(":"), "%3A");
    EXPECT_EQ(urlEncode("?"), "%3F");
    EXPECT_EQ(urlEncode("#"), "%23");
    EXPECT_EQ(urlEncode("&"), "%26");
    EXPECT_EQ(urlEncode("="), "%3D");
    EXPECT_EQ(urlEncode("@"), "%40");
    EXPECT_EQ(urlEncode("+"), "%2B");
    EXPECT_EQ(urlEncode("%"), "%25");

    // Hex digits A-F must be uppercase, never lowercase ("%2F" not "%2f").
    EXPECT_NE(urlEncode("/"), "%2f");
}

// ---- Realistic mixed string: unreserved kept, reserved encoded inline ----
TEST(UrlEncodeTest, RealisticMixedString)
{
    EXPECT_EQ(urlEncode("abc 123/x:y"), "abc%20123%2Fx%3Ay");
}

// ---- Bytes are unsigned: a high non-ASCII byte encodes as uppercase %XX ----
TEST(UrlEncodeTest, NonAsciiHighByteEncodesUnsigned)
{
    EXPECT_EQ(urlEncode(std::string("\xff")), "%FF");
    EXPECT_EQ(urlEncode(std::string("\x80")), "%80");
    // Embedded NUL byte must encode too (string carries its own length).
    EXPECT_EQ(urlEncode(std::string("\x00", 1)), "%00");
}

// ======================= urlDecode (audit #73) ============================

// ---- Basic decode: %XX -> byte, '+' -> space, plain text verbatim ----
TEST(UrlDecodeTest, BasicEscapesAndPlus)
{
    EXPECT_EQ(urlDecode("name%3Dvalue"), "name=value");
    EXPECT_EQ(urlDecode("a+b+c"), "a b c");
    EXPECT_EQ(urlDecode("hello%20world"), "hello world");
    EXPECT_EQ(urlDecode("plain"), "plain");
    EXPECT_EQ(urlDecode(""), "");
    EXPECT_EQ(urlDecode("100%25"), "100%");          // literal percent
    // Round-trips against urlEncode for a reserved-heavy string.
    EXPECT_EQ(urlDecode(urlEncode("abc 123/x:y")), "abc 123/x:y");
}

// ---- A FULL trailing "%XX" must decode (the #73 regression guard) ----
// This is the case the audit feared was dropped. It is NOT — pos+2 < length()
// already covers a complete escape that ends the string. Lock it in.
TEST(UrlDecodeTest, TrailingEscape)
{
    EXPECT_EQ(urlDecode("%41"), "A");                // whole string is one escape
    EXPECT_EQ(urlDecode("x%41"), "xA");
    EXPECT_EQ(urlDecode("road%2F"), "road/");        // trailing '/'
    EXPECT_EQ(urlDecode("a=b%26c=d%3D"), "a=b&c=d=");// ends on a full escape
    EXPECT_EQ(urlDecode("ab%41"), "abA");
}

// ---- A TRUNCATED or non-hex escape is passed through literally, NOT swallowed ----
// Guards against the proposed "<=" relaxation, which would decode "%2" as 0x02.
TEST(UrlDecodeTest, MalformedEscapePassthrough)
{
    EXPECT_EQ(urlDecode("%2"), "%2");                // one hex digit at EOS
    EXPECT_EQ(urlDecode("end%2"), "end%2");
    EXPECT_EQ(urlDecode("%"), "%");                  // bare trailing percent
    EXPECT_EQ(urlDecode("a%"), "a%");
    EXPECT_EQ(urlDecode("%zz"), "%zz");              // non-hex digits
    EXPECT_EQ(urlDecode("%2z"), "%2z");              // second digit non-hex
}

// ---- Lowercase hex digits decode (servers may emit either case) ----
TEST(UrlDecodeTest, LowercaseHex)
{
    EXPECT_EQ(urlDecode("%2f"), "/");
    EXPECT_EQ(urlDecode("%ff"), std::string("\xff"));
}

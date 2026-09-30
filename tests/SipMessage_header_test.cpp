#include <gtest/gtest.h>
#include "SipMessage.hpp"
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

TEST(SipMessage, HeaderMatchingRobustness) {
    sockaddr_in dummy = {}; 
    std::string raw =
        "OPTIONS sip:server SIP/2.0\r\n"
        " v: SIP/2.0/UDP 1.2.3.4:5060;branch=z9h\r\n"
        "F: <sip:100@host>\r\n"
        "T: <sip:server@host>\r\n"
        "i: abc\r\n"
        "c: <sip:...>\r\n"
        "l: 0\r\n\r\n";
    SipMessage msg(raw, dummy);
    ASSERT_FALSE(std::string(msg.getVia()).empty());
    ASSERT_FALSE(std::string(msg.getFrom()).empty());
}

// #739: the Session-Expires / Min-SE parsers.
namespace
{
    SipMessage inviteWith(const std::string& extraHeaders) {
        sockaddr_in dummy = {};
        std::string raw =
            "INVITE sip:200@server SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK739\r\n"
            "From: <sip:100@server>;tag=a\r\n"
            "To: <sip:200@server>\r\n"
            "Call-ID: c739\r\n"
            "CSeq: 1 INVITE\r\n" +
            extraHeaders +
            "Content-Length: 0\r\n\r\n";
        return SipMessage(raw, dummy);
    }
}

TEST(SipMessageSessionTimer, RefresherNameAndValueAreCaseInsensitive) {
    // Positive control: the plain lowercase form.
    EXPECT_EQ(inviteWith("Session-Expires: 1800;refresher=uac\r\n").getSessionExpiresRefresher(), "uac");
    EXPECT_EQ(inviteWith("Session-Expires: 1800;refresher=uas\r\n").getSessionExpiresRefresher(), "uas");
    // The same header in another case names the same refresher.
    EXPECT_EQ(inviteWith("Session-Expires: 1800;refresher=UAS\r\n").getSessionExpiresRefresher(), "uas");
    EXPECT_EQ(inviteWith("Session-Expires: 1800;Refresher=Uac\r\n").getSessionExpiresRefresher(), "uac");
    EXPECT_EQ(inviteWith("x: 1800;REFRESHER=UAS\r\n").getSessionExpiresRefresher(), "uas");
    // Absent or unknown never reads as uac/uas.
    EXPECT_TRUE(inviteWith("Session-Expires: 1800\r\n").getSessionExpiresRefresher().empty());
    EXPECT_EQ(inviteWith("Session-Expires: 1800;refresher=bogus\r\n").getSessionExpiresRefresher(), "bogus");
}

TEST(SipMessageSessionTimer, SessionExpiresAndMinSESaturateInsteadOfWrapping) {
    // Positive control: ordinary values and the exact maximum parse unchanged.
    EXPECT_EQ(inviteWith("Session-Expires: 1800\r\n").getSessionExpiresSecs(), 1800u);
    EXPECT_EQ(inviteWith("Session-Expires: 4294967295\r\n").getSessionExpiresSecs(), 4294967295u);
    EXPECT_EQ(inviteWith("Min-SE: 4294967294\r\n").getMinSESecs(), 4294967294u);
    // One past the maximum wrapped to 0 (read as "no timer"); +30 wrapped to 30.
    EXPECT_EQ(inviteWith("Session-Expires: 4294967296\r\n").getSessionExpiresSecs(), 4294967295u);
    EXPECT_EQ(inviteWith("Session-Expires: 4294967326\r\n").getSessionExpiresSecs(), 4294967295u);
    EXPECT_EQ(inviteWith("Session-Expires: 99999999999999999999;refresher=uac\r\n").getSessionExpiresSecs(), 4294967295u);
    EXPECT_EQ(inviteWith("Min-SE: 4294967296\r\n").getMinSESecs(), 4294967295u);
    EXPECT_EQ(inviteWith("Min-SE: 99999999999999999999\r\n").getMinSESecs(), 4294967295u);
}

// RegisterBinding_test.cpp — issue #755: the REGISTER 200 lists the phone's binding.
//
// onRegister() answered every REGISTER with the PBX's own URI in Contact
// (`<sip:ext@<pbx>:5060;transport=UDP>;expires=N`). RFC 3261 §10.3 step 8: the
// 200 MUST enumerate the current bindings, and a UA finds its own Contact in
// that list to learn the lease it was granted (§10.2.4). The PBX's URI is not a
// binding. The phone's own Contact, with the granted expires, is.

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "ConferenceRoom.hpp"
#include "RequestsHandler.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	constexpr const char* kServerIp = "192.168.52.1";

	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(port);
		return a;
	}

	using Outbox = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	// `contactAndExpires` is the Contact line plus any standalone Expires line,
	// each CRLF-terminated.
	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip,
		const std::string& callId, const std::string& contactAndExpires)
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKb" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=bt" + callId + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 REGISTER\r\n" +
			contactAndExpires +
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	// The one 200 OK the REGISTER drew (register-beep requests are ignored).
	std::shared_ptr<SipMessage> theOk(const Outbox& sent)
	{
		std::shared_ptr<SipMessage> ok;
		for (const auto& [addr, msg] : sent)
		{
			(void)addr;
			if (msg && msg->toString().rfind("SIP/2.0 200 OK", 0) == 0)
			{
				EXPECT_FALSE(ok) << "a REGISTER draws exactly one 200";
				ok = msg;
			}
		}
		return ok;
	}
}

TEST(RegisterBinding, TheOkListsThePhonesOwnContactWithTheGrantedLeaseNotThePbxUri)
{
	Outbox sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			sent.emplace_back(a, std::move(m));
		});

	handler.handle(makeRegister("451", "192.168.52.51", "bind-451",
		"Contact: <sip:451@192.168.52.51:5060>\r\nExpires: 3600\r\n"));

	auto ok = theOk(sent);
	ASSERT_NE(ok, nullptr);
	const std::string contact(ok->getContact());
	EXPECT_NE(contact.find("<sip:451@192.168.52.51:5060>"), std::string::npos) << contact;
	EXPECT_NE(contact.find(";expires=3600"), std::string::npos) << contact;
	EXPECT_EQ(contact.find(kServerIp), std::string::npos)
		<< "the PBX's own URI is not a binding: " << contact;
}

TEST(RegisterBinding, ABareAddrSpecContactIsEchoedAsTheBindingToo)
{
	Outbox sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			sent.emplace_back(a, std::move(m));
		});

	handler.handle(makeRegister("452", "192.168.52.52", "bind-452",
		"Contact: sip:452@192.168.52.52:5060;expires=600\r\n"));

	auto ok = theOk(sent);
	ASSERT_NE(ok, nullptr);
	const std::string contact(ok->getContact());
	EXPECT_NE(contact.find("<sip:452@192.168.52.52:5060>;expires=600"), std::string::npos) << contact;
	EXPECT_EQ(contact.find(kServerIp), std::string::npos) << contact;
}

TEST(RegisterBinding, AContactStarDeregisterIsAnswered200WithNoContactAtAll)
{
	Outbox sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			sent.emplace_back(a, std::move(m));
		});

	handler.handle(makeRegister("453", "192.168.52.53", "bind-453",
		"Contact: *\r\nExpires: 0\r\n"));

	auto ok = theOk(sent);
	ASSERT_NE(ok, nullptr);
	EXPECT_TRUE(ok->getContact().empty())
		<< "\"*\" is not a binding and the PBX's URI never is: " << ok->getContact();
}

TEST(RegisterBinding, TheBindingIsTheContactUriWhateverTheDisplayNameHolds)
{
	// #835 (the #824 class): the binding was cut at the first '<' on the line,
	// even one in the display name, so the 200 listed "<1>" or "<A>" and the
	// phone could not find its own Contact (RFC 3261 s10.2.4). It is the URI
	// the registrar stores (contactUriView).
	for (const char* name : {"\"Lobby <1>\" ", "\"Lobby 55\" <A> TV\" ", "\"Lobby 55\" TV\" ", "\"Desk 454\" "})
	{
		SCOPED_TRACE(name);
		Outbox sent;
		RequestsHandler handler(kServerIp, 5060,
			[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
				sent.emplace_back(a, std::move(m));
			});

		handler.handle(makeRegister("454", "192.168.52.54", "bind-454",
			std::string("Contact: ") + name + "<sip:454@192.168.52.54:5060;line=k3>;reg-id=1;"
			"+sip.instance=\"<urn:uuid:0>\"\r\nExpires: 3600\r\n"));

		auto ok = theOk(sent);
		ASSERT_NE(ok, nullptr);
		EXPECT_EQ(std::string(ok->getContact()), "Contact: <sip:454@192.168.52.54:5060;line=k3>;expires=3600");
	}
}

TEST(RegisterBinding, AnUppercaseSchemeBareContactIsEchoedAsTheBinding)
{
	// #835 nit, the same here: RFC 3261 s19.1.4, the scheme is case-insensitive,
	// and the registrar stores a sips: Contact as it does a sip: one.
	for (const char* uri : {"SIP:455@192.168.52.55:5060", "sips:455@192.168.52.55:5060"})
	{
		SCOPED_TRACE(uri);
		Outbox sent;
		RequestsHandler handler(kServerIp, 5060,
			[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
				sent.emplace_back(a, std::move(m));
			});

		handler.handle(makeRegister("455", "192.168.52.55", "bind-455",
			std::string("Contact: ") + uri + ";expires=600\r\n"));

		auto ok = theOk(sent);
		ASSERT_NE(ok, nullptr);
		EXPECT_EQ(std::string(ok->getContact()), std::string("Contact: <") + uri + ">;expires=600");
	}
}

#ifndef GOOGLE_SERVICE_AUTH_HPP
#define GOOGLE_SERVICE_AUTH_HPP

// GoogleServiceAuth: issue #159's Google Workspace service-account
// domain-wide-delegation path. Builds an RS256-signed JWT assertion (RFC
// 7519 header/claims, Google's JWT-Bearer grant profile -- RFC 7523),
// exchanges it for a Bearer access token, and caches the token until it
// expires. SmtpDialogue::Config::accessToken is filled from getAccessToken()
// by the caller before a send; SmtpDialogue itself never talks OAuth.
//
// Split the same way SipDigest/TimeSync/RtpSender are: the pure JWT
// construction (header/claims JSON, the base64url signing input) is
// host-tested directly, byte for byte; RS256 signing is ONE function with
// two bodies -- mbedTLS `mbedtls_pk_sign` on-device (mbedtls is already a
// project dependency; main/CMakeLists.txt REQUIRES it), OpenSSL
// `EVP_DigestSign` on the host build (see tests/CMakeLists.txt's
// find_package(OpenSSL) -- IDF's own mbedtls ships only `mbedtls/private/*`
// headers, the same reason SipDigest.hpp vendors its own MD5 instead of
// depending on them). Both back the SAME RS256 algorithm (PKCS#1 v1.5 over
// SHA-256), so GoogleServiceAuth_test.cpp signs with a fixed embedded test
// key and verifies the result cryptographically -- there is nothing
// platform-specific left to diverge once the signature itself verifies.
//
// The network exchange (POST to oauth2.googleapis.com/token, parse the JSON
// response, cache) is ESP-only and NOT host-tested -- no network on the host
// build, and this task's scope note explicitly excludes real Google
// delivery from host coverage.

#include <cstdint>
#include <string>

namespace GoogleServiceAuth
{

	// {"alg":"RS256","typ":"JWT"} -- fixed, exposed for direct testing.
	std::string buildHeaderJson();

	// {"iss":...,"sub":...,"scope":...,"aud":...,"iat":...,"exp":...} per
	// RFC 7523 §3. `sub` is the Workspace user being sent-as (domain-wide
	// delegation); `aud` is always "https://oauth2.googleapis.com/token" in
	// buildSignedJwt() below but is a parameter here so the claims builder
	// itself has no hardcoded Google-specific string to get subtly wrong
	// without a test noticing.
	std::string buildClaimsJson(const std::string& iss, const std::string& sub,
	                             const std::string& scope, const std::string& aud,
	                             uint64_t iat, uint64_t exp);

	// RS256-signs `signingInput` (already the compact
	// "base64url(header).base64url(claims)" form) with a PEM RSA private
	// key, returning the RAW (unencoded) signature bytes. mbedTLS on-device,
	// OpenSSL on host -- see this header's top comment.
	bool signRs256(const std::string& privateKeyPem, const std::string& signingInput,
	                std::string& signatureOut, std::string& errOut);

	// Builds the full compact JWT: header.claims.signature, each segment
	// base64url (unpadded). exp = nowUnix + 3600 (Google's fixed maximum
	// lifetime for this grant type). `nowUnix` is a parameter, never read
	// from a clock internally, so this is deterministic and host-testable
	// end to end (GoogleServiceAuth_test.cpp signs with a fixed key and
	// verifies the signature over the exact bytes this function signed).
	bool buildSignedJwt(const std::string& serviceAccountEmail, const std::string& subjectUser,
	                     const std::string& scope, const std::string& privateKeyPem,
	                     uint64_t nowUnix, std::string& jwtOut, std::string& errOut);

#if defined(ESP_PLATFORM) || defined(ESP32)
	// Returns a Bearer access token for XOAUTH2, reusing a cached one until
	// 60 s before it expires. Builds+signs a fresh JWT and POSTs it to
	// Google's token endpoint (RFC 7523 §4) on a cache miss. Cache key is
	// (serviceAccountEmail, subjectUser, scope) -- cheap to call on every
	// send. ESP-only: real network + cJSON parsing.
	bool getAccessToken(const std::string& serviceAccountEmail, const std::string& subjectUser,
	                     const std::string& scope, const std::string& privateKeyPem,
	                     std::string& accessTokenOut, std::string& errOut);
#endif

} // namespace GoogleServiceAuth

#endif

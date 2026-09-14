// GoogleServiceAuth_test.cpp — issue #159 acceptance: "JWT construction +
// signature verified against a known test key". Covers:
//   1. The pure, crypto-free JSON construction (buildHeaderJson/
//      buildClaimsJson) against exact expected strings.
//   2. RS256 signing (signRs256, and end to end via buildSignedJwt) against a
//      FIXED, checked-in 2048-bit test-only RSA key, with the signature
//      verified cryptographically against that same key's public half using
//      OpenSSL directly here in the test -- independent of, and a check on,
//      GoogleServiceAuth.cpp's own OpenSSL-backed host implementation
//      (signRs256's on-device arm is mbedTLS; both produce the one
//      deterministic PKCS#1 v1.5 SHA-256 signature for a given key+input, so
//      a signature that verifies here is verified full stop -- see
//      GoogleServiceAuth.hpp's header comment for why there is nothing
//      platform-specific left to diverge once that holds).
//
// This is a TEST-ONLY key. It authenticates nothing and is committed
// deliberately (the whole point is a fixed, reproducible vector) -- never
// reuse it for anything that expects secrecy.

#include <gtest/gtest.h>
#include "GoogleServiceAuth.hpp"
#include "SmtpDialogue.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include <cstdint>
#include <string>
#include <vector>

namespace
{
	const char* kTestPrivateKeyPem =
		"-----BEGIN PRIVATE KEY-----\n" // gitleaks:allow -- test-only key, see file header comment
		"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCLHn22oH+dG00U\n"
		"A0Qk5xTmQlrwg+o02dcFr3mUugnUIHb2U0+jMUm0bFcBEdjb2S2Z1StzsufvopB0\n"
		"2A+MrpVzkKt2drZXYsVJToZhtNL36wsJyEaoHGA/yf7vqHgLiOSpJ4fQO6wR8NLq\n"
		"DpcdczjYxPjpW8sPOpIcMwUf4P90GoXQ3/GLukeXNAWiE0Sl2adhTZ+7tEjBoXGl\n"
		"BQIRWFSARwESIdT2bzN3P9zgA9lrbEGlHBvmZKZRQkCpDcj6xOTDI4oNrXdIrYxT\n"
		"NtSf687mWSBWFOePwCGwCvqGF2Ud//9haGa7xoT8ogo4Rs4cyl6hpfSzcSgIPfKb\n"
		"AuGKe/pFAgMBAAECggEAB51nZa3y1kNmjGwiWH/Ck9j5d9VMplBvNds1RTgKri8J\n"
		"u/Fy+DyMK4FLoN4cd+ozFgrGSlq2WdZU4GRsM3fh69W1IPKeB/n60Qioj+QRMStP\n"
		"Kx2oim6lMRCqMO2QhpcbZwvoIfSGNmQvc0rRqDXEnI7pjgJtgruiwELlqqlK6kyt\n"
		"sCg221sWqSsvVyyb4B7JaSf2TFHPdz90dZsFia3fS5DYmjHv0lzYqRpboQDImR2+\n"
		"SsDdYXRteLtCkDBxjv7kj/ZoHqqtk8i59tvBz5sF/rEXn8I0ydf91zgcfF9zvj4D\n"
		"4UoMHwbwAGRS8Op1HqKU4hYSxsMDQB5gyEFktTDR0QKBgQDB1Lh3q9W4dyH4uZGt\n"
		"EkSUowTyieeI4RnlQetftIrjcR0YzIPQ5wBYYqLB3cwK8vdK27QKSnrDvn34hvFK\n"
		"JJqWnxGKZy2znzLi/2DUG0T0JCNj3kdJlRY0ansC8fjOVZq8xfnZWSjiIHeBnNGW\n"
		"eS2m2KIxoFUqc6i0BR3/NdFKtQKBgQC3vW6tqXIygycDTU+v93HIFTtjZuwlp9Yo\n"
		"oktPozEIH4OHP/V4mAwRlpoFMvc7nGHPMqgyjmvzcINtOm2VMhXa+E8CRIx8P1JS\n"
		"uKzUsVZd5Geh94ns1Sjw/EZuCzHLobc7Dnm+tc3SlDVJKl8J2kM1X6YpB5lgP9jZ\n"
		"2I2gZwFbUQKBgHG3TBYhgPx9IDgdHsMsEYImdfOZRnY+ogOnfeCjOkyfgxOWgMsh\n"
		"i0lPbO9SIbBWxRBs/x5+fbGzY5JYEN2PxgYSAqdxSxWzk5Yrf3JRIU4emYiw0p/v\n"
		"0Jwl0E91CKR9ApA3khKaxWqM46/uAeRG6aqWM+nrh6ulOVeMHQIqX8R1AoGAbBLM\n"
		"SvFj7joedF7BBGuzTVDPwcQEGpIB8ZykV49Rg8mlf6QrKmekkaPXrD8yFKoDDfBp\n"
		"5nLHJEWFyHWZhywSlt1++4J+b4Z/UZC2d9RnTIrQOgBz7A3lKvn4IzoKbBAOynnV\n"
		"OkuNaNMsFIELravn5DkCbxe9K1PipSAvDa4IqkECgYBzpTINu/os/T34Yclj4eI5\n"
		"jHNuVaNmsw1oTJ+AKOOQMRjEuX4BR5Hg1jSq6+/91XX9BFEytRISwhuQOPGT9bmR\n"
		"7HpN44AP745IepmliPIdpjcXqxy28qO8pqrfjRi4OLJbSdnh9vgVOSpSjf1y7/h5\n"
		"7emjJptaWVlTpgEN5+CKJw==\n"
		"-----END PRIVATE KEY-----\n";

	// Minimal base64url DECODER, test-only (the library only exposes
	// encoders -- SmtpClient/GoogleServiceAuth never need to decode their own
	// output). Ignores whitespace; tolerant of missing padding, since
	// base64UrlEncode never emits any.
	std::vector<uint8_t> base64UrlDecode(const std::string& in)
	{
		auto val = [](char c) -> int {
			if (c >= 'A' && c <= 'Z') return c - 'A';
			if (c >= 'a' && c <= 'z') return c - 'a' + 26;
			if (c >= '0' && c <= '9') return c - '0' + 52;
			if (c == '-') return 62;
			if (c == '_') return 63;
			return -1;
		};
		std::vector<uint8_t> out;
		int buf = 0, bits = 0;
		for (char c : in)
		{
			int v = val(c);
			if (v < 0) continue;
			buf = (buf << 6) | v;
			bits += 6;
			if (bits >= 8)
			{
				bits -= 8;
				out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
			}
		}
		return out;
	}

	std::string toStr(const std::vector<uint8_t>& v)
	{
		return std::string(reinterpret_cast<const char*>(v.data()), v.size());
	}

	// Verifies an RSA-SHA256 (PKCS#1 v1.5) signature against `signingInput`
	// using the public half of kTestPrivateKeyPem. Independent of
	// GoogleServiceAuth.cpp's own signRs256 -- this is the "known test key"
	// half of the acceptance criterion.
	bool verifyRs256WithTestKey(const std::string& signingInput, const std::vector<uint8_t>& signature)
	{
		BIO* bio = BIO_new_mem_buf(kTestPrivateKeyPem, -1);
		EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
		BIO_free(bio);
		if (pkey == nullptr) return false;

		bool ok = false;
		EVP_MD_CTX* ctx = EVP_MD_CTX_new();
		if (ctx != nullptr)
		{
			if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
			    EVP_DigestVerifyUpdate(ctx, signingInput.data(), signingInput.size()) == 1)
			{
				ok = (EVP_DigestVerifyFinal(ctx, signature.data(), signature.size()) == 1);
			}
			EVP_MD_CTX_free(ctx);
		}
		EVP_PKEY_free(pkey);
		return ok;
	}
} // namespace

// ---------------------------------------------------------------------
// Pure JSON construction -- no crypto.
// ---------------------------------------------------------------------

TEST(GoogleServiceAuthPure, HeaderJsonIsFixed)
{
	EXPECT_EQ(GoogleServiceAuth::buildHeaderJson(), "{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
}

TEST(GoogleServiceAuthPure, ClaimsJsonExactShape)
{
	std::string claims = GoogleServiceAuth::buildClaimsJson(
		"sa@project.iam.gserviceaccount.com", "user@example.com",
		"https://mail.google.com/", "https://oauth2.googleapis.com/token",
		1700000000ULL, 1700003600ULL);
	EXPECT_EQ(claims,
		"{\"iss\":\"sa@project.iam.gserviceaccount.com\","
		"\"sub\":\"user@example.com\","
		"\"scope\":\"https://mail.google.com/\","
		"\"aud\":\"https://oauth2.googleapis.com/token\","
		"\"iat\":1700000000,\"exp\":1700003600}");
}

TEST(GoogleServiceAuthPure, ClaimsJsonEscapesUnsafeCharacters)
{
	// jsonEscapeString is already unit-tested (JsonEscape_test.cpp); this
	// just confirms buildClaimsJson actually routes every field through it,
	// so a subject/iss containing a quote can never break the JSON shape.
	std::string claims = GoogleServiceAuth::buildClaimsJson("a\"b", "c\\d", "e", "f", 0, 0);
	EXPECT_NE(claims.find("a\\\"b"), std::string::npos);
	EXPECT_NE(claims.find("c\\\\d"), std::string::npos);
}

// ---------------------------------------------------------------------
// RS256 signing against the fixed test key.
// ---------------------------------------------------------------------

TEST(GoogleServiceAuthCrypto, SignRs256_VerifiesAgainstKnownTestKey)
{
	std::string signingInput = "dGVzdA.cGF5bG9hZA"; // arbitrary fixed bytes
	std::string signature, err;
	ASSERT_TRUE(GoogleServiceAuth::signRs256(kTestPrivateKeyPem, signingInput, signature, err)) << err;
	EXPECT_GT(signature.size(), 0u);

	std::vector<uint8_t> sigBytes(signature.begin(), signature.end());
	EXPECT_TRUE(verifyRs256WithTestKey(signingInput, sigBytes));

	// A signature over different bytes must NOT verify against this one.
	EXPECT_FALSE(verifyRs256WithTestKey("different input", sigBytes));
}

TEST(GoogleServiceAuthCrypto, SignRs256_RejectsGarbageKey)
{
	std::string signature, err;
	EXPECT_FALSE(GoogleServiceAuth::signRs256("not a pem key", "input", signature, err));
	EXPECT_FALSE(err.empty());
}

TEST(GoogleServiceAuthCrypto, BuildSignedJwt_StructureAndSignatureVerify)
{
	std::string jwt, err;
	uint64_t now = 1700000000ULL;
	ASSERT_TRUE(GoogleServiceAuth::buildSignedJwt(
		"sa@project.iam.gserviceaccount.com", "user@example.com",
		"https://mail.google.com/", kTestPrivateKeyPem, now, jwt, err)) << err;

	// Exactly three dot-separated segments.
	size_t d1 = jwt.find('.');
	ASSERT_NE(d1, std::string::npos);
	size_t d2 = jwt.find('.', d1 + 1);
	ASSERT_NE(d2, std::string::npos);
	EXPECT_EQ(jwt.find('.', d2 + 1), std::string::npos);

	std::string headerSeg = jwt.substr(0, d1);
	std::string claimsSeg = jwt.substr(d1 + 1, d2 - d1 - 1);
	std::string sigSeg = jwt.substr(d2 + 1);

	// No padding, no '+'/'/' in any segment (base64url, unpadded).
	for (const std::string* seg : {&headerSeg, &claimsSeg, &sigSeg})
	{
		EXPECT_EQ(seg->find('='), std::string::npos);
		EXPECT_EQ(seg->find('+'), std::string::npos);
		EXPECT_EQ(seg->find('/'), std::string::npos);
	}

	std::string headerJson = toStr(base64UrlDecode(headerSeg));
	EXPECT_EQ(headerJson, "{\"alg\":\"RS256\",\"typ\":\"JWT\"}");

	std::string claimsJson = toStr(base64UrlDecode(claimsSeg));
	EXPECT_NE(claimsJson.find("\"iss\":\"sa@project.iam.gserviceaccount.com\""), std::string::npos);
	EXPECT_NE(claimsJson.find("\"sub\":\"user@example.com\""), std::string::npos);
	EXPECT_NE(claimsJson.find("\"scope\":\"https://mail.google.com/\""), std::string::npos);
	EXPECT_NE(claimsJson.find("\"aud\":\"https://oauth2.googleapis.com/token\""), std::string::npos);
	EXPECT_NE(claimsJson.find("\"iat\":1700000000"), std::string::npos);
	// exp = iat + 3600 (Google's fixed max lifetime for this grant type).
	EXPECT_NE(claimsJson.find("\"exp\":1700003600"), std::string::npos);

	std::string signingInput = headerSeg + "." + claimsSeg;
	std::vector<uint8_t> sigBytes = base64UrlDecode(sigSeg);
	EXPECT_TRUE(verifyRs256WithTestKey(signingInput, sigBytes));
}

TEST(GoogleServiceAuthCrypto, BuildSignedJwt_MissingFieldsRefused)
{
	std::string jwt, err;
	EXPECT_FALSE(GoogleServiceAuth::buildSignedJwt("", "sub", "scope", kTestPrivateKeyPem, 1, jwt, err));
	EXPECT_FALSE(GoogleServiceAuth::buildSignedJwt("iss", "sub", "scope", "", 1, jwt, err));
}

TEST(GoogleServiceAuthCrypto, BuildSignedJwt_DifferentInputsProduceDifferentSignatures)
{
	std::string jwt1, jwt2, err;
	ASSERT_TRUE(GoogleServiceAuth::buildSignedJwt("sa@x", "userA@x", "scope", kTestPrivateKeyPem, 1700000000ULL, jwt1, err));
	ASSERT_TRUE(GoogleServiceAuth::buildSignedJwt("sa@x", "userB@x", "scope", kTestPrivateKeyPem, 1700000000ULL, jwt2, err));
	EXPECT_NE(jwt1, jwt2);
}

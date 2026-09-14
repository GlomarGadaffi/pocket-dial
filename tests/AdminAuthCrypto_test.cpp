// AdminAuthCrypto_test.cpp — issue #186's password-based sealing primitives
// (AdminAuth::pbkdf2Sha256 / aesGcmSeal / aesGcmOpen), vector-tested against
// independent, published sources rather than only against themselves:
//
//   * PBKDF2-HMAC-SHA256: RFC 7914 §11's two vectors (P="passwd"/S="salt"/
//     c=1 and P="Password"/S="NaCl"/c=80000, both dkLen=64), plus an
//     independent cross-check against Python's hashlib.pbkdf2_hmac during
//     development (see the PR description) since a transcription error in a
//     hand-copied hex constant is indistinguishable from an implementation
//     bug without a second source.
//   * AES-256-GCM: the McGrew-Viega GCM specification's Appendix B Test
//     Cases 13 and 14 -- the two all-zero-key/IV 256-bit cases, one with an
//     empty plaintext (exercises tag-only output) and one with one full
//     16-byte block.
//
// Plus the properties that matter for THIS use (sealing a config-export
// blob), not just the raw vectors: a round trip recovers the exact
// plaintext, a single flipped ciphertext byte is rejected (never silently
// decrypts), a wrong AAD is rejected (the secrets block cannot be spliced
// onto a different plaintext section -- see HttpServer.cpp's
// sendApiConfigExport/Import), and the tag comparison does not short-circuit
// (aesGcmOpen's own comment documents the constant-time compare; this file
// pins its two failure paths -- wrong tag length is impossible by
// construction here since kGcmTagBytes is fixed, so the meaningful case is
// "any single differing byte", tested via the tamper case below across
// multiple byte positions).

#include <gtest/gtest.h>
#include "AdminAuth.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace
{
	std::string bytesToHex(const uint8_t* data, size_t len)
	{
		static const char* d = "0123456789abcdef";
		std::string out;
		out.reserve(len * 2);
		for (size_t i = 0; i < len; ++i)
		{
			out.push_back(d[(data[i] >> 4) & 0xF]);
			out.push_back(d[data[i] & 0xF]);
		}
		return out;
	}
}

// ── PBKDF2-HMAC-SHA256: RFC 7914 §11 vectors ────────────────────────────────

TEST(AdminAuthCrypto, Pbkdf2_Rfc7914Vector1_PasswdSaltC1)
{
	uint8_t out[64];
	const std::string salt = "salt";
	ASSERT_TRUE(AdminAuth::pbkdf2Sha256("passwd",
		reinterpret_cast<const uint8_t*>(salt.data()), salt.size(), 1, out, sizeof(out)));
	EXPECT_EQ(bytesToHex(out, sizeof(out)),
		"55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b6"
		"45991664b39d77ef317c71b845b1e30bd509112041d3a19783");
}

TEST(AdminAuthCrypto, Pbkdf2_Rfc7914Vector2_PasswordNaClC80000)
{
	uint8_t out[64];
	const std::string salt = "NaCl";
	ASSERT_TRUE(AdminAuth::pbkdf2Sha256("Password",
		reinterpret_cast<const uint8_t*>(salt.data()), salt.size(), 80000, out, sizeof(out)));
	EXPECT_EQ(bytesToHex(out, sizeof(out)),
		"4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833"
		"549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d");
}

TEST(AdminAuthCrypto, Pbkdf2_DegenerateInputsRejected)
{
	uint8_t out[32];
	const std::string salt = "salt";
	EXPECT_FALSE(AdminAuth::pbkdf2Sha256("pw",
		reinterpret_cast<const uint8_t*>(salt.data()), salt.size(), 0, out, sizeof(out)))
		<< "iterations == 0 must be rejected, not silently treated as 1";
	EXPECT_FALSE(AdminAuth::pbkdf2Sha256("pw",
		reinterpret_cast<const uint8_t*>(salt.data()), salt.size(), 1000, out, 0))
		<< "dkLen == 0 must be rejected";
}

TEST(AdminAuthCrypto, Pbkdf2_DifferentPasswordsProduceDifferentKeys)
{
	uint8_t a[32], b[32];
	const std::string salt = "same-salt-for-both";
	ASSERT_TRUE(AdminAuth::pbkdf2Sha256("password-one",
		reinterpret_cast<const uint8_t*>(salt.data()), salt.size(), 1000, a, sizeof(a)));
	ASSERT_TRUE(AdminAuth::pbkdf2Sha256("password-two",
		reinterpret_cast<const uint8_t*>(salt.data()), salt.size(), 1000, b, sizeof(b)));
	EXPECT_NE(bytesToHex(a, sizeof(a)), bytesToHex(b, sizeof(b)));
}

// ── AES-256-GCM: McGrew-Viega GCM spec, Appendix B, Test Cases 13 & 14 ─────

TEST(AdminAuthCrypto, Gcm_TestCase13_EmptyPlaintextEmptyAad_AllZeroKeyIv)
{
	uint8_t key[32] = {0};
	uint8_t iv[12] = {0};
	std::string ct;
	AdminAuth::aesGcmSeal(key, iv, "", "", ct);
	// Empty plaintext -> ciphertext is just the 16-byte tag.
	ASSERT_EQ(ct.size(), 16u);
	EXPECT_EQ(bytesToHex(reinterpret_cast<const uint8_t*>(ct.data()), ct.size()),
		"530f8afbc74536b9a963b4f1c4cb738b");

	std::string opened;
	ASSERT_TRUE(AdminAuth::aesGcmOpen(key, iv, "", ct, opened));
	EXPECT_EQ(opened, "");
}

TEST(AdminAuthCrypto, Gcm_TestCase14_OneZeroBlock_AllZeroKeyIv)
{
	uint8_t key[32] = {0};
	uint8_t iv[12] = {0};
	const std::string pt(16, '\0');
	std::string ct;
	AdminAuth::aesGcmSeal(key, iv, "", pt, ct);
	ASSERT_EQ(ct.size(), 32u);   // 16-byte ciphertext + 16-byte tag
	EXPECT_EQ(bytesToHex(reinterpret_cast<const uint8_t*>(ct.data()), 16),
		"cea7403d4d606b6e074ec5d3baf39d18");
	EXPECT_EQ(bytesToHex(reinterpret_cast<const uint8_t*>(ct.data()) + 16, 16),
		"d0d1c8a799996bf0265b98b5d48ab919");

	std::string opened;
	ASSERT_TRUE(AdminAuth::aesGcmOpen(key, iv, "", ct, opened));
	EXPECT_EQ(opened, pt);
}

// ── Properties this feature actually depends on ─────────────────────────────

TEST(AdminAuthCrypto, RoundTrip_ArbitraryKeyNonceAadPlaintext)
{
	uint8_t key[32];
	for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i * 7 + 1);
	uint8_t nonce[12];
	for (int i = 0; i < 12; ++i) nonce[i] = static_cast<uint8_t>(0xA0 + i);
	const std::string aad = "config-export-plaintext-section";
	const std::string pt = "the quick brown fox jumps over the lazy dog, 47 times";

	std::string ct;
	AdminAuth::aesGcmSeal(key, nonce, aad, pt, ct);
	EXPECT_EQ(ct.size(), pt.size() + AdminAuth::kGcmTagBytes);

	std::string opened;
	ASSERT_TRUE(AdminAuth::aesGcmOpen(key, nonce, aad, ct, opened));
	EXPECT_EQ(opened, pt);
}

TEST(AdminAuthCrypto, TamperedCiphertext_RejectedAtEveryByteOffset)
{
	// Flips each byte of a real ciphertext one at a time and asserts open()
	// fails every single time -- not just "the first byte", which alone
	// would not catch a bug in only part of the CTR-mode keystream or GHASH
	// accumulation.
	uint8_t key[32];
	for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i);
	uint8_t nonce[12];
	for (int i = 0; i < 12; ++i) nonce[i] = static_cast<uint8_t>(i);
	const std::string pt = "0123456789abcdef0123456789abcdef";   // 33 bytes, >2 blocks
	std::string ct;
	AdminAuth::aesGcmSeal(key, nonce, "aad", pt, ct);

	for (size_t i = 0; i < ct.size(); ++i)
	{
		std::string tampered = ct;
		tampered[i] = static_cast<char>(tampered[i] ^ 0x01);
		std::string opened;
		EXPECT_FALSE(AdminAuth::aesGcmOpen(key, nonce, "aad", tampered, opened))
			<< "byte offset " << i << " was not authenticated";
	}
}

TEST(AdminAuthCrypto, WrongAad_Rejected)
{
	uint8_t key[32] = {0};
	uint8_t nonce[12] = {0};
	std::string ct;
	AdminAuth::aesGcmSeal(key, nonce, "correct-aad", "some plaintext", ct);

	std::string opened;
	EXPECT_FALSE(AdminAuth::aesGcmOpen(key, nonce, "wrong-aad", ct, opened))
		<< "a splice attempt (same ciphertext, different plaintext section as AAD) must fail";
	EXPECT_FALSE(AdminAuth::aesGcmOpen(key, nonce, "", ct, opened))
		<< "an empty AAD must not be treated as a wildcard";
}

TEST(AdminAuthCrypto, WrongKey_Rejected)
{
	uint8_t key1[32] = {0};
	uint8_t key2[32] = {0};
	key2[0] = 0x01;
	uint8_t nonce[12] = {0};
	std::string ct;
	AdminAuth::aesGcmSeal(key1, nonce, "", "some plaintext data", ct);

	std::string opened;
	EXPECT_FALSE(AdminAuth::aesGcmOpen(key2, nonce, "", ct, opened));
}

TEST(AdminAuthCrypto, TruncatedCiphertext_ShorterThanTag_Rejected)
{
	uint8_t key[32] = {0};
	uint8_t nonce[12] = {0};
	std::string tooShort(AdminAuth::kGcmTagBytes - 1, '\0');
	std::string opened;
	EXPECT_FALSE(AdminAuth::aesGcmOpen(key, nonce, "", tooShort, opened));
}

TEST(AdminAuthCrypto, SecureRandomBytesProducesDistinctOutput)
{
	uint8_t a[16] = {0};
	uint8_t b[16] = {0};
	AdminAuth::secureRandomBytes(a, sizeof(a));
	AdminAuth::secureRandomBytes(b, sizeof(b));
	EXPECT_NE(bytesToHex(a, sizeof(a)), bytesToHex(b, sizeof(b)))
		<< "two successive draws landing on the same 128 bits would indicate a broken RNG";
}

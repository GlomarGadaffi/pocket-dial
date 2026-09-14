// AdminAuth.cpp: platform-portable admin credential + session manager.
//
// See AdminAuth.hpp for the design rationale. This file is intentionally
// dependency-free beyond the C++17 standard library and the platform guards.
//
// Crypto: a small, self-contained SHA-256 (public-domain reference
// implementation of FIPS 180-4) is used on BOTH host and ESP so that the
// stored credential is identical and portable, and so the host build needs no
// external crypto library. Secrets (the login password and the DTMF PIN) are
// stored as salt + iterated SHA-256 (a PBKDF-style key-stretch) — never in
// cleartext. The username is stored in cleartext (it is an identity, not a
// secret) alongside the password's salt/hash.
//
// Randomness: esp_random() (a hardware CSPRNG) on ESP; on host, a
// std::random_device-seeded std::mt19937_64 (host is a developer/CI simulator,
// not the production trust boundary — documented in docs/THREAT_MODEL.md).

#include "AdminAuth.hpp"

#include <array>
#include <cctype>
#include <mutex>
#include <vector>
#include <cstring>
#include <chrono>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// On the device, credentials persist in NVS and randomness comes from the
	// hardware RNG. nvs_flash/nvs/esp_random are core ESP-IDF components present
	// on EVERY transport (wifi, eth, display) — they are not WiFi-specific, so
	// they must be gated on ESP_PLATFORM, not POCKETDIAL_HAS_WIFI.
	#include "nvs_flash.h"
	#include "nvs.h"
	#include "esp_random.h"
#else
	#include <random>
#endif

namespace
{
	// ---------------------------------------------------------------------
	// Self-contained SHA-256 (FIPS 180-4). Public-domain reference style.
	// Operates on bytes; produces a 32-byte digest.
	// ---------------------------------------------------------------------
	class Sha256
	{
	public:
		Sha256() { reset(); }

		void update(const uint8_t* data, size_t len)
		{
			for (size_t i = 0; i < len; ++i)
			{
				_buffer[_bufferLen++] = data[i];
				if (_bufferLen == 64)
				{
					transform(_buffer.data());
					_bitLen += 512;
					_bufferLen = 0;
				}
			}
		}

		void update(const std::string& s)
		{
			update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
		}

		// Finalizes and writes the 32-byte digest into out.
		void finalize(uint8_t out[32])
		{
			uint64_t totalBits = _bitLen + static_cast<uint64_t>(_bufferLen) * 8;

			// Append the 0x80 padding byte.
			size_t i = _bufferLen;
			_buffer[i++] = 0x80;

			// If there is no room for the 8-byte length, pad+flush this block.
			if (i > 56)
			{
				while (i < 64) _buffer[i++] = 0x00;
				transform(_buffer.data());
				i = 0;
			}
			while (i < 56) _buffer[i++] = 0x00;

			// Append the message length as a big-endian 64-bit integer.
			for (int b = 7; b >= 0; --b)
			{
				_buffer[i++] = static_cast<uint8_t>((totalBits >> (b * 8)) & 0xFF);
			}
			transform(_buffer.data());

			// Emit the state in big-endian order.
			for (int j = 0; j < 8; ++j)
			{
				out[j * 4 + 0] = static_cast<uint8_t>((_state[j] >> 24) & 0xFF);
				out[j * 4 + 1] = static_cast<uint8_t>((_state[j] >> 16) & 0xFF);
				out[j * 4 + 2] = static_cast<uint8_t>((_state[j] >> 8) & 0xFF);
				out[j * 4 + 3] = static_cast<uint8_t>(_state[j] & 0xFF);
			}
		}

	private:
		void reset()
		{
			_state[0] = 0x6a09e667u;
			_state[1] = 0xbb67ae85u;
			_state[2] = 0x3c6ef372u;
			_state[3] = 0xa54ff53au;
			_state[4] = 0x510e527fu;
			_state[5] = 0x9b05688cu;
			_state[6] = 0x1f83d9abu;
			_state[7] = 0x5be0cd19u;
			_bufferLen = 0;
			_bitLen = 0;
		}

		static uint32_t rotr(uint32_t x, uint32_t n)
		{
			return (x >> n) | (x << (32 - n));
		}

		void transform(const uint8_t* chunk)
		{
			static const uint32_t k[64] = {
				0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
				0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
				0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
				0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
				0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
				0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
				0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
				0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
				0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
				0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
				0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
				0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
				0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
				0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
				0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
				0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
			};

			uint32_t w[64];
			for (int i = 0; i < 16; ++i)
			{
				w[i] = (static_cast<uint32_t>(chunk[i * 4 + 0]) << 24) |
				       (static_cast<uint32_t>(chunk[i * 4 + 1]) << 16) |
				       (static_cast<uint32_t>(chunk[i * 4 + 2]) << 8) |
				       (static_cast<uint32_t>(chunk[i * 4 + 3]));
			}
			for (int i = 16; i < 64; ++i)
			{
				uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
				uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
				w[i] = w[i - 16] + s0 + w[i - 7] + s1;
			}

			uint32_t a = _state[0];
			uint32_t b = _state[1];
			uint32_t c = _state[2];
			uint32_t d = _state[3];
			uint32_t e = _state[4];
			uint32_t f = _state[5];
			uint32_t g = _state[6];
			uint32_t h = _state[7];

			for (int i = 0; i < 64; ++i)
			{
				uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
				uint32_t ch = (e & f) ^ ((~e) & g);
				uint32_t temp1 = h + s1 + ch + k[i] + w[i];
				uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
				uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
				uint32_t temp2 = s0 + maj;

				h = g;
				g = f;
				f = e;
				e = d + temp1;
				d = c;
				c = b;
				b = a;
				a = temp1 + temp2;
			}

			_state[0] += a;
			_state[1] += b;
			_state[2] += c;
			_state[3] += d;
			_state[4] += e;
			_state[5] += f;
			_state[6] += g;
			_state[7] += h;
		}

		std::array<uint32_t, 8> _state{};
		std::array<uint8_t, 64> _buffer{};
		size_t   _bufferLen = 0;
		uint64_t _bitLen = 0;
	};

	std::string toHex(const uint8_t* data, size_t len)
	{
		static const char* digits = "0123456789abcdef";
		std::string out;
		out.reserve(len * 2);
		for (size_t i = 0; i < len; ++i)
		{
			out.push_back(digits[(data[i] >> 4) & 0x0F]);
			out.push_back(digits[data[i] & 0x0F]);
		}
		return out;
	}

	// Plain SHA-256 over a byte buffer, as a fixed 32-byte array. Thin wrapper
	// around the Sha256 class above, used by the HMAC/PBKDF2/GCM helpers below.
	std::array<uint8_t, 32> sha256Bytes(const uint8_t* data, size_t len)
	{
		Sha256 sha;
		sha.update(data, len);
		std::array<uint8_t, 32> out;
		sha.finalize(out.data());
		return out;
	}

	// ---------------------------------------------------------------------
	// HMAC-SHA256 (RFC 2104). Block size 64 bytes, output 32 bytes.
	// ---------------------------------------------------------------------
	std::array<uint8_t, 32> hmacSha256(const uint8_t* key, size_t keyLen,
		const uint8_t* msg, size_t msgLen)
	{
		constexpr size_t kBlock = 64;
		std::array<uint8_t, kBlock> keyBlock{};   // zero-padded

		if (keyLen > kBlock)
		{
			auto hashed = sha256Bytes(key, keyLen);
			std::copy(hashed.begin(), hashed.end(), keyBlock.begin());
		}
		else if (keyLen > 0)
		{
			std::copy(key, key + keyLen, keyBlock.begin());
		}

		std::array<uint8_t, kBlock> ipad{};
		std::array<uint8_t, kBlock> opad{};
		for (size_t i = 0; i < kBlock; ++i)
		{
			ipad[i] = static_cast<uint8_t>(keyBlock[i] ^ 0x36);
			opad[i] = static_cast<uint8_t>(keyBlock[i] ^ 0x5c);
		}

		Sha256 inner;
		inner.update(ipad.data(), ipad.size());
		inner.update(msg, msgLen);
		std::array<uint8_t, 32> innerDigest;
		inner.finalize(innerDigest.data());

		Sha256 outer;
		outer.update(opad.data(), opad.size());
		outer.update(innerDigest.data(), innerDigest.size());
		std::array<uint8_t, 32> result;
		outer.finalize(result.data());
		return result;
	}

	// ---------------------------------------------------------------------
	// AES-256 (FIPS 197). Encryption direction only — GCM's CTR mode never
	// needs the inverse cipher (decryption is "encrypt the counter, XOR the
	// keystream" in both directions), so no InvSubBytes/InvMixColumns table
	// is carried here.
	// ---------------------------------------------------------------------
	const uint8_t kAesSbox[256] = {
		0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
		0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
		0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
		0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
		0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
		0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
		0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
		0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
		0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
		0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
		0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
		0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
		0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
		0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
		0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
		0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
	};

	uint8_t gmul(uint8_t a, uint8_t b)
	{
		uint8_t p = 0;
		for (int i = 0; i < 8; ++i)
		{
			if (b & 1) p ^= a;
			bool hi = a & 0x80;
			a = static_cast<uint8_t>(a << 1);
			if (hi) a ^= 0x1b;
			b = static_cast<uint8_t>(b >> 1);
		}
		return p;
	}

	// AES-256 key schedule: 8 key words expand to 60 round-key words (15
	// round keys x 4 words), per FIPS 197 §5.2. Nk=8 has ONE wrinkle versus
	// AES-128: every 4th word (i % Nk == 4) also gets SubWord (but NOT
	// RotWord/Rcon) applied — the branch below exists for exactly that.
	struct AesKeySchedule
	{
		// 60 x 4-byte words = 240 bytes = 15 round keys.
		uint8_t w[60][4];
	};

	void aesKeyExpansion(const uint8_t key[32], AesKeySchedule& ks)
	{
		constexpr int Nk = 8;
		constexpr int Nr = 14;
		constexpr int totalWords = 4 * (Nr + 1);   // 60

		static const uint8_t rcon[11] = {
			0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
		};

		for (int i = 0; i < Nk; ++i)
		{
			ks.w[i][0] = key[4 * i + 0];
			ks.w[i][1] = key[4 * i + 1];
			ks.w[i][2] = key[4 * i + 2];
			ks.w[i][3] = key[4 * i + 3];
		}

		uint8_t temp[4];
		for (int i = Nk; i < totalWords; ++i)
		{
			temp[0] = ks.w[i - 1][0];
			temp[1] = ks.w[i - 1][1];
			temp[2] = ks.w[i - 1][2];
			temp[3] = ks.w[i - 1][3];

			if (i % Nk == 0)
			{
				// RotWord
				uint8_t t0 = temp[0];
				temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t0;
				// SubWord
				for (auto& b : temp) b = kAesSbox[b];
				temp[0] = static_cast<uint8_t>(temp[0] ^ rcon[i / Nk]);
			}
			else if (i % Nk == 4)
			{
				// AES-256-only step: SubWord with no rotation and no Rcon.
				for (auto& b : temp) b = kAesSbox[b];
			}

			for (int j = 0; j < 4; ++j)
			{
				ks.w[i][j] = static_cast<uint8_t>(ks.w[i - Nk][j] ^ temp[j]);
			}
		}
	}

	// Encrypts one 16-byte block in place. `state` is column-major, matching
	// FIPS 197's convention (state[col][row] laid out as state[4*col+row]).
	void aesEncryptBlock(const AesKeySchedule& ks, const uint8_t in[16], uint8_t out[16])
	{
		constexpr int Nr = 14;
		uint8_t s[16];
		for (int i = 0; i < 16; ++i) s[i] = in[i];

		auto addRoundKey = [&](int round) {
			for (int c = 0; c < 4; ++c)
				for (int r = 0; r < 4; ++r)
					s[4 * c + r] = static_cast<uint8_t>(s[4 * c + r] ^ ks.w[round * 4 + c][r]);
		};

		addRoundKey(0);

		for (int round = 1; round <= Nr; ++round)
		{
			// SubBytes
			for (int i = 0; i < 16; ++i) s[i] = kAesSbox[s[i]];

			// ShiftRows (row r shifts left by r, in column-major layout)
			uint8_t t[16];
			for (int c = 0; c < 4; ++c)
				for (int r = 0; r < 4; ++r)
					t[4 * c + r] = s[4 * ((c + r) % 4) + r];
			for (int i = 0; i < 16; ++i) s[i] = t[i];

			// MixColumns (skipped on the final round)
			if (round != Nr)
			{
				for (int c = 0; c < 4; ++c)
				{
					uint8_t a0 = s[4 * c + 0], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
					s[4 * c + 0] = static_cast<uint8_t>(gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3);
					s[4 * c + 1] = static_cast<uint8_t>(a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3);
					s[4 * c + 2] = static_cast<uint8_t>(a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3));
					s[4 * c + 3] = static_cast<uint8_t>(gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2));
				}
			}

			addRoundKey(round);
		}

		for (int i = 0; i < 16; ++i) out[i] = s[i];
	}

	// ---------------------------------------------------------------------
	// GHASH: multiplication in GF(2^128) with the GCM reduction polynomial
	// (x^128 + x^7 + x^2 + x + 1), MSB-first bit order per NIST SP 800-38D.
	// Bit-at-a-time — simple and constant-structure rather than fast, which
	// is the right trade for encrypting a few KB of config once per export.
	// ---------------------------------------------------------------------
	void gf128Mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16])
	{
		uint8_t z[16] = {0};
		uint8_t v[16];
		for (int i = 0; i < 16; ++i) v[i] = y[i];

		for (int i = 0; i < 128; ++i)
		{
			int byteIdx = i / 8;
			int bitIdx = 7 - (i % 8);
			if (x[byteIdx] & (1 << bitIdx))
			{
				for (int j = 0; j < 16; ++j) z[j] ^= v[j];
			}
			bool lsb = (v[15] & 0x01) != 0;
			for (int j = 15; j > 0; --j)
			{
				v[j] = static_cast<uint8_t>((v[j] >> 1) | ((v[j - 1] & 0x01) << 7));
			}
			v[0] = static_cast<uint8_t>(v[0] >> 1);
			if (lsb)
			{
				v[0] = static_cast<uint8_t>(v[0] ^ 0xe1);
			}
		}
		for (int i = 0; i < 16; ++i) out[i] = z[i];
	}

	struct GhashState
	{
		uint8_t h[16];
		uint8_t y[16] = {0};
	};

	void ghashUpdateBlock(GhashState& g, const uint8_t block[16])
	{
		uint8_t xored[16];
		for (int i = 0; i < 16; ++i) xored[i] = static_cast<uint8_t>(g.y[i] ^ block[i]);
		gf128Mul(xored, g.h, g.y);
	}

	// Feeds `data` through GHASH as full 16-byte blocks, zero-padding a final
	// short block (the padding is NOT written back — GCM's u/v padding is
	// virtual, per the spec).
	void ghashUpdateBytes(GhashState& g, const uint8_t* data, size_t len)
	{
		size_t off = 0;
		while (off + 16 <= len)
		{
			ghashUpdateBlock(g, data + off);
			off += 16;
		}
		if (off < len)
		{
			uint8_t block[16] = {0};
			for (size_t i = 0; i < len - off; ++i) block[i] = data[off + i];
			ghashUpdateBlock(g, block);
		}
	}

	void writeBe64(uint8_t out[8], uint64_t v)
	{
		for (int i = 0; i < 8; ++i)
		{
			out[i] = static_cast<uint8_t>((v >> (56 - 8 * i)) & 0xFF);
		}
	}

	// Increments only the low 32 bits of a 16-byte GCM counter block (the
	// high 96 bits, the nonce, are left untouched) — NIST SP 800-38D's inc32.
	void gcmIncCounter(uint8_t counter[16])
	{
		for (int i = 15; i >= 12; --i)
		{
			if (++counter[i] != 0) break;
		}
	}

	// CTR-mode keystream XOR, starting at `counter` (mutated as it advances).
	// Used for both directions: GCM ciphertext is XOR-with-keystream either
	// way, so encrypt and decrypt share this one routine.
	void gcmCtrXor(const AesKeySchedule& ks, uint8_t counter[16],
		const uint8_t* in, uint8_t* out, size_t len)
	{
		size_t off = 0;
		while (off < len)
		{
			uint8_t keystream[16];
			aesEncryptBlock(ks, counter, keystream);
			gcmIncCounter(counter);
			size_t chunk = (len - off < 16) ? (len - off) : 16;
			for (size_t i = 0; i < chunk; ++i)
			{
				out[off + i] = static_cast<uint8_t>(in[off + i] ^ keystream[i]);
			}
			off += chunk;
		}
	}

	// Salted, iterated SHA-256 (PBKDF-style key-stretch). The iteration count
	// makes offline brute-forcing of a leaked hash markedly more expensive.
	// Returns a 64-char lowercase hex digest. Used for both the login password
	// and the DTMF PIN — same stretch cost either way.
	std::string hashSecret(const std::string& salt, const std::string& secret)
	{
		uint8_t digest[32];

		// Round 0: SHA-256(salt || secret).
		{
			Sha256 sha;
			sha.update(salt);
			sha.update(secret);
			sha.finalize(digest);
		}

		// Subsequent rounds: SHA-256(salt || previousDigest).
		for (uint32_t i = 1; i < AdminAuth::kHashIterations; ++i)
		{
			Sha256 sha;
			sha.update(salt);
			sha.update(digest, sizeof(digest));
			sha.finalize(digest);
		}

		return toHex(digest, sizeof(digest));
	}

	// Cryptographically-strong (on ESP) random bytes. On host, a PRNG seeded
	// from std::random_device — adequate for the host simulator.
	void fillRandom(uint8_t* buf, size_t len)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		// Hardware CSPRNG, available on every ESP transport.
		for (size_t i = 0; i < len; ++i)
		{
			buf[i] = static_cast<uint8_t>(esp_random() & 0xFF);
		}
#else
		// Host simulator: seed mt19937_64 from random_device once, also stirring
		// in a steady-clock sample. (Host is a developer/CI simulator, not the
		// production trust boundary — documented in docs/THREAT_MODEL.md.)
		static std::mt19937_64 rng = [] {
			std::random_device rd;
			uint64_t seed = (static_cast<uint64_t>(rd()) << 32) ^ rd();
			seed ^= static_cast<uint64_t>(
				std::chrono::steady_clock::now().time_since_epoch().count());
			return std::mt19937_64(seed);
		}();
		for (size_t i = 0; i < len; ++i)
		{
			buf[i] = static_cast<uint8_t>(rng() & 0xFF);
		}
#endif
	}

	std::string randomHex(size_t hexChars)
	{
		size_t nbytes = (hexChars + 1) / 2;
		std::vector<uint8_t> bytes(nbytes);
		fillRandom(bytes.data(), bytes.size());
		std::string hex = toHex(bytes.data(), bytes.size());
		hex.resize(hexChars);
		return hex;
	}

	// Constant-time string compare. Returns true iff equal. Designed not to
	// short-circuit on the first differing byte, so timing does not leak how
	// many leading characters matched. (Length is compared up front — for the
	// fixed-length hex digests this leaks nothing beyond "same length"; for the
	// username compare in verifyCredential() the password hash is always
	// computed regardless of this result, so a wrong username costs the same
	// wall-clock time as a wrong password.)
	bool constantTimeEquals(const std::string& a, const std::string& b)
	{
		if (a.size() != b.size())
		{
			return false;
		}
		unsigned char diff = 0;
		for (size_t i = 0; i < a.size(); ++i)
		{
			diff = static_cast<unsigned char>(
				diff | (static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i])));
		}
		return diff == 0;
	}

	bool usernameValid(const std::string& u)
	{
		if (u.size() < AdminAuth::kMinUsernameLength || u.size() > AdminAuth::kMaxUsernameLength)
		{
			return false;
		}
		for (char c : u)
		{
			// No whitespace or control characters — this is an identity string
			// rendered into JSON/NVS, not free text.
			if (std::iscntrl(static_cast<unsigned char>(c)) || std::isspace(static_cast<unsigned char>(c)))
			{
				return false;
			}
		}
		return true;
	}

	bool passwordValid(const std::string& p)
	{
		return p.size() >= AdminAuth::kMinPasswordLength && p.size() <= AdminAuth::kMaxPasswordLength;
	}

	bool dtmfPinValid(const std::string& p)
	{
		if (p.size() < AdminAuth::kMinDtmfPinLength || p.size() > AdminAuth::kMaxDtmfPinLength)
		{
			return false;
		}
		for (char c : p)
		{
			if (!std::isdigit(static_cast<unsigned char>(c)))
			{
				return false;
			}
		}
		return true;
	}

	uint64_t nowMs()
	{
		return static_cast<uint64_t>(
			std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now().time_since_epoch()).count());
	}

	// ---------------------------------------------------------------------
	// Shared, mutex-guarded state.
	// ---------------------------------------------------------------------
	struct Session
	{
		std::string token;
		// Per-session CSRF token. Bound to the session by living in the same slot;
		// never sent as a cookie, so SameSite/HttpOnly protect the session id while
		// this protects against a same-site page that can still drive fetch().
		std::string csrf;
		uint64_t    expiresAtMs = 0;
		bool        used = false;
		// Issue #173: the role this session authenticated as. Defaults to Sysop
		// so every pre-existing createSession() call (no argument) keeps its old
		// meaning exactly.
		AdminAuth::Role role = AdminAuth::Role::Sysop;
	};

	// Per-principal aggregate brute-force backstop (see AttemptBucket below for
	// the per-client half). Two independent triplets — one per Role that
	// authenticate() can resolve to — so that spraying the SYSOP password from
	// rotated source addresses cannot also lock the OWNER out via the shared
	// aggregate counter the way a single counter would. Index with
	// principalIndex() below. Deliberately NOT used by verifyCredential()/
	// verifyDtmfPin(), which keep their own original single triplet (in
	// AuthState below) unchanged, for exact backward compatibility.
	struct GlobalBackstop
	{
		int      failures = 0;
		int      trips = 0;
		uint64_t lockoutUntilMs = 0;
	};

	// 0 = sysop, 1 = owner. Role::None never reaches here (authenticate() always
	// resolves to one or the other before accounting).
	size_t principalIndex(AdminAuth::Role r)
	{
		return (r == AdminAuth::Role::Owner) ? 1 : 0;
	}

	const char* principalName(AdminAuth::Role r)
	{
		return (r == AdminAuth::Role::Owner) ? "owner" : "sysop";
	}

	// One brute-force accounting bucket per client identity (see
	// AdminAuth::kMaxAttemptBuckets). `key` is the HTTP peer address; the empty
	// key is the unkeyed bucket used by callers with no peer (the DTMF menu).
	// Shared between login-credential and DTMF-PIN attempts.
	struct AttemptBucket
	{
		std::string key;
		bool        used = false;
		int         failures = 0;        // failures inside the current window
		int         trips = 0;           // lockouts engaged since the last success
		uint64_t    lockoutUntilMs = 0;
		uint64_t    lastSeenMs = 0;      // for least-recently-seen eviction
	};

	struct AuthState
	{
		std::mutex mutex;

		// In-memory mirror of the stored credentials. On ESP this is loaded from
		// NVS on first access; on host it IS the credential (host has no NVS).
		bool        loaded = false;     // have we tried to load from NVS yet?

		// Login credential (web dashboard). `provisioned` is true only once
		// setLoginCredential() has been called at least once — until then,
		// verifyCredential() accepts only the compiled-in default.
		bool        provisioned = false;
		std::string username;
		std::string pwSalt;             // hex
		std::string pwHash;             // hex (salted, iterated digest)

		// Issue #173: the OWNER principal. Independent of the sysop fields
		// above — same shape, own NVS keys, own "has this ever been set" flag.
		bool        ownerProvisioned = false;
		std::string ownerUsername;
		std::string ownerPwSalt;        // hex
		std::string ownerPwHash;        // hex (salted, iterated digest)

		// DTMF admin-menu PIN (phone keypad). No default — dtmfPinSet stays
		// false, and verifyDtmfPin() always fails, until setDtmfPin() is called.
		bool        dtmfPinSet = false;
		std::string pinSalt;            // hex
		std::string pinHash;            // hex (salted, iterated digest)

		// Brute-force lockout, tracked per client (docs/THREAT_MODEL.md §5.2, D-3).
		// Shared by login-credential and DTMF-PIN attempts. authenticate() (the
		// two-role HTTP path) uses its OWN composite "clientKey\x1fprincipal" keys
		// into this SAME table (acquireBucketLocked's `key` is an opaque string),
		// so a sysop guess and an owner guess from the same client land in
		// different buckets automatically.
		std::array<AttemptBucket, AdminAuth::kMaxAttemptBuckets> attempts{};

		// Aggregate backstop across every client, so that rotating source addresses
		// cannot buy an unbounded guess rate (see kMaxFailedAttemptsGlobal).
		// Used ONLY by verifyCredential()/verifyDtmfPin() (unchanged, for exact
		// backward compatibility) — authenticate() uses principalBackstop[] below.
		int      globalFailures = 0;
		int      globalTrips = 0;
		uint64_t globalLockoutUntilMs = 0;

		// Per-principal aggregate backstop for authenticate() — see
		// GlobalBackstop's comment for why this must not be shared across roles.
		std::array<GlobalBackstop, 2> principalBackstop{};

		std::array<Session, AdminAuth::kMaxSessions> sessions{};
	};

	// Function-local static: avoids a static-initialization-order fiasco and is
	// thread-safe to initialize under C++11+.
	AuthState& state()
	{
		static AuthState s;
		return s;
	}

	// --- NVS-backed persistence (ESP only); no-ops on host. ---
	// Caller must hold state().mutex.
	void loadCredentialLocked(AuthState& s)
	{
		if (s.loaded)
		{
			return;
		}
		s.loaded = true;

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open("storage", NVS_READWRITE, &h) == ESP_OK)
		{
			char userBuf[128] = {0};
			char saltBuf[128] = {0};
			char hashBuf[128] = {0};
			size_t userLen = sizeof(userBuf);
			size_t saltLen = sizeof(saltBuf);
			size_t hashLen = sizeof(hashBuf);
			esp_err_t e1 = nvs_get_str(h, "admin_user", userBuf, &userLen);
			esp_err_t e2 = nvs_get_str(h, "admin_pw_salt", saltBuf, &saltLen);
			esp_err_t e3 = nvs_get_str(h, "admin_pw_hash", hashBuf, &hashLen);
			if (e1 == ESP_OK && e2 == ESP_OK && e3 == ESP_OK &&
				userBuf[0] != '\0' && saltBuf[0] != '\0' && hashBuf[0] != '\0')
			{
				s.username = userBuf;
				s.pwSalt = saltBuf;
				s.pwHash = hashBuf;
				s.provisioned = true;
			}

			char pinSaltBuf[128] = {0};
			char pinHashBuf[128] = {0};
			size_t pinSaltLen = sizeof(pinSaltBuf);
			size_t pinHashLen = sizeof(pinHashBuf);
			esp_err_t e4 = nvs_get_str(h, "admin_pin_salt", pinSaltBuf, &pinSaltLen);
			esp_err_t e5 = nvs_get_str(h, "admin_pin_hash", pinHashBuf, &pinHashLen);
			if (e4 == ESP_OK && e5 == ESP_OK && pinSaltBuf[0] != '\0' && pinHashBuf[0] != '\0')
			{
				s.pinSalt = pinSaltBuf;
				s.pinHash = pinHashBuf;
				s.dtmfPinSet = true;
			}

			// Issue #173: the OWNER principal, own NVS keys.
			char ownerUserBuf[128] = {0};
			char ownerSaltBuf[128] = {0};
			char ownerHashBuf[128] = {0};
			size_t ownerUserLen = sizeof(ownerUserBuf);
			size_t ownerSaltLen = sizeof(ownerSaltBuf);
			size_t ownerHashLen = sizeof(ownerHashBuf);
			esp_err_t e6 = nvs_get_str(h, "owner_user", ownerUserBuf, &ownerUserLen);
			esp_err_t e7 = nvs_get_str(h, "owner_pw_salt", ownerSaltBuf, &ownerSaltLen);
			esp_err_t e8 = nvs_get_str(h, "owner_pw_hash", ownerHashBuf, &ownerHashLen);
			if (e6 == ESP_OK && e7 == ESP_OK && e8 == ESP_OK &&
				ownerUserBuf[0] != '\0' && ownerSaltBuf[0] != '\0' && ownerHashBuf[0] != '\0')
			{
				s.ownerUsername = ownerUserBuf;
				s.ownerPwSalt = ownerSaltBuf;
				s.ownerPwHash = ownerHashBuf;
				s.ownerProvisioned = true;
			}
			nvs_close(h);
		}
#else
		(void)s;
#endif
	}

	// Caller must hold state().mutex.
	bool persistLoginCredentialLocked(const AuthState& s)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open("storage", NVS_READWRITE, &h) != ESP_OK)
		{
			return false;
		}
		bool ok = (nvs_set_str(h, "admin_user", s.username.c_str()) == ESP_OK) &&
		          (nvs_set_str(h, "admin_pw_salt", s.pwSalt.c_str()) == ESP_OK) &&
		          (nvs_set_str(h, "admin_pw_hash", s.pwHash.c_str()) == ESP_OK) &&
		          (nvs_commit(h) == ESP_OK);
		nvs_close(h);
		return ok;
#else
		// Host: the in-memory AuthState IS the store. Nothing else to do.
		(void)s;
		return true;
#endif
	}

	// Caller must hold state().mutex.
	bool persistOwnerCredentialLocked(const AuthState& s)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open("storage", NVS_READWRITE, &h) != ESP_OK)
		{
			return false;
		}
		bool ok = (nvs_set_str(h, "owner_user", s.ownerUsername.c_str()) == ESP_OK) &&
		          (nvs_set_str(h, "owner_pw_salt", s.ownerPwSalt.c_str()) == ESP_OK) &&
		          (nvs_set_str(h, "owner_pw_hash", s.ownerPwHash.c_str()) == ESP_OK) &&
		          (nvs_commit(h) == ESP_OK);
		nvs_close(h);
		return ok;
#else
		(void)s;
		return true;
#endif
	}

	// Caller must hold state().mutex.
	bool persistDtmfPinLocked(const AuthState& s)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open("storage", NVS_READWRITE, &h) != ESP_OK)
		{
			return false;
		}
		bool ok = (nvs_set_str(h, "admin_pin_salt", s.pinSalt.c_str()) == ESP_OK) &&
		          (nvs_set_str(h, "admin_pin_hash", s.pinHash.c_str()) == ESP_OK) &&
		          (nvs_commit(h) == ESP_OK);
		nvs_close(h);
		return ok;
#else
		(void)s;
		return true;
#endif
	}

	// --- Brute-force accounting buckets. Caller must hold state().mutex. ---

	// The bucket for `key`, or nullptr if this client has no history. Read-only:
	// used by isLockedOut(), which must not allocate a slot for a client that has
	// never guessed (otherwise merely asking would evict a real attacker's record).
	AttemptBucket* findBucketLocked(AuthState& s, const std::string& key)
	{
		for (auto& b : s.attempts)
		{
			if (b.used && b.key == key)
			{
				return &b;
			}
		}
		return nullptr;
	}

	// The bucket for `key`, creating one if needed. When the table is full the
	// least-recently-seen entry is reused; a client that keeps guessing keeps
	// touching its bucket, so the entry that gets dropped is always the most
	// stale one. This bounds memory against a flood of spoofed source addresses
	// at the cost of letting a large enough flood eventually recycle a record —
	// an accepted trade on a device whose AP holds ten stations.
	AttemptBucket& acquireBucketLocked(AuthState& s, const std::string& key)
	{
		if (AttemptBucket* existing = findBucketLocked(s, key))
		{
			existing->lastSeenMs = nowMs();
			return *existing;
		}

		AttemptBucket* victim = &s.attempts[0];
		for (auto& b : s.attempts)
		{
			if (!b.used)
			{
				victim = &b;
				break;
			}
			if (b.lastSeenMs < victim->lastSeenMs)
			{
				victim = &b;
			}
		}

		*victim = AttemptBucket{};
		victim->key = key;
		victim->used = true;
		victim->lastSeenMs = nowMs();
		return *victim;
	}

	// Per-CLIENT-bucket half only (no AuthState global triplet touched) — same
	// escalating-backoff shape as recordAttemptLocked's bucket branch below,
	// factored out so authenticate() (issue #173) can update ONLY the bucket
	// it resolved (clientKey+principal) without also mutating the LEGACY
	// shared s.globalFailures/Trips/LockoutUntilMs triplet that
	// verifyCredential()/verifyDtmfPin() own. Sharing that triplet would
	// reopen exactly what (channel, principal) keying is supposed to close:
	// an HTTP login spray engaging the DTMF PIN's lockout and vice versa,
	// and a successful HTTP login silently clearing the DTMF menu's
	// accounting (or the reverse). authenticate() tracks its OWN aggregate
	// backstop per principal instead (AuthState::principalBackstop, updated
	// by its caller after this returns).
	void recordBucketAttemptLocked(AttemptBucket& b, bool ok)
	{
		if (ok)
		{
			b.failures = 0;
			b.trips = 0;
			b.lockoutUntilMs = 0;
			return;
		}
		++b.failures;
		if (b.failures >= AdminAuth::kMaxFailedAttempts)
		{
			++b.trips;
			const int shift = (b.trips - 1 < AdminAuth::kMaxLockoutShift)
				? (b.trips - 1) : AdminAuth::kMaxLockoutShift;
			b.lockoutUntilMs = nowMs() + (AdminAuth::kLockoutMs << shift);
			b.failures = 0;
		}
	}

	// Shared lockout-and-accounting update used by both verifyCredential() and
	// verifyDtmfPin(). Caller must hold state().mutex and have already checked
	// the lockout gates before doing the (expensive) hash comparison; this only
	// updates the bookkeeping once the comparison result (`ok`) is known.
	void recordAttemptLocked(AuthState& s, AttemptBucket& b, bool ok)
	{
		if (ok)
		{
			b.failures = 0;
			b.trips = 0;
			b.lockoutUntilMs = 0;
			// A correct credential proves a legitimate operator is present, so it
			// clears the aggregate backstop too — otherwise a burst of noise from
			// the AP would keep punishing the admin after they had demonstrably
			// arrived.
			s.globalFailures = 0;
			s.globalTrips = 0;
			s.globalLockoutUntilMs = 0;
			return;
		}

		++b.failures;
		++s.globalFailures;
		if (s.globalFailures >= AdminAuth::kMaxFailedAttemptsGlobal)
		{
			++s.globalTrips;
			const int gshift = (s.globalTrips - 1 < AdminAuth::kMaxLockoutShift)
				? (s.globalTrips - 1) : AdminAuth::kMaxLockoutShift;
			s.globalLockoutUntilMs = nowMs() + (AdminAuth::kLockoutMs << gshift);
			s.globalFailures = 0;
		}
		if (b.failures >= AdminAuth::kMaxFailedAttempts)
		{
			// Escalating backoff: keep the trip count and double the cooldown each
			// time, rather than resetting it after every cooldown (which would
			// hand the attacker a fresh kMaxFailedAttempts window forever). Only a
			// correct credential clears it (above).
			++b.trips;
			const int shift = (b.trips - 1 < AdminAuth::kMaxLockoutShift)
				? (b.trips - 1) : AdminAuth::kMaxLockoutShift;
			b.lockoutUntilMs = nowMs() + (AdminAuth::kLockoutMs << shift);
			b.failures = 0;
		}
	}

	// Caller must hold state().mutex.
	void eraseCredentialLocked()
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open("storage", NVS_READWRITE, &h) == ESP_OK)
		{
			nvs_erase_key(h, "admin_user");
			nvs_erase_key(h, "admin_pw_salt");
			nvs_erase_key(h, "admin_pw_hash");
			nvs_erase_key(h, "admin_pin_salt");
			nvs_erase_key(h, "admin_pin_hash");
			nvs_erase_key(h, "owner_user");
			nvs_erase_key(h, "owner_pw_salt");
			nvs_erase_key(h, "owner_pw_hash");
			nvs_commit(h);
			nvs_close(h);
		}
#endif
	}
}

namespace AdminAuth
{
	bool isProvisioned()
	{
		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadCredentialLocked(s);
		return s.provisioned;
	}

	bool needsInitialSetup()
	{
		return !isProvisioned();
	}

	bool setLoginCredential(const std::string& username, const std::string& password)
	{
		if (!usernameValid(username) || !passwordValid(password))
		{
			return false;
		}

		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadCredentialLocked(s);

		// Issue #173: the collision guard must be symmetric with
		// setOwnerCredential()'s (found in review) — a sysop renaming
		// themselves to the owner's username would route their own logins to
		// the owner bucket/principal and lock the real sysop identity out,
		// the same ambiguity setOwnerCredential() already refuses in the
		// other direction.
		if (s.ownerProvisioned && username == s.ownerUsername)
		{
			return false;
		}

		std::string salt = randomHex(32);   // 128-bit salt
		if (salt.empty())
		{
			return false;
		}
		std::string hash = hashSecret(salt, password);

		std::string prevUsername = s.username;
		std::string prevSalt = s.pwSalt;
		std::string prevHash = s.pwHash;
		bool        prevProvisioned = s.provisioned;

		s.username = username;
		s.pwSalt = salt;
		s.pwHash = hash;
		s.provisioned = true;

		if (!persistLoginCredentialLocked(s))
		{
			// Roll back the in-memory state if persistence failed.
			s.username = prevUsername;
			s.pwSalt = prevSalt;
			s.pwHash = prevHash;
			s.provisioned = prevProvisioned;
			return false;
		}

		// A credential (re)set clears brute-force accounting for every client
		// (shared table — also affects the DTMF PIN's accounting, which is
		// fine: whoever just authenticated to change the login credential has
		// already proven themselves).
		s.attempts = {};
		s.globalFailures = 0;
		s.globalTrips = 0;
		s.globalLockoutUntilMs = 0;
		return true;
	}

	bool isLockedOut()
	{
		return isLockedOut(std::string());
	}

	bool isLockedOut(const std::string& clientKey)
	{
		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		const uint64_t now = nowMs();
		if (s.globalLockoutUntilMs != 0 && now < s.globalLockoutUntilMs)
		{
			return true;   // aggregate backstop is engaged: everyone waits
		}
		AttemptBucket* b = findBucketLocked(s, clientKey);
		return b != nullptr && b->lockoutUntilMs != 0 && now < b->lockoutUntilMs;
	}

	bool verifyCredential(const std::string& username, const std::string& password,
		const std::string& clientKey)
	{
		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadCredentialLocked(s);

		AttemptBucket& b = acquireBucketLocked(s, clientKey);

		// Honor this client's lockout — and the aggregate backstop — without
		// hashing while either is engaged.
		if (b.lockoutUntilMs != 0 && nowMs() < b.lockoutUntilMs)
		{
			return false;
		}
		if (s.globalLockoutUntilMs != 0 && nowMs() < s.globalLockoutUntilMs)
		{
			return false;
		}

		bool ok;
		if (!s.provisioned)
		{
			// No real credential has ever been set: only the well-known default
			// verifies. Still subject to the same lockout accounting below — the
			// default is not a bypass of brute-force protection, and once
			// setLoginCredential() runs this branch never executes again.
			ok = (username == kDefaultUsername) && (password == kDefaultPassword);
		}
		else
		{
			// Compute the password hash unconditionally (even if the username is
			// already wrong) so a wrong username costs the same wall-clock time
			// as a wrong password — no timing signal on which one was correct.
			bool userOk = constantTimeEquals(username, s.username);
			std::string candidate = hashSecret(s.pwSalt, password);
			bool passOk = constantTimeEquals(candidate, s.pwHash);
			ok = userOk && passOk;
		}

		recordAttemptLocked(s, b, ok);
		return ok;
	}

	// ── Issue #173: two-role privilege model ──────────────────────────────────

	bool isOwnerProvisioned()
	{
		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadCredentialLocked(s);
		return s.ownerProvisioned;
	}

	bool setOwnerCredential(const std::string& username, const std::string& password)
	{
		if (!usernameValid(username) || !passwordValid(password))
		{
			return false;
		}

		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadCredentialLocked(s);

		// The two principals must be distinguishable — see authenticate()'s
		// principal-selection comment for why a shared username would make
		// lockout accounting and "which role did I just log in as" both
		// ambiguous. Compared as stored (case-sensitive), same as every other
		// identity string in this file.
		if (username == s.username)
		{
			return false;
		}

		std::string salt = randomHex(32);
		if (salt.empty())
		{
			return false;
		}
		std::string hash = hashSecret(salt, password);

		std::string prevUsername = s.ownerUsername;
		std::string prevSalt = s.ownerPwSalt;
		std::string prevHash = s.ownerPwHash;
		bool        prevProvisioned = s.ownerProvisioned;

		s.ownerUsername = username;
		s.ownerPwSalt = salt;
		s.ownerPwHash = hash;
		s.ownerProvisioned = true;

		if (!persistOwnerCredentialLocked(s))
		{
			s.ownerUsername = prevUsername;
			s.ownerPwSalt = prevSalt;
			s.ownerPwHash = prevHash;
			s.ownerProvisioned = prevProvisioned;
			return false;
		}

		// Same "a credential (re)set clears brute-force accounting" contract as
		// setLoginCredential() — whoever just authenticated to set this has
		// already proven themselves. Clears BOTH principals' buckets (the shared
		// table has no cheap way to clear just one, and there is no security
		// cost to clearing early: it only ever HELPS a legitimate operator).
		s.attempts = {};
		s.globalFailures = 0;
		s.globalTrips = 0;
		s.globalLockoutUntilMs = 0;
		s.principalBackstop = {};
		return true;
	}

	Role authenticate(const std::string& username, const std::string& password,
		const std::string& clientKey)
	{
		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadCredentialLocked(s);

		// Resolve the principal from the SUBMITTED username (public information
		// on the wire either way) before touching any lockout state, so the
		// bucket a failed attempt is charged against is deterministic and an
		// attacker cannot smuggle an owner-bucket guess into the sysop bucket
		// (or vice versa) by lying about which principal they meant.
		const bool ownerAttempt = s.ownerProvisioned && username == s.ownerUsername;
		const Role principal = ownerAttempt ? Role::Owner : Role::Sysop;
		const std::string bucketKey = clientKey + "\x1f" + principalName(principal);

		AttemptBucket& b = acquireBucketLocked(s, bucketKey);
		GlobalBackstop& gb = s.principalBackstop[principalIndex(principal)];

		if (b.lockoutUntilMs != 0 && nowMs() < b.lockoutUntilMs)
		{
			return Role::None;
		}
		if (gb.lockoutUntilMs != 0 && nowMs() < gb.lockoutUntilMs)
		{
			return Role::None;
		}

		bool ok;
		if (ownerAttempt)
		{
			bool userOk = constantTimeEquals(username, s.ownerUsername);
			std::string candidate = hashSecret(s.ownerPwSalt, password);
			bool passOk = constantTimeEquals(candidate, s.ownerPwHash);
			ok = userOk && passOk;
		}
		else if (!s.provisioned)
		{
			// No real sysop credential has ever been set: only the well-known
			// default verifies — identical branch to verifyCredential()'s.
			ok = (username == kDefaultUsername) && (password == kDefaultPassword);
		}
		else
		{
			bool userOk = constantTimeEquals(username, s.username);
			std::string candidate = hashSecret(s.pwSalt, password);
			bool passOk = constantTimeEquals(candidate, s.pwHash);
			ok = userOk && passOk;
		}

		// Bucket-only accounting (see recordBucketAttemptLocked's comment for
		// why this must NOT be recordAttemptLocked: that helper also writes
		// AuthState's single legacy global triplet, which verifyCredential()/
		// verifyDtmfPin() own — reusing it here would leak an HTTP-login spray
		// into the DTMF PIN's lockout state and back, defeating the whole
		// point of per-principal keying).
		recordBucketAttemptLocked(b, ok);
		// This principal's OWN aggregate backstop, independent of the legacy
		// shared one.
		if (ok)
		{
			gb.failures = 0;
			gb.trips = 0;
			gb.lockoutUntilMs = 0;
		}
		else
		{
			++gb.failures;
			if (gb.failures >= kMaxFailedAttemptsGlobal)
			{
				++gb.trips;
				const int shift = (gb.trips - 1 < kMaxLockoutShift) ? (gb.trips - 1) : kMaxLockoutShift;
				gb.lockoutUntilMs = nowMs() + (kLockoutMs << shift);
				gb.failures = 0;
			}
		}

		return ok ? principal : Role::None;
	}

	bool isLockedOutForAuth(const std::string& username, const std::string& clientKey)
	{
		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadCredentialLocked(s);

		const bool ownerAttempt = s.ownerProvisioned && username == s.ownerUsername;
		const Role principal = ownerAttempt ? Role::Owner : Role::Sysop;
		const std::string bucketKey = clientKey + "\x1f" + principalName(principal);
		const uint64_t now = nowMs();

		const GlobalBackstop& gb = s.principalBackstop[principalIndex(principal)];
		if (gb.lockoutUntilMs != 0 && now < gb.lockoutUntilMs)
		{
			return true;
		}
		AttemptBucket* b = findBucketLocked(s, bucketKey);
		return b != nullptr && b->lockoutUntilMs != 0 && now < b->lockoutUntilMs;
	}

	Role sessionRole(const std::string& token)
	{
		if (token.empty())
		{
			return Role::None;
		}

		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);

		const uint64_t now = nowMs();
		for (auto& sess : s.sessions)
		{
			if (!sess.used) continue;
			if (sess.expiresAtMs != 0 && now >= sess.expiresAtMs) continue;
			if (constantTimeEquals(sess.token, token))
			{
				return sess.role;
			}
		}
		return Role::None;
	}

	bool sessionSatisfiesRole(const std::string& token, Role need)
	{
		Role got = sessionRole(token);
		if (got == Role::None)
		{
			return false;
		}
		if (need == Role::Owner && got != Role::Owner)
		{
			// No-owner fallback: see this function's declaration comment.
			return !isOwnerProvisioned();
		}
		return true;   // Sysop-gated action, or already Owner.
	}

	bool dtmfPinIsSet()
	{
		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadCredentialLocked(s);
		return s.dtmfPinSet;
	}

	bool setDtmfPin(const std::string& pin)
	{
		if (!dtmfPinValid(pin))
		{
			return false;
		}

		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadCredentialLocked(s);

		std::string salt = randomHex(32);
		if (salt.empty())
		{
			return false;
		}
		std::string hash = hashSecret(salt, pin);

		std::string prevSalt = s.pinSalt;
		std::string prevHash = s.pinHash;
		bool        prevSet = s.dtmfPinSet;

		s.pinSalt = salt;
		s.pinHash = hash;
		s.dtmfPinSet = true;

		if (!persistDtmfPinLocked(s))
		{
			s.pinSalt = prevSalt;
			s.pinHash = prevHash;
			s.dtmfPinSet = prevSet;
			return false;
		}

		s.attempts = {};
		s.globalFailures = 0;
		s.globalTrips = 0;
		s.globalLockoutUntilMs = 0;
		return true;
	}

	bool verifyDtmfPin(const std::string& pin)
	{
		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		loadCredentialLocked(s);

		if (!s.dtmfPinSet)
		{
			return false;
		}

		AttemptBucket& b = acquireBucketLocked(s, std::string());

		if (b.lockoutUntilMs != 0 && nowMs() < b.lockoutUntilMs)
		{
			return false;
		}
		if (s.globalLockoutUntilMs != 0 && nowMs() < s.globalLockoutUntilMs)
		{
			return false;
		}

		std::string candidate = hashSecret(s.pinSalt, pin);
		bool ok = constantTimeEquals(candidate, s.pinHash);

		recordAttemptLocked(s, b, ok);
		return ok;
	}

	std::string createSession(Role role)
	{
		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);

		std::string token = randomHex(kSessionTokenHex);
		if (token.empty())
		{
			return "";
		}

		uint64_t now = nowMs();

		// Find a free slot: prefer an unused one, else an expired one, else the
		// soonest-to-expire (evict the oldest).
		size_t slot = 0;
		bool found = false;
		uint64_t earliestExpiry = UINT64_MAX;
		for (size_t i = 0; i < s.sessions.size(); ++i)
		{
			Session& sess = s.sessions[i];
			if (!sess.used || (sess.expiresAtMs != 0 && now >= sess.expiresAtMs))
			{
				slot = i;
				found = true;
				break;
			}
			if (sess.expiresAtMs < earliestExpiry)
			{
				earliestExpiry = sess.expiresAtMs;
				slot = i;
			}
		}
		(void)found;

		s.sessions[slot].token = token;
		s.sessions[slot].csrf = randomHex(kCsrfTokenHex);
		s.sessions[slot].expiresAtMs = now + kSessionTtlMs;
		s.sessions[slot].used = true;
		s.sessions[slot].role = role;
		return token;
	}

	bool validateSession(const std::string& token)
	{
		if (token.empty())
		{
			return false;
		}

		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);

		uint64_t now = nowMs();
		for (auto& sess : s.sessions)
		{
			if (!sess.used)
			{
				continue;
			}
			if (sess.expiresAtMs != 0 && now >= sess.expiresAtMs)
			{
				// Lazily reap expired sessions.
				sess.used = false;
				sess.token.clear();
				sess.csrf.clear();
				sess.expiresAtMs = 0;
				continue;
			}
			// Constant-time compare against each live token.
			if (constantTimeEquals(sess.token, token))
			{
				// Sliding expiry: an actively-used session is kept alive. Each
				// successful validation pushes the absolute deadline out by the
				// full TTL so a working admin isn't logged out mid-session.
				sess.expiresAtMs = now + AdminAuth::kSessionTtlMs;
				return true;
			}
		}
		return false;
	}

	void destroySession(const std::string& token)
	{
		if (token.empty())
		{
			return;
		}

		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);

		for (auto& sess : s.sessions)
		{
			if (sess.used && constantTimeEquals(sess.token, token))
			{
				sess.used = false;
				sess.token.clear();
				sess.csrf.clear();
				sess.expiresAtMs = 0;
			}
		}
	}

	void clearCredential()
	{
		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);

		eraseCredentialLocked();

		s.username.clear();
		s.pwSalt.clear();
		s.pwHash.clear();
		s.provisioned = false;
		s.ownerUsername.clear();
		s.ownerPwSalt.clear();
		s.ownerPwHash.clear();
		s.ownerProvisioned = false;
		s.pinSalt.clear();
		s.pinHash.clear();
		s.dtmfPinSet = false;
		s.loaded = true;          // we know the (now empty) state; don't reload
		s.attempts = {};
		s.globalFailures = 0;
		s.globalTrips = 0;
		s.globalLockoutUntilMs = 0;
		s.principalBackstop = {};

		for (auto& sess : s.sessions)
		{
			sess.used = false;
			sess.token.clear();
			sess.csrf.clear();
			sess.expiresAtMs = 0;
		}
	}

	std::string sessionCsrf(const std::string& token)
	{
		if (token.empty())
		{
			return "";
		}

		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);

		uint64_t now = nowMs();
		for (auto& sess : s.sessions)
		{
			if (!sess.used)
			{
				continue;
			}
			if (sess.expiresAtMs != 0 && now >= sess.expiresAtMs)
			{
				continue;
			}
			if (constantTimeEquals(sess.token, token))
			{
				return sess.csrf;
			}
		}
		return "";
	}

	bool validateCsrf(const std::string& token, const std::string& csrf)
	{
		if (csrf.empty())
		{
			return false;
		}
		const std::string want = sessionCsrf(token);
		if (want.empty())
		{
			return false;
		}
		return constantTimeEquals(want, csrf);
	}

	uint64_t sessionRemainingMs(const std::string& token)
	{
		if (token.empty())
		{
			return 0;
		}

		AuthState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);

		const uint64_t now = nowMs();
		for (auto& sess : s.sessions)
		{
			if (!sess.used)
			{
				continue;
			}
			if (sess.expiresAtMs != 0 && now >= sess.expiresAtMs)
			{
				continue;
			}
			if (constantTimeEquals(sess.token, token))
			{
				return (sess.expiresAtMs == 0) ? 0 : (sess.expiresAtMs - now);
			}
		}
		return 0;
	}

	// credentialIsSet: lightweight NVS probe used by the boot provisioning gate.
	// Opens NVS namespace "storage", reads key "admin_pw_hash" as a string, and
	// returns true iff the string is non-empty. Closes the handle on exit.
	// On non-ESP builds it delegates to the in-memory isProvisioned() so the
	// host unit tests exercise the same logic path.
	bool credentialIsSet()
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		nvs_handle_t h;
		if (nvs_open("storage", NVS_READONLY, &h) != ESP_OK)
		{
			return false;
		}
		char hashBuf[128] = {0};
		size_t hashLen = sizeof(hashBuf);
		esp_err_t err = nvs_get_str(h, "admin_pw_hash", hashBuf, &hashLen);
		nvs_close(h);
		return (err == ESP_OK && hashBuf[0] != '\0');
#else
		return isProvisioned();
#endif
	}

	// ── Issue #186: password-based sealing (PBKDF2-HMAC-SHA256, AES-256-GCM) ──
	// Pure functions, no shared state — see AdminAuth.hpp for the contract.

	void secureRandomBytes(uint8_t* buf, size_t len)
	{
		fillRandom(buf, len);
	}

	bool pbkdf2Sha256(const std::string& password, const uint8_t* salt, size_t saltLen,
		uint32_t iterations, uint8_t* out, size_t dkLen)
	{
		if (iterations == 0 || dkLen == 0)
		{
			return false;
		}

		constexpr size_t kHLen = 32;
		const uint32_t numBlocks = static_cast<uint32_t>((dkLen + kHLen - 1) / kHLen);

		std::vector<uint8_t> saltAndIndex(salt, salt + saltLen);
		saltAndIndex.resize(saltLen + 4);

		size_t written = 0;
		for (uint32_t i = 1; i <= numBlocks; ++i)
		{
			saltAndIndex[saltLen + 0] = static_cast<uint8_t>((i >> 24) & 0xFF);
			saltAndIndex[saltLen + 1] = static_cast<uint8_t>((i >> 16) & 0xFF);
			saltAndIndex[saltLen + 2] = static_cast<uint8_t>((i >> 8) & 0xFF);
			saltAndIndex[saltLen + 3] = static_cast<uint8_t>(i & 0xFF);

			auto u = hmacSha256(reinterpret_cast<const uint8_t*>(password.data()), password.size(),
				saltAndIndex.data(), saltAndIndex.size());
			auto t = u;
			for (uint32_t c = 1; c < iterations; ++c)
			{
				u = hmacSha256(reinterpret_cast<const uint8_t*>(password.data()), password.size(),
					u.data(), u.size());
				for (size_t j = 0; j < kHLen; ++j) t[j] = static_cast<uint8_t>(t[j] ^ u[j]);
			}

			size_t take = (dkLen - written < kHLen) ? (dkLen - written) : kHLen;
			std::copy(t.begin(), t.begin() + static_cast<long>(take), out + written);
			written += take;
		}
		return true;
	}

	void aesGcmSeal(const uint8_t key[kAesKeyBytes], const uint8_t nonce[kGcmNonceBytes],
		const std::string& aad, const std::string& plaintext, std::string& outCiphertext)
	{
		AesKeySchedule ks;
		aesKeyExpansion(key, ks);

		// H = E(K, 0^128); J0 = nonce || 0^31 || 1 (the 96-bit-IV case).
		uint8_t zero[16] = {0};
		uint8_t h[16];
		aesEncryptBlock(ks, zero, h);

		uint8_t j0[16] = {0};
		for (int i = 0; i < 12; ++i) j0[i] = nonce[i];
		j0[15] = 0x01;

		std::vector<uint8_t> ct(plaintext.size());
		uint8_t counter[16];
		for (int i = 0; i < 16; ++i) counter[i] = j0[i];
		gcmIncCounter(counter);   // keystream starts at inc32(J0)
		gcmCtrXor(ks, counter, reinterpret_cast<const uint8_t*>(plaintext.data()),
			ct.data(), plaintext.size());

		GhashState g;
		for (int i = 0; i < 16; ++i) g.h[i] = h[i];
		ghashUpdateBytes(g, reinterpret_cast<const uint8_t*>(aad.data()), aad.size());
		ghashUpdateBytes(g, ct.data(), ct.size());
		uint8_t lenBlock[16] = {0};
		writeBe64(lenBlock + 0, static_cast<uint64_t>(aad.size()) * 8ull);
		writeBe64(lenBlock + 8, static_cast<uint64_t>(ct.size()) * 8ull);
		ghashUpdateBlock(g, lenBlock);

		uint8_t tag[16];
		aesEncryptBlock(ks, j0, tag);   // E(K, J0)
		for (int i = 0; i < 16; ++i) tag[i] = static_cast<uint8_t>(tag[i] ^ g.y[i]);

		outCiphertext.assign(reinterpret_cast<const char*>(ct.data()), ct.size());
		outCiphertext.append(reinterpret_cast<const char*>(tag), sizeof(tag));
	}

	bool aesGcmOpen(const uint8_t key[kAesKeyBytes], const uint8_t nonce[kGcmNonceBytes],
		const std::string& aad, const std::string& ciphertextAndTag, std::string& outPlaintext)
	{
		if (ciphertextAndTag.size() < kGcmTagBytes)
		{
			return false;
		}
		const size_t ctLen = ciphertextAndTag.size() - kGcmTagBytes;
		const uint8_t* ct = reinterpret_cast<const uint8_t*>(ciphertextAndTag.data());
		const uint8_t* tagIn = ct + ctLen;

		AesKeySchedule ks;
		aesKeyExpansion(key, ks);

		uint8_t zero[16] = {0};
		uint8_t h[16];
		aesEncryptBlock(ks, zero, h);

		uint8_t j0[16] = {0};
		for (int i = 0; i < 12; ++i) j0[i] = nonce[i];
		j0[15] = 0x01;

		GhashState g;
		for (int i = 0; i < 16; ++i) g.h[i] = h[i];
		ghashUpdateBytes(g, reinterpret_cast<const uint8_t*>(aad.data()), aad.size());
		ghashUpdateBytes(g, ct, ctLen);
		uint8_t lenBlock[16] = {0};
		writeBe64(lenBlock + 0, static_cast<uint64_t>(aad.size()) * 8ull);
		writeBe64(lenBlock + 8, static_cast<uint64_t>(ctLen) * 8ull);
		ghashUpdateBlock(g, lenBlock);

		uint8_t expectedTag[16];
		aesEncryptBlock(ks, j0, expectedTag);
		for (int i = 0; i < 16; ++i) expectedTag[i] = static_cast<uint8_t>(expectedTag[i] ^ g.y[i]);

		// Constant-time tag compare — a timing side-channel here would leak how
		// many leading tag bytes matched, which is exactly the oracle GCM's
		// authentication is supposed to deny an attacker.
		unsigned char diff = 0;
		for (int i = 0; i < 16; ++i)
		{
			diff = static_cast<unsigned char>(diff | (expectedTag[i] ^ tagIn[i]));
		}
		if (diff != 0)
		{
			return false;   // wrong password and a tampered blob look identical here
		}

		std::vector<uint8_t> pt(ctLen);
		uint8_t counter[16];
		for (int i = 0; i < 16; ++i) counter[i] = j0[i];
		gcmIncCounter(counter);
		gcmCtrXor(ks, counter, ct, pt.data(), ctLen);

		outPlaintext.assign(reinterpret_cast<const char*>(pt.data()), pt.size());
		return true;
	}
}

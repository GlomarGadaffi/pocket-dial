// TelephonyStaging_test.cpp -- #997: the telephony API config's NVS write leaves
// RequestsHandler::_mutex, and the client secret never goes with it.
//
// TelephonyApiConfig::persist() used to run 25 nvs_set_* and a commit (4 slots x
// 6 keys + `active`) with the engine lock held. It now copies every field EXCEPT
// the client secret into the NVS writer's Key::Telephony staging slot and returns;
// the nvs_writer task applies the snapshot with TelephonyApiConfig::writeSnapshot()
// into the same keys. The secret is written separately, synchronously, only when it
// changed, so it is never in the staging slot, the queue item or the writer's
// scratch (none of which is zeroised). The writer does not exist on the host, so
// these tests play it: nvswriter::drainForTest() takes what was staged and
// TelephonyApiConfig::emitSnapshot() -- the walk writeSnapshot() makes, with the put
// callbacks in place of nvs_set_* -- records the (key, value) pairs.
//
// Every "the secret is not in X" check is paired with a "the client id IS in X"
// check on the same buffers: without the pairing a tree that stages nothing passes
// the absence check, which is exactly what main did.
//
// The board-only half (the nvs_* calls, the fourth slot and queue, who calls what
// under which lock) is pinned by tests/tools/test_telephony_staging_wiring.py.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "NvsWriter.hpp"
#include "RequestsHandler.hpp"
#include "ResetGuard.hpp"
#include "SipMessage.hpp"
#include "TelephonyApiConfig.hpp"
#include "TelephonyProvider.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

using nvswriter::Key;

static_assert(TelephonyApiConfig::kSlots == 4, "the literal expectations below spell out four slots");
static_assert(TelephonyApiConfig::kMaxUrlLen == 128, "the long-value tests use the 128-character URL cap");
static_assert(TelephonyApiConfig::kSnapshotLen == 4 * (2 + 3 * 129) + 1, "type, enabled, three 129-byte cells per slot, then active");
static_assert(nvswriter::kKeyCount == 4, "devices, forwards, DID table, telephony");

namespace
{
	constexpr const char* kSecret = "S3CR3T-sentinel-5c1f9a77d0";
	constexpr const char* kSecret2 = "ROTATED-sentinel-aa90e3b1";
	constexpr const char* kClientId = "CLIENT-visible-4e2b";
	constexpr unsigned kAll = nvswriter::InSlot | nvswriter::InQueue | nvswriter::InScratch;

	using Pairs = std::vector<std::pair<std::string, std::string>>;

	// What a walk of one staged snapshot produced, with the numeric keys in decimal.
	struct Walk
	{
		unsigned telephonyWrites = 0;   // times the writer was handed a telephony snapshot
		unsigned otherWrites = 0;       // writes for any other key
		bool wellFormed = true;         // the snapshot passed emitSnapshot()'s checks
		Pairs pairs;                    // the last snapshot's walk
	};

	// One writer pass.
	Walk drain()
	{
		Walk d;
		nvswriter::drainForTest([&](Key k, const char* p, size_t n) {
			if (k != Key::Telephony)
			{
				++d.otherWrites;
				return true;
			}
			++d.telephonyWrites;
			d.pairs.clear();
			d.wellFormed = TelephonyApiConfig::emitSnapshot(p, n,
				[&](const char* key, uint8_t v) { d.pairs.emplace_back(key, std::to_string(v)); return true; },
				[&](const char* key, const char* v) { d.pairs.emplace_back(key, v); return true; });
			return d.wellFormed;
		});
		return d;
	}

	using Pair = std::pair<std::string, std::string>;

	// The last / i-th pair of a walk, or a marker when the walk is shorter: a tree that stages nothing
	// must fail these comparisons, not read past the end of an empty vector.
	Pair lastOf(const Walk& d) { return d.pairs.empty() ? Pair("<no pairs>", "") : d.pairs.back(); }
	Pair pairAt(const Walk& d, size_t i) { return i < d.pairs.size() ? d.pairs[i] : Pair("<no pair>", ""); }

	unsigned where(const char* needle) { return nvswriter::buffersHoldingForTest(needle); }

	std::string stagedTel() { return std::string(nvswriter::stagedForTest(Key::Telephony)); }

	std::string slurp(const std::string& path)
	{
		std::ifstream f(path, std::ios::binary);
		return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
	}

	TelephonyApiConfig::Slot realSlot(const char* secret)
	{
		TelephonyApiConfig::Slot s;
		s.type = TelephonyProviderType::Telephony;
		s.enabled = true;
		s.baseUrl = "https://pbx.example.invalid";
		s.clientId = kClientId;
		s.secret = secret;
		s.routeDn = "100";
		return s;
	}

	// The default (never-used) slot, as the walk spells it.
	void unusedSlot(Pairs& out, size_t i)
	{
		const std::string p = "s" + std::to_string(i);
		out.emplace_back(p + "type", "0");
		out.emplace_back(p + "en", "0");
		out.emplace_back(p + "url", "");
		out.emplace_back(p + "id", "");
		out.emplace_back(p + "dn", "");
	}

	class TelephonyStaging : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			resetguard::resetForTest();
			nvswriter::resetForTest();
			const std::string name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
			_path = "test_telstage_" + name + ".cfg";
			_path2 = "test_telstage2_" + name + ".cfg";
			std::remove(_path.c_str());
			std::remove(_path2.c_str());
			_cfg.setStorePath(_path);
			_cfg.load();
			nvswriter::resetForTest();
		}
		void TearDown() override
		{
			std::remove(_path.c_str());
			std::remove(_path2.c_str());
			nvswriter::resetForTest();
			resetguard::resetForTest();
		}

		TelephonyApiConfig _cfg;
		std::string _path;
		std::string _path2;
	};
}

TEST_F(TelephonyStaging, SetSlotStagesEveryFieldButTheSecretUnderTheOldKeys)
{
	ASSERT_EQ(_cfg.setSlot(1, realSlot(kSecret), /*keepSecret=*/false), "");
	EXPECT_EQ(nvswriter::stats().staged, 1u);
	EXPECT_EQ(stagedTel().size(), TelephonyApiConfig::kSnapshotLen);

	const Walk d = drain();
	EXPECT_EQ(d.telephonyWrites, 1u);
	EXPECT_EQ(d.otherWrites, 0u);
	ASSERT_TRUE(d.wellFormed);

	// Spelled out: the keys and values the old persist() handed nvs_set_*, in its
	// order, with the four `s<i>sec` sets gone.
	const Pairs want = {
		{"s0type", "0"}, {"s0en", "0"}, {"s0url", ""}, {"s0id", ""}, {"s0dn", ""},
		{"s1type", "1"}, {"s1en", "1"}, {"s1url", "https://pbx.example.invalid"}, {"s1id", kClientId}, {"s1dn", "100"},
		{"s2type", "0"}, {"s2en", "0"}, {"s2url", ""}, {"s2id", ""}, {"s2dn", ""},
		{"s3type", "0"}, {"s3en", "0"}, {"s3url", ""}, {"s3id", ""}, {"s3dn", ""},
		{"active", "255"},
	};
	EXPECT_EQ(d.pairs, want);
	for (const auto& kv : d.pairs)
	{
		EXPECT_EQ(kv.first.find("sec"), std::string::npos) << "the writer must never build a secret key: " << kv.first;
		EXPECT_EQ(kv.second.find("S3CR3T"), std::string::npos) << kv.first;
	}
	EXPECT_EQ(nvswriter::stats().written, 1u);
}

TEST_F(TelephonyStaging, TheActiveSlotIsStagedAndAnUnusedOneIsNone)
{
	ASSERT_EQ(_cfg.setSlot(2, realSlot(kSecret), false), "");
	ASSERT_EQ(_cfg.setActiveSlot(2), "");
	const Walk d = drain();
	ASSERT_EQ(d.telephonyWrites, 1u) << "two changes, one write: the newest snapshot";
	EXPECT_EQ(lastOf(d), (Pair{"active", "2"}));

	ASSERT_EQ(_cfg.setActiveSlot(TelephonyApiConfig::kNoActiveSlot), "");
	EXPECT_EQ(lastOf(drain()), (Pair{"active", "255"}));
}

TEST_F(TelephonyStaging, TheSecretIsInNoWriterBufferAfterAWriteAWriterPassOrAnotherWrite)
{
	ASSERT_EQ(_cfg.setSlot(1, realSlot(kSecret), false), "");
	ASSERT_GE(nvswriter::stats().staged, 1u) << "nothing staged means the scans below prove nothing";

	// Staged and waiting: the client id is in the slot and the queue item, the secret in neither,
	// and the scratch has not been touched yet.
	EXPECT_EQ(where(kClientId), nvswriter::InSlot | nvswriter::InQueue);
	EXPECT_EQ(where(kSecret), 0u);
	EXPECT_EQ(where("S3CR3T"), 0u) << "not even a prefix of it";

	// The writer has taken it: its scratch holds a copy of the item, and still no secret.
	ASSERT_EQ(drain().telephonyWrites, 1u);
	EXPECT_EQ(where(kClientId), kAll);
	EXPECT_EQ(where(kSecret), 0u);
	EXPECT_EQ(where("S3CR3T"), 0u);

	// A new secret, and then the slot cleared: neither the old nor the new one shows up anywhere.
	ASSERT_EQ(_cfg.setSlot(1, realSlot(kSecret2), false), "");
	EXPECT_EQ(where(kClientId), kAll);
	EXPECT_EQ(where(kSecret2), 0u);
	EXPECT_EQ(where(kSecret), 0u);
	ASSERT_EQ(drain().telephonyWrites, 1u);
	ASSERT_EQ(_cfg.clearSlot(1), "");
	ASSERT_EQ(drain().telephonyWrites, 1u);
	EXPECT_EQ(where(kSecret2), 0u);
	EXPECT_EQ(where(kSecret), 0u);
	EXPECT_EQ(where("ROTATED"), 0u);
}

TEST_F(TelephonyStaging, ASnapshotDiscardedByAResetLeavesNoSecretEither)
{
	ASSERT_EQ(_cfg.setSlot(1, realSlot(kSecret), false), "");
	ASSERT_EQ(where(kClientId), nvswriter::InSlot | nvswriter::InQueue);
	resetguard::begin();   // the reset opens between the stage and the writer's pass

	const Walk d = drain();
	EXPECT_EQ(d.telephonyWrites, 0u) << "the writer refuses data during a reset like any NVS writer";
	EXPECT_EQ(nvswriter::stats().suppressed, 1u);
	EXPECT_EQ(nvswriter::stats().written, 0u);
	EXPECT_TRUE(stagedTel().empty()) << "...and does not keep it for later";
	// The discarded item was still copied into the scratch before the writer looked at the reset flag:
	// the scan sees that copy (the pairing), and the secret is not in it.
	EXPECT_EQ(where(kClientId), kAll);
	EXPECT_EQ(where(kSecret), 0u);
	EXPECT_EQ(where("S3CR3T"), 0u);
}

TEST_F(TelephonyStaging, ASecretIsWrittenOnlyWhenItChanged)
{
	ASSERT_EQ(_cfg.secretWrites(), 0u);

	ASSERT_EQ(_cfg.setSlot(0, realSlot(kSecret), false), "");
	EXPECT_EQ(_cfg.secretWrites(), 1u) << "a new secret is written";
	EXPECT_FALSE(_cfg.secretPending(0));

	TelephonyApiConfig::Slot edit = realSlot("");
	edit.routeDn = "200";
	ASSERT_EQ(_cfg.setSlot(0, edit, /*keepSecret=*/true), "");
	EXPECT_EQ(_cfg.secretWrites(), 1u) << "an edit that keeps the secret writes none";

	ASSERT_EQ(_cfg.setSlot(0, realSlot(kSecret), false), "");
	EXPECT_EQ(_cfg.secretWrites(), 1u) << "saving the same value again is not a change";

	ASSERT_EQ(_cfg.setActiveSlot(0), "");
	EXPECT_EQ(_cfg.secretWrites(), 1u);

	ASSERT_EQ(_cfg.setSlot(0, realSlot(kSecret2), false), "");
	EXPECT_EQ(_cfg.secretWrites(), 2u) << "a different value is a change";

	ASSERT_EQ(_cfg.clearSlot(1), "");
	EXPECT_EQ(_cfg.secretWrites(), 2u) << "clearing a slot that never had a secret writes none";
	ASSERT_EQ(_cfg.clearSlot(0), "");
	EXPECT_EQ(_cfg.secretWrites(), 3u) << "clearing one that had a secret erases it, synchronously";
	EXPECT_FALSE(_cfg.secretPending(0));

	EXPECT_EQ(nvswriter::stats().staged, 7u) << "every one of those still staged the table; only the secret write is conditional";
}

#if !defined(_WIN32)
TEST_F(TelephonyStaging, AChangedSecretIsRetriedAfterAFailedWrite)
{
	// The store cannot be opened: the secret write fails.
	_cfg.setStorePath("test_telstage_no_such_dir_997/tapi.cfg");
	EXPECT_NE(_cfg.setSlot(0, realSlot(kSecret), false), "");
	EXPECT_TRUE(_cfg.secretPending(0)) << "a write that failed is still owed";
	EXPECT_EQ(_cfg.secretWrites(), 0u);
	EXPECT_TRUE(_cfg.view(0).secretSet) << "live in RAM either way";

	// Same value again: a comparison against the live value would call it unchanged and skip it forever.
	_cfg.setStorePath(_path);
	EXPECT_EQ(_cfg.setSlot(0, realSlot(kSecret), false), "");
	EXPECT_EQ(_cfg.secretWrites(), 1u);
	EXPECT_FALSE(_cfg.secretPending(0));
	EXPECT_NE(slurp(_path).find(kSecret), std::string::npos) << "the host store carries the secret";
}

TEST_F(TelephonyStaging, ARefusedStageWritesNeitherPartAndKeepsTheSecretPending)
{
	resetguard::begin();
	const std::string err = _cfg.setSlot(0, realSlot(kSecret), false);
	EXPECT_NE(err.find("factory reset"), std::string::npos) << err;
	EXPECT_EQ(nvswriter::stats().suppressed, 1u);
	EXPECT_EQ(nvswriter::stats().staged, 0u);
	EXPECT_TRUE(stagedTel().empty());
	EXPECT_TRUE(slurp(_path).empty()) << "a refused stage means no write at all: the secret is not written alone";
	EXPECT_EQ(_cfg.secretWrites(), 0u);
	EXPECT_TRUE(_cfg.secretPending(0)) << "...it is still owed";
	EXPECT_TRUE(_cfg.view(0).secretSet) << "only the flash copy is refused";
	EXPECT_EQ(where(kSecret), 0u);

	// The next accepted persist pays what is owed.
	resetguard::resetForTest();
	EXPECT_EQ(_cfg.setActiveSlot(0), "");
	EXPECT_EQ(_cfg.secretWrites(), 1u);
	EXPECT_FALSE(_cfg.secretPending(0));
	EXPECT_NE(slurp(_path).find(kSecret), std::string::npos);
}

TEST_F(TelephonyStaging, AValueLongerThanItsCellIsRefusedWholeAndTheSecretIsNotWrittenAlone)
{
	// Only a hand-edited store can hold one (load() reads at most kMaxUrlLen characters on the board).
	const std::string handEdited = "s2url=" + std::string(TelephonyApiConfig::kMaxUrlLen + 72, 'x') + "\n";
	{
		std::ofstream f(_path, std::ios::binary);
		f << handEdited;
	}
	_cfg.load();
	nvswriter::resetForTest();

	const std::string err = _cfg.setSlot(0, realSlot(kSecret), false);
	EXPECT_NE(err, "") << "a table that could not be staged is an error, not a 200";
	EXPECT_EQ(nvswriter::stats().tooBig, 1u);
	EXPECT_EQ(nvswriter::stats().staged, 0u);
	EXPECT_TRUE(stagedTel().empty()) << "refused whole: nothing half-written reaches the writer";
	EXPECT_EQ(slurp(_path), handEdited) << "the store was not touched, so the secret was not written either";
	EXPECT_EQ(_cfg.secretWrites(), 0u);
	EXPECT_TRUE(_cfg.secretPending(0));
}

TEST_F(TelephonyStaging, ClearAllIsSynchronousAndWritesEveryKeyEvenAfterTheResetBegan)
{
	ASSERT_EQ(_cfg.setSlot(0, realSlot(kSecret), false), "");
	ASSERT_EQ(_cfg.setSlot(2, realSlot(kSecret2), false), "");
	ASSERT_EQ(_cfg.setActiveSlot(2), "");
	ASSERT_NE(slurp(_path).find(kSecret), std::string::npos);
	nvswriter::resetForTest();

	// /api/factory-reset: resetguard::begin() first, then the erase, then it reports.
	resetguard::begin();
	EXPECT_EQ(_cfg.clearAll(), "") << "the reset's erase must not be refused like a staged write";
	EXPECT_EQ(nvswriter::stats().staged, 0u);
	EXPECT_EQ(nvswriter::stats().suppressed, 0u) << "it never goes through the writer";

	std::string empty;
	for (size_t i = 0; i < TelephonyApiConfig::kSlots; ++i)
	{
		const std::string p = "s" + std::to_string(i);
		empty += p + "type=0\n" + p + "en=0\n" + p + "url=\n" + p + "id=\n" + p + "sec=\n" + p + "dn=\n";
	}
	EXPECT_EQ(slurp(_path), empty) << "every key written empty, secrets included, before clearAll() returned; no active slot";
	EXPECT_EQ(_cfg.activeSlot(), TelephonyApiConfig::kNoActiveSlot);
	for (size_t i = 0; i < TelephonyApiConfig::kSlots; ++i)
	{
		EXPECT_FALSE(_cfg.view(i).secretSet);
		EXPECT_FALSE(_cfg.secretPending(i));
	}
	EXPECT_EQ(where(kSecret), 0u);
	EXPECT_EQ(where(kSecret2), 0u);
}

TEST_F(TelephonyStaging, ClearSlotStagesTheRestAndErasesTheSecretWithoutWaitingForTheWriter)
{
	ASSERT_EQ(_cfg.setSlot(1, realSlot(kSecret), false), "");
	ASSERT_EQ(_cfg.setActiveSlot(1), "");
	ASSERT_NE(slurp(_path).find(kSecret), std::string::npos);
	ASSERT_EQ(drain().telephonyWrites, 1u);
	nvswriter::resetForTest();

	ASSERT_EQ(_cfg.clearSlot(1), "");
	EXPECT_EQ(nvswriter::stats().staged, 1u);
	EXPECT_EQ(_cfg.secretWrites(), 2u);
	EXPECT_EQ(slurp(_path).find(kSecret), std::string::npos) << "the secret is gone from the store before the writer has run";
	const Walk d = drain();
	ASSERT_EQ(d.telephonyWrites, 1u);
	Pairs want;
	for (size_t i = 0; i < TelephonyApiConfig::kSlots; ++i) unusedSlot(want, i);
	want.emplace_back("active", "255");
	EXPECT_EQ(d.pairs, want) << "the cleared slot is the default one, and it was the active slot";
}
#endif

TEST_F(TelephonyStaging, TheWalkStopsAtTheFirstFailedPutAndRefusesAMalformedSnapshot)
{
	ASSERT_EQ(_cfg.setSlot(1, realSlot(kSecret), false), "");
	const std::string good = stagedTel();
	ASSERT_EQ(good.size(), TelephonyApiConfig::kSnapshotLen);

	unsigned puts = 0;
	auto okU8 = [&](const char*, uint8_t) { ++puts; return true; };
	auto okStr = [&](const char*, const char*) { ++puts; return true; };
	EXPECT_TRUE(TelephonyApiConfig::emitSnapshot(good.data(), good.size(), okU8, okStr));
	EXPECT_EQ(puts, 4 * 5 + 1u);

	puts = 0;
	EXPECT_FALSE(TelephonyApiConfig::emitSnapshot(good.data(), good.size(), okU8,
		[&](const char*, const char*) { ++puts; return puts < 3; }));
	EXPECT_EQ(puts, 3u) << "the old `ok && nvs_set_*(...)` chain made no call after a failure";

	// Refused before the first put: wrong length, or a cell that does not end in a NUL.
	puts = 0;
	EXPECT_FALSE(TelephonyApiConfig::emitSnapshot(good.data(), 0, okU8, okStr));
	EXPECT_FALSE(TelephonyApiConfig::emitSnapshot(good.data(), good.size() - 1, okU8, okStr)) << "one byte short";
	const std::string longer = good + std::string(1, '\0');
	EXPECT_FALSE(TelephonyApiConfig::emitSnapshot(longer.data(), longer.size(), okU8, okStr)) << "one byte over";
	std::string noNul = good;
	noNul[3 * TelephonyApiConfig::kSlotSnapshotLen + 2 + 3 * TelephonyApiConfig::kCellLen - 1] = 'x';   // slot 3's route DN cell
	EXPECT_FALSE(TelephonyApiConfig::emitSnapshot(noNul.data(), noNul.size(), okU8, okStr));
	EXPECT_EQ(puts, 0u) << "a refused snapshot must not have written a single key";
}

#if !defined(_WIN32)
TEST_F(TelephonyStaging, WhatTheWriterEmitsPlusTheSecretIsWhatLoadReadsBack)
{
	ASSERT_EQ(_cfg.setSlot(0, realSlot(kSecret), false), "");
	TelephonyApiConfig::Slot s2 = realSlot(kSecret2);
	s2.routeDn = "205";
	ASSERT_EQ(_cfg.setSlot(2, s2, false), "");
	ASSERT_EQ(_cfg.setActiveSlot(2), "");
	const Walk d = drain();
	ASSERT_EQ(d.telephonyWrites, 1u);

	// The board's two halves, as the host store: the writer's walk, then the secret keys the
	// synchronous half wrote, in a file persist() never touched.
	{
		std::ofstream f(_path2, std::ios::binary);
		for (const auto& kv : d.pairs) f << kv.first << "=" << kv.second << "\n";
		f << "s0sec=" << kSecret << "\ns2sec=" << kSecret2 << "\n";
	}
	TelephonyApiConfig reloaded;
	reloaded.setStorePath(_path2);
	reloaded.load();

	EXPECT_EQ(reloaded.activeSlot(), 2u);
	for (size_t i = 0; i < TelephonyApiConfig::kSlots; ++i)
	{
		const TelephonyApiConfig::Slot* want = _cfg.bootSlot(i);
		const TelephonyApiConfig::Slot* got = reloaded.bootSlot(i);
		ASSERT_NE(want, nullptr);
		ASSERT_NE(got, nullptr);
		EXPECT_EQ(got->type, want->type) << i;
		EXPECT_EQ(got->enabled, want->enabled) << i;
		EXPECT_EQ(got->baseUrl, want->baseUrl) << i;
		EXPECT_EQ(got->clientId, want->clientId) << i;
		EXPECT_EQ(got->routeDn, want->routeDn) << i;
		EXPECT_EQ(got->secret, want->secret) << i;
	}
}
#endif

// ---------------------------------------------------------------------------
// Through RequestsHandler, the way the HTTP setters, the SBC route and the reset reach it.

namespace
{
	class TelephonyHandlerStaging : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			resetguard::resetForTest();
			nvswriter::resetForTest();
			const std::string name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
			_tapi = "test_telhandler_tapi_" + name + ".cfg";
			_did = "test_telhandler_did_" + name + ".cfg";
			std::remove(_tapi.c_str());
			std::remove(_did.c_str());
			_h = std::make_unique<RequestsHandler>("192.168.60.1", 5060,
				[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
			_h->setTelephonyStorePathsForTest(_tapi, _did);
			nvswriter::resetForTest();   // construction may have staged
		}
		void TearDown() override
		{
			_h.reset();
			std::remove(_tapi.c_str());
			std::remove(_did.c_str());
			nvswriter::resetForTest();
			resetguard::resetForTest();
		}

		std::unique_ptr<RequestsHandler> _h;
		std::string _tapi;
		std::string _did;
	};
}

TEST_F(TelephonyHandlerStaging, TheHttpSettersStageAndOnlyTheSecretEditWritesASecret)
{
	EXPECT_EQ(_h->setTelephonyConfigSlot(0, realSlot(kSecret), false), "");
	EXPECT_EQ(_h->telephonySecretWritesForTest(), 1u);
	EXPECT_EQ(_h->setTelephonyConfigActiveSlot(0), "");
	TelephonyApiConfig::Slot keep = realSlot("");
	keep.routeDn = "300";
	EXPECT_EQ(_h->setTelephonyConfigSlot(0, keep, true), "");
	EXPECT_EQ(_h->telephonySecretWritesForTest(), 1u);
	EXPECT_EQ(nvswriter::stats().staged, 3u);

	const Walk d = drain();
	EXPECT_EQ(d.telephonyWrites, 1u);
	EXPECT_TRUE(d.wellFormed);
	EXPECT_EQ(pairAt(d, 4), (Pair{"s0dn", "300"}));
	EXPECT_EQ(lastOf(d), (Pair{"active", "0"}));
	EXPECT_EQ(where(kClientId), kAll);
	EXPECT_EQ(where(kSecret), 0u);

	EXPECT_EQ(_h->clearTelephonyConfigSlot(0), "");
	EXPECT_EQ(_h->telephonySecretWritesForTest(), 2u);
}

TEST_F(TelephonyHandlerStaging, TheSbcRouteStagesTheActiveSlotAndIsRefusedDuringAReset)
{
	EXPECT_EQ(_h->setSbcMode(true, 1), "");
	EXPECT_EQ(nvswriter::stats().staged, 1u);
	EXPECT_EQ(lastOf(drain()), (Pair{"active", "1"}));
	EXPECT_EQ(_h->telephonySecretWritesForTest(), 0u);

	// A staged write is refused once a reset has begun, so enabling SBC mode answers an error and leaves it off.
	ASSERT_EQ(_h->setSbcMode(false, 1), "");
	resetguard::begin();
	EXPECT_NE(_h->setSbcMode(true, 2), "");
	EXPECT_FALSE(_h->getSbcMode().first);
}

TEST_F(TelephonyHandlerStaging, TheFactoryResetClearStaysSynchronous)
{
	ASSERT_EQ(_h->setTelephonyConfigSlot(0, realSlot(kSecret), false), "");
	nvswriter::resetForTest();
	resetguard::begin();
	EXPECT_EQ(_h->clearAllTelephonyConfig(), "") << "/api/factory-reset erases after resetguard::begin() and reports the result";
	EXPECT_EQ(nvswriter::stats().staged, 0u);
	EXPECT_EQ(nvswriter::stats().suppressed, 0u);
	EXPECT_FALSE(_h->getTelephonyConfigSlot(0).secretSet);
}

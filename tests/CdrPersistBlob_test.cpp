// Issue #470: the CDR ring persists as an NVS BLOB, because nvs_set_str caps a
// value at 4000 B including the NUL and a full ring of long AORs serializes
// past that. That write failed, and the writer ignored the error, so history
// silently went stale. Also covers #473's reset guard, which the CDR writer is
// the first to honour.
//
// The NVS calls themselves run only on the ESP writer task; what the host can
// pin is everything around them: the serialized length really is over the old
// limit, the text round-trips through loadFromText() (the parse load() now
// uses for both the blob and the one-time legacy fallback), serializing
// allocates nothing, and the guard's ordering contract holds.

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <thread>

#include "CdrRing.hpp"
#include "ResetGuard.hpp"
#include "support/AllocCounter.hpp"

namespace
{
	// A 48-character AOR (CdrRing's per-field cap), distinct per record.
	std::string aor(char tag, size_t i)
	{
		std::string s(48, tag);
		const std::string n = std::to_string(i);
		s.replace(0, n.size(), n);
		return s;
	}

	std::array<CallDetailRecord, POCKETDIAL_CDR_RECORDS> maxRing()
	{
		std::array<CallDetailRecord, POCKETDIAL_CDR_RECORDS> ring{};
		for (size_t i = 0; i < ring.size(); ++i)
		{
			ring[i].caller = aor('c', i);
			ring[i].callee = aor('e', i);
			ring[i].startMs = 18446744073709551000ULL + i;   // 20 digits
			ring[i].durationSec = 4294967295U - static_cast<uint32_t>(i);
			ring[i].result = static_cast<CdrResult>(i % 5);
		}
		return ring;
	}
}

// The case the old nvs_set_str path could not store: over 4000 B, yet within
// the blob, and it comes back record for record.
TEST(CdrPersistBlob, MaxAorRingSerializesPast4000BytesAndRoundTrips)
{
	const auto ring = maxRing();
	static CdrRingBlob blob;   // ~4.5 KB: not on the test's stack
	CdrRing::serializeForPersist(ring, /*head=*/0, /*count=*/POCKETDIAL_CDR_RECORDS, blob);

	EXPECT_GT(blob.len, 3999u) << "a full ring of max-length AORs must exceed nvs_set_str's limit";
	EXPECT_EQ(blob.len, std::strlen(blob.text)) << "len is the serialized length";
	EXPECT_FALSE(blob.erase);

	CdrRing restored;
	ASSERT_EQ(restored.loadFromText(std::string_view(blob.text, blob.len)),
		static_cast<size_t>(POCKETDIAL_CDR_RECORDS));
	const auto snap = restored.snapshot();   // newest first
	ASSERT_EQ(snap.size(), ring.size());
	for (size_t i = 0; i < ring.size(); ++i)
	{
		const auto& want = ring[ring.size() - 1 - i];
		EXPECT_EQ(snap[i].caller, want.caller) << i;
		EXPECT_EQ(snap[i].callee, want.callee) << i;
		EXPECT_EQ(snap[i].startMs, want.startMs) << i;
		EXPECT_EQ(snap[i].durationSec, want.durationSec) << i;
		EXPECT_EQ(snap[i].result, want.result) << i;
	}
}

// serializeForPersist runs on whatever task ended the call (#273), under the
// engine's mutex: it must not touch the heap. std::to_string of a 20-digit
// startMs used to allocate three times per record.
TEST(CdrPersistBlob, SerializingAFullRingAllocatesNothing)
{
	const auto ring = maxRing();
	static CdrRingBlob blob;
	CdrRing::serializeForPersist(ring, 0, POCKETDIAL_CDR_RECORDS, blob);   // warm

	AllocGuard guard;
	CdrRing::serializeForPersist(ring, 0, POCKETDIAL_CDR_RECORDS, blob);
	EXPECT_EQ(guard.delta(), 0u);
}

// An empty ring serializes to nothing; persist() turns that into an erase
// command for the writer (it is how clearAll() -- and the factory reset --
// removes the history rather than storing an empty blob).
TEST(CdrPersistBlob, EmptyRingHasZeroLength)
{
	std::array<CallDetailRecord, POCKETDIAL_CDR_RECORDS> ring{};
	static CdrRingBlob blob;
	CdrRing::serializeForPersist(maxRing(), 0, POCKETDIAL_CDR_RECORDS, blob);
	CdrRing::serializeForPersist(ring, 0, 0, blob);
	EXPECT_EQ(blob.len, 0u);
	EXPECT_STREQ(blob.text, "");
}

// loadFromText() keeps at most POCKETDIAL_CDR_RECORDS records however long the
// persisted text is (a corrupt or hand-edited value must not overrun the ring).
TEST(CdrPersistBlob, LoadingMoreLinesThanTheRingHoldsStopsAtTheRingSize)
{
	std::string text;
	for (size_t i = 0; i < POCKETDIAL_CDR_RECORDS + 8; ++i)
	{
		text += "c" + std::to_string(i) + "\te\t1\t1\t0\n";
	}
	CdrRing r;
	EXPECT_EQ(r.loadFromText(text), static_cast<size_t>(POCKETDIAL_CDR_RECORDS));
	const auto snap = r.snapshot();
	ASSERT_EQ(snap.size(), static_cast<size_t>(POCKETDIAL_CDR_RECORDS));
	EXPECT_EQ(snap.back().caller, "c0") << "the first (oldest) lines are the ones kept";
	EXPECT_EQ(snap.front().caller, "c" + std::to_string(POCKETDIAL_CDR_RECORDS - 1));
}

namespace
{
	bool g_idleSeenByReset = false;

	// Runs inside WriteScope, between "count me" and "am I allowed?".
	void startResetMidScope()
	{
		resetguard::begin();
		g_idleSeenByReset = resetguard::waitForWritersIdle(0);
	}
}

// #476 review: the guard's real job, deterministically. A reset that begins at
// the worst moment -- inside a writer's WriteScope, between its two steps --
// must never both see the writers idle AND let that writer write. With the
// steps in the right order (count, then check) the reset sees one writer in
// flight and the writer is refused. Reverse them and the reset sees zero
// writers while the writer has already been told it may write.
TEST(ResetGuard, AResetBeginningInsideAWriteScopeNeverSeesIdleWhileItWrites)
{
	resetguard::resetForTest();
	g_idleSeenByReset = true;
	resetguard::betweenStepsHookForTest() = &startResetMidScope;
	bool allowed = true;
	{
		resetguard::WriteScope scope;
		allowed = scope.allowed();
	}
	resetguard::betweenStepsHookForTest() = nullptr;

	EXPECT_FALSE(g_idleSeenByReset) << "the reset must count the writer that is mid-scope";
	EXPECT_FALSE(allowed) << "a writer whose scope saw the reset begin must not write";
	EXPECT_FALSE(g_idleSeenByReset && allowed) << "the invariant: never idle-and-writing";
	resetguard::resetForTest();
}

// #473: once begin() has run, a writer that starts afterwards is refused, and
// waitForWritersIdle() only reports idle once every in-flight write is done.
TEST(ResetGuard, WritersAreRefusedAfterBeginAndDrainedBeforeTheErase)
{
	resetguard::resetForTest();
	{
		resetguard::WriteScope before;
		EXPECT_TRUE(before.allowed()) << "no reset: writes proceed";
	}
	EXPECT_TRUE(resetguard::waitForWritersIdle(0));

	// A write already in flight when the reset begins must be waited for.
	auto inFlight = std::make_unique<resetguard::WriteScope>();
	ASSERT_TRUE(inFlight->allowed());
	resetguard::begin();
	EXPECT_TRUE(resetguard::inProgress());
	EXPECT_FALSE(resetguard::waitForWritersIdle(20)) << "the in-flight write is still open";

	{
		resetguard::WriteScope after;
		EXPECT_FALSE(after.allowed()) << "a write that starts after begin() is refused";
	}
	std::thread finisher([&inFlight] {
		std::this_thread::sleep_for(std::chrono::milliseconds(30));
		inFlight.reset();
	});
	EXPECT_TRUE(resetguard::waitForWritersIdle(2000)) << "idle once the in-flight write ends";
	finisher.join();

	resetguard::resetForTest();
}

#ifndef CDR_RING_HPP
#define CDR_RING_HPP

#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "CallDetailRecord.hpp"
#include "Session.hpp"

// Fixed-capacity NVS blob for the CDR ring's write-through persistence.
// Sized so the worst case (every one of POCKETDIAL_CDR_RECORDS records at its
// per-field cap) fits with room to spare -- see CdrRing.cpp's kMaxLineBytes
// comment for the exact arithmetic. Never allocates: this is what crosses
// from persist() -- called from RequestsHandler::endCall(), on WHATEVER task
// ended the call, including a PSRAM-stacked one (issues #273/#288) -- to the
// dedicated, plain-stack writer task via a fixed-size FreeRTOS queue item.
// The actual flash write happens only on that task; nothing here does I/O.
//
// Issue #470: stored with nvs_set_blob (limit ~508 KB), no longer nvs_set_str,
// which IDF caps at 4000 B including the NUL -- below kCapacity (4481 B at the
// default 32 records), so a ring of long AORs used to fail to persist, and
// the writer ignored the error. `len` is the serialized length (text is still
// NUL-terminated for the host tests and the legacy reader); `erase` asks the
// writer to remove the persisted ring instead (an empty ring -- clearAll()).
struct CdrRingBlob
{
	static constexpr size_t kCapacity = POCKETDIAL_CDR_RECORDS * 140 + 1;
	uint16_t len = 0;
	bool     erase = false;
	char text[kCapacity] = {};
};
static_assert(CdrRingBlob::kCapacity <= 0xFFFF, "CdrRingBlob::len is 16-bit");

// ── Call Detail Record ring buffer, extracted out of RequestsHandler ─────────
// Fixed capacity (POCKETDIAL_CDR_RECORDS), no heap growth: writes wrap and
// overwrite the oldest slot. Unlike PbxFeatureConfig (see PbxFeatureConfig.hpp),
// this machine takes no PbxEnv reference: record() never logs and nothing about
// a CDR write refreshes the dashboard snapshot immediately — the snapshot's
// `cdr` view is rebuilt only from tick()'s periodic sweep, via snapshot(), same
// as before this split (see RequestsHandler::tick()).
//
// Locking: every method assumes the caller holds the engine's _mutex, same
// convention as every other extracted machine — except load(), called once
// from the constructor before any handler is dispatching.
class CdrRing
{
public:
	// Write one record into the ring as a call ends. Caller holds _mutex.
	// `session` (may be null) supplies the start time / final state used to
	// derive duration and result; src/dest provide the parties when the
	// session lookup can't (e.g. the virtual 777/999 extensions reuse a shared
	// dummy client). Write-through persists to NVS (no-op on host). Returns a
	// reference to the slot just written (valid until the ring wraps back onto
	// it POCKETDIAL_CDR_RECORDS records from now) so a caller — endCall(),
	// specifically — can reuse the already-computed startMs/durationSec/result
	// (including the Connected/Held/Bye -> Answered disposition logic above)
	// instead of re-deriving them from the session a second time. Issue #194
	// Stage 1 (SD CDR archive) is the first consumer of this.
	const CallDetailRecord& record(const std::shared_ptr<Session>& session,
		std::string_view srcNumber, std::string_view destNumber);

	// Newest-first copy of the ring, for the dashboard snapshot. Caller holds
	// _mutex.
	std::vector<CallDetailRecord> snapshot() const;

	// *69: extension of the last party that called `calleeExt`, walking
	// newest to oldest; empty string if none found. Caller holds _mutex.
	std::string lastCallerFor(std::string_view calleeExt) const;

	// Boot-time reload from NVS. Construction is single-threaded (no handler
	// is dispatching yet), so this runs without holding _mutex, same as
	// before this split.
	void load();

	// Wipe every record and persist the empty ring. Caller holds _mutex.
	// Used by the factory-reset path — CDR data (caller/callee numbers) is as
	// sensitive as the credential tables in TelephonyApiConfig/DidMapping and
	// lives in its own NVS namespace ("cdrlog"), so a reset must clear it too.
	void clearAll();

	// Pure, host-testable, never allocates: builds the exact NVS blob format
	// persist() writes -- oldest-first, tab-separated, one line per record --
	// directly into `out`. Unchanged by issue #273's fix, which only moved
	// WHERE the flash write happens, not what it writes, so
	// load()/deserializeBlob() need no matching change. caller/callee are
	// truncated to a fixed cap (see CdrRing.cpp) rather than the unbounded
	// length the live std::string fields allow -- anchor-sourced values
	// bypass isValidAor()'s length bound, same precedent as
	// CdrArchive.cpp's kMaxAorRaw -- which is the one behavior change from
	// the pre-fix code, a necessary consequence of a fixed-size buffer
	// rather than a scope addition.
	//
	// Takes `out` BY REFERENCE rather than returning a CdrRingBlob, matching
	// CdrArchive.cpp's formatLine(..., QueuedLine& out) convention for the
	// same reason: at ~4.5 KB, a return-by-value risks a temporary of that
	// size materializing on the caller's stack around the assignment, even
	// with a static destination -- an out-parameter writes straight into
	// whatever storage the caller already owns (persist()'s static `blob`),
	// with nothing but this function's own small locals ever touching the
	// stack. Exposed as a static method (rather than private) specifically
	// so CdrRing_test.cpp can exercise the format/truncation logic directly,
	// without FreeRTOS, NVS, or a live CdrRing instance.
	static void serializeForPersist(
		const std::array<CallDetailRecord, POCKETDIAL_CDR_RECORDS>& ring,
		size_t head, size_t count, CdrRingBlob& out);

	// Issue #470: rebuild the ring from a persisted blob's text (the format
	// serializeForPersist() writes). Replaces the current contents; returns the
	// number of records loaded. Boot-time only (it allocates while parsing,
	// once); split out of load() so the round trip is host-testable.
	size_t loadFromText(std::string_view text);

	// Issue #470: NVS failures in the persist writer (open, set, commit, or the
	// legacy-key erase), and data writes refused because a factory reset was in
	// progress (#473). Always 0 on host, which has no writer. For /api/status.
	static uint32_t persistFailureCount();
	static uint32_t persistSuppressedCount();

private:
	void persist();

	std::array<CallDetailRecord, POCKETDIAL_CDR_RECORDS> _ring{};
	size_t _head = 0;   // index of the NEXT slot to write
	size_t _count = 0;  // caps at POCKETDIAL_CDR_RECORDS
};

#endif

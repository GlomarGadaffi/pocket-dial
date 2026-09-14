#ifndef CALL_DETAIL_RECORD_HPP
#define CALL_DETAIL_RECORD_HPP

// CallDetailRecord.hpp — fixed-footprint Call Detail Record (CDR) types.
//
// A CDR is written exactly once, as a call tears down (see CdrRing::record,
// invoked from RequestsHandler::endCall()). Records are kept in a fixed-capacity ring
// buffer (POCKETDIAL_CDR_RECORDS) so the memory cost is paid statically at boot
// and never grows on the heap — consistent with the SIP object pools (see
// PoolConfig.hpp). The newest record overwrites the oldest once the ring is full.

#include <string>
#include <cstdint>

// Number of Call Detail Records retained in the ring buffer. Compile-time
// tunable (-DPOCKETDIAL_CDR_RECORDS=N). The default of 32 mirrors the client
// pool depth and keeps the static footprint modest on the ESP32-S3.
#ifndef POCKETDIAL_CDR_RECORDS
#define POCKETDIAL_CDR_RECORDS 32
#endif

// How a call ended. Derived from the Session's final state at teardown.
enum class CdrResult
{
	Answered,    // the call connected (Session reached Connected)
	Busy,        // callee was busy (486)
	Cancelled,   // caller hung up before answer (CANCEL / 487)
	Unavailable, // callee unavailable (480) or no answer
	Failed       // anything else (parse error, forced disconnect, ...)
};

inline const char* cdrResultToString(CdrResult r)
{
	switch (r)
	{
		case CdrResult::Answered:    return "answered";
		case CdrResult::Busy:        return "busy";
		case CdrResult::Cancelled:   return "cancelled";
		case CdrResult::Unavailable: return "unavailable";
		case CdrResult::Failed:      return "failed";
		default:                     return "failed";
	}
}

// One completed call. Strings are short SIP AORs (extensions) on MOST paths.
//
// CORRECTED (issue #194 audit): this used to claim caller/callee "are bounded
// by the registrar's isValidAor() validation on ingress, so they cannot grow
// without limit." That is false on two counts. First, isValidAor() (see
// RequestsHandler::isValidAor) is a pure CHARSET filter — alnum plus
// `. - _ + * #` — with no length check at all, so even an AOR that does pass
// through it could be arbitrarily long; RequestsHandler.cpp now caps it at
// kMaxAorLen (64) for exactly this reason (a caller/callee string heap-
// allocates inside every ring slot below, and CdrRing has no bound of its
// own). Second, not every CDR field actually comes through that gate: the
// anchor/trunk paths (RequestsHandler.cpp's endCall() calls around the
// participant-id branches, e.g. `ev.participantId` /
// Session::getAnchorParticipantId()) pass values sourced from the anchor's
// own JSON, which never touches isValidAor(). Those are bounded only by
// whatever the anchor/telephony provider itself enforces upstream — treat
// them as untrusted-length input at any new consumer (like the SD archive
// formatter in CdrArchive.cpp, which truncates defensively rather than
// trusting this comment a second time).
//
// A CDR is a value type copied into the dashboard snapshot.
struct CallDetailRecord
{
	std::string caller;       // calling extension (From)
	std::string callee;       // called extension (To)
	uint64_t    startMs = 0;  // steady-clock epoch ms when the call started
	                          // (same basis as HttpServer uptime)
	uint32_t    durationSec = 0; // talk time in seconds (0 if never connected)
	CdrResult   result = CdrResult::Failed;
};

#endif

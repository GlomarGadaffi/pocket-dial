#ifndef TIME_SYNC_HPP
#define TIME_SYNC_HPP

// TimeSync — the wall clock this firmware has never had.
//
// WHY THIS EXISTS. Nothing in the tree ever started an SNTP client. The only
// reference was DtmfFeatureCodes.cpp's `esp_sntp_restart()`, which restarts a
// stack that was never initialised, so it has always been a no-op. Everything
// that needed a time therefore used std::chrono::steady_clock, which counts from
// an arbitrary origin at boot:
//
//   * CallDetailRecord::startMs (CdrRing.cpp) is steady_clock, so CDRs that
//     survive a reboot already render as "0s ago" in the dashboard.
//   * An SD-backed CDR archive (issue #194 Stage 1) would inherit that: two files
//     written either side of a reboot could not be ordered against each other,
//     which makes the archive close to useless.
//   * RFC 5424 syslog has a TIMESTAMP field. Without a wall clock the only honest
//     thing to emit is the NILVALUE "-" (RFC 5424 §6.2.3).
//
// steady_clock stays exactly where it is. It is the RIGHT clock for durations and
// timers precisely because it never steps, and an SNTP step must not make a call
// appear to last minus four seconds. This module is purely ADDITIVE: a second,
// separate notion of "what time is it in the world", for stamping records and log
// lines. Never use it to measure an interval.
//
// LAYERING, matching RtpSender/RtpReceiver: the formatter is pure and
// host-unit-tested; the SNTP client is ESP-only behind `#if defined(ESP_PLATFORM)`
// and compiles to a no-op stub on the desktop build, so the host suite still
// exercises the "never synced" behaviour that the rest of the code has to handle.

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>

namespace timesync
{

// RFC 5424 §6.2.3 NILVALUE — what a structured log field carries when the value
// is genuinely unknown. Also what rfc3339Now() returns before the first sync.
inline constexpr const char* kNilValue = "-";

// Begin synchronising. NON-BLOCKING by design, and that is load-bearing: the SIP
// registrar must come up whether or not a time server is reachable, so this never
// waits for a first sync and never fails the boot. Safe to call more than once;
// subsequent calls are ignored.
//
// Server selection, in order of preference:
//   1. Whatever DHCP option 42 supplied, when CONFIG_LWIP_DHCP_GET_NTP_SRV is
//      enabled. A LAN appliance that ignores the NTP server its own network
//      handed it, and reaches out to the public internet instead, is doing the
//      wrong thing — some deployments have no route out at all.
//   2. time.nist.gov — NIST's Internet Time Service. Queried by DNS NAME, never
//      a hardcoded address: NIST round-robins the name across its servers and
//      explicitly asks clients not to pin an IP.
//
// Call AFTER the network has an address. On this firmware that is the Ethernet
// GOT_IP path; calling earlier just means the first query fails and the client
// retries on its own schedule.
void start();

// True once a server has answered at least once and the system clock has been
// set. Everything that stamps a time must branch on this rather than assuming.
bool isSynced();

// Seconds since the Unix epoch, or 0 when never synced. 0 is unambiguous here:
// a real reading would be ~1.7e9, and the firmware cannot legitimately believe
// it is 1970 once a server has replied.
uint64_t epochSeconds();

// ── Pure formatter (host-unit-tested) ───────────────────────────────────────

// Format `t` as RFC 3339 UTC, e.g. "2026-09-14T01:23:45Z" — the shape RFC 5424
// §6.2.3 wants for TIMESTAMP and a sortable key for a CDR archive filename.
// Always UTC: the firmware has no timezone database and a local-time log that
// does not say which local time is worse than useless across a DST boundary.
// Writes at most `cap` bytes including the terminator and returns the length
// written (0 if `cap` is too small), never allocating.
size_t formatRfc3339(time_t t, char* out, size_t cap);

// The current time as RFC 3339, or kNilValue ("-") when unsynced. Convenience
// wrapper for log/record call sites; the "-" is what makes an unsynced syslog
// frame still RFC 5424 conformant rather than carrying a fabricated 1970 stamp.
std::string rfc3339Now();

}  // namespace timesync

#endif

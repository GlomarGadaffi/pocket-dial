#include <gtest/gtest.h>
#include "TimeSync.hpp"

#include <ctime>
#include <string>

// TimeSync — the wall clock. These cover the PURE half: the RFC 3339 formatter
// and the unsynced behaviour. The SNTP client itself is ESP-only, so on the host
// build isSynced() is permanently false, which is exactly the state every caller
// has to handle correctly and is therefore worth pinning.

TEST(TimeSync, FormatsAKnownEpochAsRfc3339Utc)
{
    // 1700000000 = 2023-11-14T22:13:20Z. A fixed vector rather than "format now
    // and parse it back", so a timezone or locale change in CI cannot make this
    // pass for the wrong reason.
    char buf[32];
    const size_t n = timesync::formatRfc3339(1700000000, buf, sizeof(buf));
    ASSERT_EQ(n, 20u);
    EXPECT_STREQ(buf, "2023-11-14T22:13:20Z");
}

TEST(TimeSync, FormatsTheUnixEpochItself)
{
    char buf[32];
    const size_t n = timesync::formatRfc3339(0, buf, sizeof(buf));
    ASSERT_EQ(n, 20u);
    EXPECT_STREQ(buf, "1970-01-01T00:00:00Z");
}

TEST(TimeSync, AlwaysUtcNeverLocalTime)
{
    // The firmware has no timezone database, and a log that says "01:23:45" with
    // no indication of WHICH 01:23:45 is worse than useless across a DST change.
    // The trailing Z is the whole contract.
    char buf[32];
    ASSERT_GT(timesync::formatRfc3339(1700000000, buf, sizeof(buf)), 0u);
    const std::string s(buf);
    EXPECT_EQ(s.back(), 'Z');
    EXPECT_NE(s.find('T'), std::string::npos);
}

TEST(TimeSync, FieldWidthsAreFixedSoTimestampsSortLexicographically)
{
    // Archive filenames and log lines get compared as strings. A single-digit
    // month or day that shortened the field would sort "2026-9-14" after
    // "2026-10-01", silently scrambling an ordered archive.
    char a[32], b[32];
    ASSERT_GT(timesync::formatRfc3339(1757808000, a, sizeof(a)), 0u);  // Sep 2025
    ASSERT_GT(timesync::formatRfc3339(1760400000, b, sizeof(b)), 0u);  // Oct 2025
    EXPECT_EQ(std::string(a).size(), std::string(b).size());
    EXPECT_LT(std::string(a), std::string(b));
}

TEST(TimeSync, RefusesABufferTooSmallRatherThanTruncating)
{
    // A truncated timestamp is a corrupt record. Returning 0 lets the caller fall
    // back to the NILVALUE instead of writing half a date.
    char small[8];
    EXPECT_EQ(timesync::formatRfc3339(1700000000, small, sizeof(small)), 0u);
    EXPECT_EQ(timesync::formatRfc3339(1700000000, nullptr, 32), 0u);

    // 21 is the exact minimum: 20 characters plus the terminator.
    char exact[21];
    EXPECT_EQ(timesync::formatRfc3339(1700000000, exact, sizeof(exact)), 20u);
    char oneShort[20];
    EXPECT_EQ(timesync::formatRfc3339(1700000000, oneShort, sizeof(oneShort)), 0u);
}

// ── Unsynced behaviour ──────────────────────────────────────────────────────

TEST(TimeSync, HostBuildIsNeverSynced)
{
    // No SNTP client off-device. Pinned because the whole point of isSynced() is
    // that callers branch on it -- if it ever returned true here, the host tests
    // would start stamping real times and stop exercising the degraded path.
    EXPECT_FALSE(timesync::isSynced());
}

TEST(TimeSync, EpochSecondsIsZeroWhenUnsynced)
{
    // 0 is unambiguous: a real reading is ~1.7e9, and the firmware cannot
    // legitimately believe it is 1970 once a server has answered.
    EXPECT_EQ(timesync::epochSeconds(), 0u);
}

TEST(TimeSync, UnsyncedRendersTheRfc5424NilValue)
{
    // RFC 5424 §6.2.3: "-" is the NILVALUE. Emitting it keeps an unsynced syslog
    // frame CONFORMANT, where a fabricated 1970 stamp would be a lie that parses.
    EXPECT_EQ(timesync::rfc3339Now(), "-");
    EXPECT_STREQ(timesync::kNilValue, "-");
}

TEST(TimeSync, StartIsSafeToCallRepeatedlyOffDevice)
{
    // The Ethernet GOT_IP handler can fire more than once (cable bounce, DHCP
    // renew), and esp_netif_sntp_init() errors if called twice -- so start() must
    // be idempotent. Off-device this simply must not crash or flip isSynced().
    timesync::start();
    timesync::start();
    EXPECT_FALSE(timesync::isSynced());
}

#include "TimeSync.hpp"

#include <atomic>
#include <cstdio>

#if defined(ESP_PLATFORM)
#include "esp_netif_sntp.h"
#include "esp_sntp.h"
#include "esp_log.h"
#endif

namespace timesync
{
namespace
{

std::atomic<bool> g_synced{false};
std::atomic<bool> g_started{false};

#if defined(ESP_PLATFORM)
constexpr const char* TAG = "TimeSync";

// NIST's Internet Time Service, by DNS name. NIST round-robins this name across
// its server fleet and asks clients NOT to hardcode an address, both so load
// spreads and so a decommissioned server does not strand anyone.
constexpr const char* kNistServer = "time.nist.gov";

// Called by the SNTP client each time it sets the clock. The first one is the
// transition the rest of the firmware cares about: before it, every timestamp is
// a lie; after it, records can be ordered against the real world.
void onTimeSynced(struct timeval* tv)
{
	const bool first = !g_synced.exchange(true, std::memory_order_acq_rel);
	if (first && tv != nullptr)
	{
		char buf[32];
		formatRfc3339(static_cast<time_t>(tv->tv_sec), buf, sizeof(buf));
		// Worth a line at INFO: this is the moment CDR and log timestamps become
		// meaningful, and its ABSENCE from a boot log is the first thing to look
		// for when an archive comes back with nonsense times.
		ESP_LOGI(TAG, "wall clock set: %s (UTC)", buf);
	}
}
#endif

}  // namespace

void start()
{
	// Idempotent: the Ethernet GOT_IP handler can fire more than once (a cable
	// bounce, a DHCP renew onto a new address), and esp_netif_sntp_init() returns
	// ESP_ERR_INVALID_STATE if called twice.
	if (g_started.exchange(true, std::memory_order_acq_rel)) return;

#if defined(ESP_PLATFORM)
	esp_sntp_config_t cfg = ESP_NETIF_SNTP_DEFAULT_CONFIG(kNistServer);

	// Step the clock rather than slewing it. Slewing is correct for a long-running
	// host that must never jump, but this device boots believing it is 1970 — a
	// smooth correction would take hours to walk 56 years, and every record written
	// in the meantime would carry a wrong-but-plausible time, which is worse than
	// an obviously-absent one.
	cfg.sync_cb = onTimeSynced;
	cfg.start   = true;

#if defined(CONFIG_LWIP_DHCP_GET_NTP_SRV)
	// Prefer the NTP server this network handed us over reaching out to NIST.
	// Some deployments have no route to the public internet at all, and an
	// appliance that ignores DHCP option 42 simply never gets a clock there.
	// NIST stays configured as the fallback entry.
	cfg.server_from_dhcp          = true;
	cfg.renew_servers_after_new_IP = true;
	cfg.index_of_first_server      = 1;   // DHCP takes slot 0, NIST keeps slot 1
	cfg.ip_event_to_renew          = IP_EVENT_ETH_GOT_IP;
#endif

	const esp_err_t err = esp_netif_sntp_init(&cfg);
	if (err != ESP_OK)
	{
		// Non-fatal on purpose. No clock is a degraded state, not a dead one: SIP,
		// the dashboard and the trunk all work without it, and everything that
		// stamps a time already has to handle isSynced() == false.
		ESP_LOGW(TAG, "SNTP init failed (%s) — continuing without a wall clock",
			esp_err_to_name(err));
		g_started.store(false, std::memory_order_release);
	}
#endif
}

bool isSynced()
{
	return g_synced.load(std::memory_order_acquire);
}

uint64_t epochSeconds()
{
	if (!isSynced()) return 0;
	const time_t now = ::time(nullptr);
	return (now > 0) ? static_cast<uint64_t>(now) : 0;
}

size_t formatRfc3339(time_t t, char* out, size_t cap)
{
	// "YYYY-MM-DDTHH:MM:SSZ" is 20 chars + NUL.
	if (out == nullptr || cap < 21) return 0;

	struct tm tmv{};
#if defined(_WIN32) || defined(_WIN64)
	if (gmtime_s(&tmv, &t) != 0) return 0;
#else
	if (::gmtime_r(&t, &tmv) == nullptr) return 0;
#endif

	// Hand-rolled rather than strftime(): strftime's output is locale-sensitive
	// for some specifiers and this format must be byte-stable everywhere it is
	// compared or sorted. %04d on tm_year+1900 also keeps a pre-1000 year (the
	// unsynced 1970-adjacent case) from shortening the field and breaking
	// lexicographic ordering of archive filenames.
	const int n = std::snprintf(out, cap, "%04d-%02d-%02dT%02d:%02d:%02dZ",
		tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
		tmv.tm_hour, tmv.tm_min, tmv.tm_sec);

	return (n > 0 && static_cast<size_t>(n) < cap) ? static_cast<size_t>(n) : 0;
}

std::string rfc3339Now()
{
	if (!isSynced()) return kNilValue;

	char buf[32];
	const size_t n = formatRfc3339(static_cast<time_t>(::time(nullptr)), buf, sizeof(buf));
	return (n > 0) ? std::string(buf, n) : std::string(kNilValue);
}

}  // namespace timesync

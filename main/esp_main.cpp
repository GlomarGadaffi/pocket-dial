#include <cstring>
#include <string>
#include <atomic>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "esp_netif.h"

#include "SipServer.hpp"
#include "HttpServer.hpp"
#include "OtaUpdater.hpp"
#include "AdminAuth.hpp"
#include "DeviceConfig.hpp"
#include "LogQueue.hpp"
#include "Syslog.hpp"
#include "host_compat.h"

// ── Default INFRA (AP) profile settings ───────────────────────────────────────
#define EXAMPLE_ESP_WIFI_SSID      "esp32-sipserver"
// No EXAMPLE_ESP_WIFI_PASS: the SoftAP passphrase is NOT a build-time constant.
// It lives in NVS and is generated per device on first use — see DeviceConfig.hpp
// and wifi_init_softap() below. A literal here would be identical on every unit
// and published in this repo, which is no security at all.
#define EXAMPLE_ESP_WIFI_CHANNEL   1
#define EXAMPLE_MAX_STA_CONN       10

#define HTTP_DASHBOARD_PORT        80

// ── Topology constants ─────────────────────────────────────────────────────────
// Stored in NVS namespace "storage" as key "wifi_mode" (u8).
#define TOPOLOGY_CLIENT 1   // Wi-Fi STA — get DHCP from upstream router
#define TOPOLOGY_INFRA  2   // Wi-Fi AP  — run embedded DHCP server for phones

static const char *TAG = "wifi softAP";

// Global pointer so the HTTP task (Core 0) can reach the SIP engine built by the
// SIP task (Core 1). Atomic with acquire/release: a plain pointer is a cross-core
// data race on the SMP Xtensa (the reader could see a stale null or a half-built
// object, and the compiler could hoist the poll out of the loop).
static std::atomic<SipServer*> g_sipServer{nullptr};

// ── Event bits for STA connect ────────────────────────────────────────────────
#define STA_GOT_IP_BIT BIT0
static EventGroupHandle_t s_sta_event_group = nullptr;
static std::string        s_sta_ip;

// ── Wi-Fi event handler ───────────────────────────────────────────────────────
static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT)
    {
        if (event_id == WIFI_EVENT_AP_STACONNECTED) {
            wifi_event_ap_staconnected_t* event = static_cast<wifi_event_ap_staconnected_t*>(event_data);
            ESP_LOGI(TAG, "station " MACSTR " join, AID=%d",
                     MAC2STR(event->mac), event->aid);
        } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
            wifi_event_ap_stadisconnected_t* event = static_cast<wifi_event_ap_stadisconnected_t*>(event_data);
            ESP_LOGI(TAG, "station " MACSTR " leave, AID=%d",
                     MAC2STR(event->mac), event->aid);
        } else if (event_id == WIFI_EVENT_STA_START) {
            esp_wifi_connect();
        } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
            ESP_LOGW(TAG, "STA disconnected — reconnecting...");
            esp_wifi_connect();
        }
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
    {
        ip_event_got_ip_t* event = static_cast<ip_event_got_ip_t*>(event_data);
        char buf[16];
        esp_ip4addr_ntoa(&event->ip_info.ip, buf, sizeof(buf));
        s_sta_ip = buf;
        ESP_LOGI(TAG, "STA got IP: %s", buf);
        if (s_sta_event_group) {
            xEventGroupSetBits(s_sta_event_group, STA_GOT_IP_BIT);
        }
    }
}

// ── INFRA topology: Wi-Fi SoftAP + DHCP server ────────────────────────────────
static std::string wifi_init_softap(void)
{
    esp_netif_t* ap_netif = esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));

    wifi_config_t wifi_config = {};
    strlcpy((char*)wifi_config.ap.ssid, EXAMPLE_ESP_WIFI_SSID, sizeof(wifi_config.ap.ssid));
    wifi_config.ap.ssid_len = strlen(EXAMPLE_ESP_WIFI_SSID);
    wifi_config.ap.channel = EXAMPLE_ESP_WIFI_CHANNEL;
    wifi_config.ap.max_connection = EXAMPLE_MAX_STA_CONN;

    // SoftAP security. Previously this copied EXAMPLE_ESP_WIFI_PASS (which is "")
    // into the config and then forced WIFI_AUTH_OPEN — the passphrase field was
    // dead code and every byte on this AP, dashboard + SIP signalling + RTP media
    // alike, went out in the clear. DeviceConfig owns the choice now; it defaults
    // to open so an already-deployed fleet is not cut off by a firmware update
    // (see DeviceConfig.hpp), and is flipped from the dashboard or at flash time.
    const bool ap_secure = DeviceConfig::isApSecure();
    if (ap_secure) {
        std::string psk = DeviceConfig::getApPsk();
        strlcpy((char*)wifi_config.ap.password, psk.c_str(), sizeof(wifi_config.ap.password));
        wifi_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
        // Yes, this logs the passphrase in the clear. This is the HEADLESS build:
        // there is no screen, so the UART console is the operator's only way to
        // learn a passphrase the device generated for itself. Anyone with a serial
        // cable is already inside the physical trust boundary (docs/THREAT_MODEL.md).
        ESP_LOGI(TAG, "INFRA: SoftAP passphrase (WPA2): %s", psk.c_str());
    } else {
        wifi_config.ap.password[0] = '\0';
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    // Explicitly start the embedded DHCP server so connected IP phones get leases.
    esp_err_t dhcps_err = esp_netif_dhcps_start(ap_netif);
    if (dhcps_err != ESP_OK && dhcps_err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED) {
        ESP_LOGW(TAG, "dhcps_start returned %d — phones may not get leases", dhcps_err);
    }

    ESP_LOGI(TAG, "INFRA: SoftAP SSID:%s channel:%d auth:%s  DHCP server active",
             EXAMPLE_ESP_WIFI_SSID, EXAMPLE_ESP_WIFI_CHANNEL,
             ap_secure ? "WPA2-PSK" : "OPEN");
    return "192.168.4.1";  // Default ESP32 AP gateway / bind address
}

// ── CLIENT topology: Wi-Fi STA — get DHCP from upstream router ────────────────
// Returns the obtained IP address string, or empty string on timeout.
static std::string wifi_init_sta(void)
{
    s_sta_event_group = xEventGroupCreate();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler,
                                                        NULL, NULL));

    // Read saved SSID/password from NVS.
    char ssid[64] = {};
    char pass[64] = {};
    nvs_handle_t nvs_h;
    if (nvs_open("storage", NVS_READONLY, &nvs_h) == ESP_OK) {
        size_t ssid_len = sizeof(ssid);
        size_t pass_len = sizeof(pass);
        nvs_get_str(nvs_h, "wifi_ssid", ssid, &ssid_len);
        nvs_get_str(nvs_h, "wifi_pass", pass, &pass_len);
        nvs_close(nvs_h);
    }

    if (ssid[0] == '\0') {
        ESP_LOGW(TAG, "CLIENT: no saved SSID — cannot connect in STA mode");
        return "";
    }

    wifi_config_t wifi_config = {};
    strlcpy((char*)wifi_config.sta.ssid,     ssid, sizeof(wifi_config.sta.ssid));
    strlcpy((char*)wifi_config.sta.password, pass, sizeof(wifi_config.sta.password));
    wifi_config.sta.threshold.authmode = WIFI_AUTH_OPEN;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    // WIFI_EVENT_STA_START fires wifi_event_handler which calls esp_wifi_connect().

    ESP_LOGI(TAG, "CLIENT: connecting to SSID \"%s\" (timeout 15 s)...", ssid);
    EventBits_t bits = xEventGroupWaitBits(s_sta_event_group,
                                           STA_GOT_IP_BIT,
                                           pdFALSE, pdTRUE,
                                           pdMS_TO_TICKS(15000));
    if (!(bits & STA_GOT_IP_BIT)) {
        ESP_LOGE(TAG, "CLIENT: no IP after 15 s");
        return "";
    }
    return s_sta_ip;
}

// ── SIP server task ────────────────────────────────────────────────────────────
static std::string s_sip_ip;  // set before task is spawned

void sip_server_task(void *pvParameters)
{
    int port = 5060;
    ESP_LOGI("SipServerTask", "Starting SipServer on %s:%d", s_sip_ip.c_str(), port);

    SipServer* srv = new SipServer(s_sip_ip, port);
    // Publish with release so the HTTP task's acquire-load sees a fully-constructed
    // object (not a half-initialised one) the moment it observes the non-null pointer.
    g_sipServer.store(srv, std::memory_order_release);
    while (1) {
        srv->getHandler().tick();
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    vTaskDelete(NULL);
}

void http_server_task(void *pvParameters)
{
    // Start the dashboard IMMEDIATELY — do not wait for g_sipServer. On an
    // unprovisioned device the SIP stack is held dark until an admin credential
    // is committed via this web UI, so waiting here deadlocks onboarding
    // (HTTP ← SIP ← credential ← HTTP). HttpServer null-checks the handler on
    // every endpoint; the live registrar is attached in the loop below.
    ESP_LOGI("HttpTask", "Starting CGA CRT Dashboard on %s:%d", s_sip_ip.c_str(), HTTP_DASHBOARD_PORT);

    HttpServer http(s_sip_ip, HTTP_DASHBOARD_PORT, nullptr);
    http.start();
    ESP_LOGI("HttpTask", "CGA CRT Dashboard is RUNNING at http://%s:%d/", s_sip_ip.c_str(), HTTP_DASHBOARD_PORT);
    // OTA rollback confirmation: the dashboard + SIP engine are up. After a few
    // seconds of healthy operation, mark this firmware image valid so the
    // bootloader keeps it (rollback is armed by
    // CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE; a crash/boot-loop before this point
    // rolls back to the previous slot). No-op unless the image is pending verify.
    int otaSettleSec = 0;
    bool otaConfirmed = false;
    bool handlerAttached = false;
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        SipServer* srv = g_sipServer.load(std::memory_order_acquire);
        if (!handlerAttached && srv != nullptr) {
            http.attachHandler(&srv->getHandler());
            handlerAttached = true;
            ESP_LOGI("HttpTask", "Dashboard: live SIP registrar attached");
        }
        if (!otaConfirmed && ++otaSettleSec >= 5) {
            otaConfirmed = true;
            if (OtaUpdater::isPendingVerify()) {
                OtaUpdater::markValid();
                ESP_LOGI("HttpTask", "OTA: new image confirmed valid after healthy boot");
            }
        }
    }

    vTaskDelete(NULL);
}

// ── Log drain task (Task 1B) ───────────────────────────────────────────────────
// Every drained line also goes to the remote collector, when one is configured.
// Runs on the drain task, after the line has already reached the UART -- serial
// is the sink that always works and must never wait on a network peer. Syslog's
// own send() is a fire-and-forget datagram on a connected socket, silent on
// failure by design (the RE-ENTRANCY RULE in Syslog.hpp: logging a syslog
// failure would come straight back here as another line to send).
static void log_tee_to_syslog(const char* line)
{
    if (line == nullptr || line[0] == '\0') {
        return;
    }
    Syslog::send(Syslog::Severity::Info, "pbx-log", line);
}

static void log_drain_task(void* /*arg*/)
{
    // Stack headroom is MEASURED, not assumed. This task carries drainToUart()'s
    // 256-byte line buffer plus, now, an lwip send() on the tee path; #183 sat
    // unwired precisely because nobody had numbers for that. Reported once, after
    // enough drains to have exercised the tee.
    unsigned drains = 0;
    while (1) {
        LogQueue::drainToUart();
        if (++drains == 500) {
            ESP_LOGI(TAG, "[log] drain task stack high-water: %u bytes free",
                     (unsigned)(uxTaskGetStackHighWaterMark(nullptr) * sizeof(StackType_t)));
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

extern "C" void app_main(void)
{
    // ── NVS init (keep ESP_ERROR_CHECK here — unrecoverable without flash) ──
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // ── Flash-time configuration seed ────────────────────────────────────────
    // Must run AFTER nvs_flash_init() (it writes NVS) and BEFORE anything reads
    // wifi_mode / wifi_ssid / the AP security keys below — the whole point is that
    // a board configured by the browser flasher comes up already configured on its
    // very first boot. A board with no cfgseed partition (any OTA-updated unit, or
    // the 4MB constrained layout) returns false here and is unaffected.
    if (DeviceConfig::applyFlashSeed()) {
        ESP_LOGI(TAG, "[boot] applied flash-time cfgseed");
    }

    // ── Task 1B: install non-blocking log queue + drain task ────────────────
    LogQueue::create();
    // Remote logging (#183). loadFromNvs() is a no-op when syslog_host is unset,
    // and send() returns immediately while unconfigured, so an unprovisioned board
    // pays nothing but the branch. Registered before the task starts so no line
    // drained during boot is missed once a host IS configured.
    Syslog::loadFromNvs();
    LogQueue::setTee(log_tee_to_syslog);
    // 3072, up from 2048: the tee adds an lwip send() to this task's deepest path.
    // The high-water mark logged by the task itself is what justifies this number
    // staying here or moving.
    xTaskCreatePinnedToCore(log_drain_task, "log_drain", 3072, nullptr, 1, nullptr, 0);

    // ── Networking stack init ────────────────────────────────────────────────
    // netif + default event loop are non-retryable boot prerequisites: if they fail the
    // Wi-Fi/lwIP stack cannot come up at all. Aborting here (matching the display build)
    // is correct — logging and continuing only defers the failure to a murkier crash
    // inside esp_wifi_init()/esp_netif_create_default_* on an uninitialized stack. The
    // recoverable, retry-with-backoff layer is the UDP socket in UdpServer, not this.
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // ── Task 1D: read topology from NVS ─────────────────────────────────────
    uint8_t topology_mode = TOPOLOGY_INFRA;  // default: INFRA (AP + DHCP)
    {
        nvs_handle_t nvs_h;
        if (nvs_open("storage", NVS_READONLY, &nvs_h) == ESP_OK) {
            uint8_t mode = 0;
            if (nvs_get_u8(nvs_h, "wifi_mode", &mode) == ESP_OK && mode != 0) {
                topology_mode = mode;
            }
            nvs_close(nvs_h);
        }
    }

    std::string sip_ip;
    if (topology_mode == TOPOLOGY_CLIENT) {
        ESP_LOGI(TAG, "[boot] topology = CLIENT (STA)");
        sip_ip = wifi_init_sta();
        if (sip_ip.empty()) {
            ESP_LOGE(TAG, "[boot] CLIENT: no IP — falling back to INFRA");
            // wifi_init_sta() already called esp_wifi_init() (and possibly esp_wifi_start()).
            // Tear the driver back down before the INFRA path calls esp_wifi_init() again;
            // a second init without an intervening deinit returns ESP_ERR_WIFI_INIT_STATE
            // and the ESP_ERROR_CHECK inside wifi_init_softap() would abort → boot loop.
            esp_wifi_stop();    // returns ESP_ERR_WIFI_NOT_STARTED if STA never started; ignored
            esp_wifi_deinit();
            // Free the STA event group created by wifi_init_sta(); after deinit no
            // more Wi-Fi events fire, so it can't be referenced again (the handler
            // null-checks it). Prevents a small FreeRTOS-heap leak on this fallback.
            if (s_sta_event_group) { vEventGroupDelete(s_sta_event_group); s_sta_event_group = nullptr; }
            topology_mode = TOPOLOGY_INFRA;
        }
    }

    if (topology_mode == TOPOLOGY_INFRA) {
        ESP_LOGI(TAG, "[boot] topology = INFRA (AP + DHCP server)");
        sip_ip = wifi_init_softap();
    }

    s_sip_ip = sip_ip;

    // ── Task 1C: provisioning gate ───────────────────────────────────────────
    // Read the "provisioned" flag from NVS. If absent or 0, hold the SIP stack
    // dark until an admin credential is committed via the dashboard.
    bool is_provisioned = false;
    {
        nvs_handle_t nvs_h;
        if (nvs_open("storage", NVS_READONLY, &nvs_h) == ESP_OK) {
            uint8_t flag = 0;
            if (nvs_get_u8(nvs_h, "provisioned", &flag) == ESP_OK && flag != 0) {
                is_provisioned = true;
            }
            nvs_close(nvs_h);
        }
    }

    // ── Launch HTTP dashboard on Core 0 (always — needed to provision) ─────────
    // The HTTP dashboard must start even on an unprovisioned device so the admin
    // can submit credentials via the web interface.
    xTaskCreatePinnedToCore(&http_server_task, "http_server_task", 8192, NULL, 4, NULL, 0);

    if (!is_provisioned) {
        ESP_LOGW(TAG, "[boot] device unprovisioned — SIP stack held dark until credential committed");

        // Bounded wait: poll AdminAuth every 2 s until a credential is set via the
        // HTTP dashboard. The drain task (priority 1) flushes logs during the delays.
        // If nothing arrives within the cap — e.g. the HTTP stack failed to come up —
        // reboot to retry from a clean state rather than hang here forever (no
        // watchdog covers this provisioning gate, so an unbounded spin is unrecoverable).
        constexpr int kMaxCredentialWaitSec = 1800;   // 30 minutes
        int credentialWaitSec = 0;
        while (!AdminAuth::credentialIsSet()) {
            vTaskDelay(pdMS_TO_TICKS(2000));
            credentialWaitSec += 2;
            if (credentialWaitSec >= kMaxCredentialWaitSec) {
                ESP_LOGE(TAG, "[boot] no admin credential after %d s — rebooting to retry",
                         kMaxCredentialWaitSec);
                esp_restart();
            }
            ESP_LOGI(TAG, "[boot] waiting for admin credential...");
        }

        // Persist the provisioned flag so we skip this gate on the next boot.
        nvs_handle_t nvs_h;
        if (nvs_open("storage", NVS_READWRITE, &nvs_h) == ESP_OK) {
            nvs_set_u8(nvs_h, "provisioned", 1);
            nvs_commit(nvs_h);
            nvs_close(nvs_h);
        }
        ESP_LOGI(TAG, "[boot] credential set — unblocking SIP stack");
    }

    // ── Launch SIP server on Core 1 (gated on provisioning) ─────────────────
    xTaskCreatePinnedToCore(&sip_server_task, "sip_server_task", 8192, NULL, 5, NULL, 1);
}

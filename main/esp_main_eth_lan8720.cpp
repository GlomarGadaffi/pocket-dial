/*
 * esp_main_eth_lan8720.cpp — ESP-IDF entry point for SipServer over LAN8720 Ethernet
 *
 * Targets: LilyGO T-Internet-COM
 *          (classic ESP32 + LAN8720 PHY via the internal EMAC / RMII, 10/100 Mbps)
 *
 * Unlike the Waveshare ESP32-S3-ETH (W5500 over SPI — see esp_main_eth.cpp), this
 * board uses the ORIGINAL ESP32's built-in Ethernet MAC driving an external
 * LAN8720 PHY over RMII. The ESP32 sources the 50 MHz RMII reference clock from
 * its internal APLL and outputs it on GPIO0 (the board's ETH_CLOCK_GPIO0_OUT).
 *
 * Build:   idf.py set-target esp32
 *          idf.py -D SIP_TRANSPORT=lan8720 build
 *
 * Pin mapping is taken from the T-Internet-COM schematic + example/Arduino/ETHDemo/config.h.
 * The LilyGO ESP-IDF examples are legacy IDF v4.x (smi pins on eth_mac_config_t,
 * esp_eth_phy_new_lan8720, make build system) — this file uses the CURRENT v5.3.x
 * internal-EMAC API instead: eth_esp32_emac_config_t + esp_eth_phy_new_lan87xx.
 *
 * VERIFY against YOUR board revision before flashing — in particular the PHY
 * power-enable pin and whether a separate PHY reset is wired.
 */

#include <cstring>
#include <string>
#include <atomic>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_system.h"
#include "bootloader_random.h"   // Issue #420: SAR ADC entropy source for esp_random()
#include "esp_event.h"
#include "esp_log.h"
#include "esp_task_wdt.h"   // Issue #185: sip_server_task TWDT subscription
#include "esp_idf_version.h"
#include "esp_eth.h"      // internal EMAC (esp_eth_mac_esp.h) + generic PHY (esp_eth_phy.h)
// LAN87xx PHY driver headers: ESP-IDF v6.0 removed the chip-specific PHY drivers
// (esp_eth_phy_new_lan87xx & friends) from the core esp_eth component and moved them
// to standalone managed components — here the `espressif/lan87xx` package, which
// ships this dedicated header. On v5.x esp_eth.h itself declared
// esp_eth_phy_new_lan87xx and this header does not exist, so the include (and the
// managed-component dependency in idf_component.yml) is gated to v6.0+.
//
// v6.0 is the enforced floor (main/CMakeLists.txt), so this include is no longer
// gated on ESP_IDF_VERSION — and neither is the cppcheck syntaxError suppression
// the host lint job previously needed to step over that gate.
#include "esp_eth_phy_lan87xx.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_mac.h"      // esp_read_mac, ESP_MAC_ETH
#include "esp_timer.h"    // esp_timer_get_time

#include "driver/gpio.h"

#include "lwip/err.h"
#include "lwip/sys.h"

#include "SipServer.hpp"
#include "HttpServer.hpp"
#include "OtaUpdater.hpp"
#include "AdminAuth.hpp"
#include "DeviceConfig.hpp"
#include "LogQueue.hpp"
#include "Syslog.hpp"
#include "SmtpClient.hpp"
#include "HeapLeakProbe.hpp"   // issue #273 leak probe (no-op unless CONFIG_HEAP_TRACING)

// ── Tag for ESP_LOG ────────────────────────────────────────────────────────
static const char* TAG = "SipServerLAN8720";

// ── Reset reason (Issue #185) ─────────────────────────────────────────────────
// Logged first thing in app_main(), below. This is a headless board's only way
// to say, after the fact, that its previous boot ended in ESP_RST_TASK_WDT --
// there is no screen and nobody was watching the UART in real time.
static const char* pdResetReasonString(esp_reset_reason_t reason)
{
    switch (reason) {
        case ESP_RST_POWERON:    return "POWERON";
        case ESP_RST_EXT:        return "EXT_PIN";
        case ESP_RST_SW:         return "SW_RESTART";
        case ESP_RST_PANIC:      return "PANIC";
        case ESP_RST_INT_WDT:    return "INT_WDT";
        case ESP_RST_TASK_WDT:   return "TASK_WDT";
        case ESP_RST_WDT:        return "OTHER_WDT";
        case ESP_RST_DEEPSLEEP:  return "DEEPSLEEP_WAKE";
        case ESP_RST_BROWNOUT:   return "BROWNOUT";
        case ESP_RST_SDIO:       return "SDIO";
        case ESP_RST_USB:        return "USB";
        case ESP_RST_JTAG:       return "JTAG";
        case ESP_RST_EFUSE:      return "EFUSE_ERROR";
        case ESP_RST_PWR_GLITCH: return "PWR_GLITCH";
        case ESP_RST_CPU_LOCKUP: return "CPU_LOCKUP";
        default:                 return "UNKNOWN";
    }
}

// ── LAN8720 RMII Pin Mapping (LilyGO T-Internet-COM) ──────────────────────
//    From example/Arduino/ETHDemo/config.h. Verify against your board revision.
#define LAN8720_MDC_GPIO       23   // ETH_MDC_PIN
#define LAN8720_MDIO_GPIO      18   // ETH_MDIO_PIN
#define LAN8720_PHY_ADDR        0   // ETH_ADDR
#define LAN8720_POWER_GPIO      4   // ETH_POWER_PIN — PHY enable, driven HIGH before init
// The Arduino BSP only toggles ETH_POWER_PIN (GPIO4); it does not drive a separate
// PHY reset through the IDF PHY driver. config.h also defines NRST=5, but on this
// board that is believed to be the 4G modem reset, NOT the LAN8720 — so leave the
// PHY reset unmanaged here (-1) and let the power-enable bring the PHY up. If your
// board wires a dedicated PHY reset, set this to that GPIO instead.
#define LAN8720_PHY_RST_GPIO   -1

// ── Static IP fallback (set USE_STATIC_IP to 1 to skip DHCP) ──────────────
#define USE_STATIC_IP     0
#define STATIC_IP         "192.168.1.200"
#define STATIC_GATEWAY    "192.168.1.1"
#define STATIC_NETMASK    "255.255.255.0"

// ── SIP configuration ─────────────────────────────────────────────────────
#define SIP_PORT          5060

// ── Topology constant ─────────────────────────────────────────────────────
#define TOPOLOGY_INFRA  2

// ── Event group bits ──────────────────────────────────────────────────────
#define ETH_CONNECTED_BIT BIT0
#define ETH_GOT_IP_BIT    BIT1

static EventGroupHandle_t s_eth_event_group = nullptr;
static esp_netif_t*       s_eth_netif       = nullptr;
static std::string        s_ip_addr;

// Global SIP server pointer so the HTTP dashboard task (Core 0) can reach the
// handler built by the SIP task. Atomic with acquire/release: a plain pointer is a
// cross-core data race on the SMP Xtensa (stale-null / half-built-object read, and
// the compiler could hoist the poll out of the attach loop).
static std::atomic<SipServer*> g_sipServer{nullptr};

#define HTTP_DASHBOARD_PORT 80

// ── Event handlers ────────────────────────────────────────────────────────

static void eth_event_handler(void* arg, esp_event_base_t event_base,
                              int32_t event_id, void* event_data)
{
    switch (event_id)
    {
        case ETHERNET_EVENT_CONNECTED:
            ESP_LOGI(TAG, "Ethernet link UP");
            xEventGroupSetBits(s_eth_event_group, ETH_CONNECTED_BIT);
            break;

        case ETHERNET_EVENT_DISCONNECTED:
            ESP_LOGW(TAG, "Ethernet link DOWN");
            xEventGroupClearBits(s_eth_event_group, ETH_CONNECTED_BIT | ETH_GOT_IP_BIT);
            break;

        default:
            break;
    }
}

static void ip_event_handler(void* arg, esp_event_base_t event_base,
                             int32_t event_id, void* event_data)
{
    if (event_id == IP_EVENT_ETH_GOT_IP)
    {
        ip_event_got_ip_t* event = static_cast<ip_event_got_ip_t*>(event_data);
        char buf[16];
        esp_ip4addr_ntoa(&event->ip_info.ip, buf, sizeof(buf));
        s_ip_addr = buf;

        ESP_LOGI(TAG, "IP:      %s", buf);
        esp_ip4addr_ntoa(&event->ip_info.gw, buf, sizeof(buf));
        ESP_LOGI(TAG, "Gateway: %s", buf);
        esp_ip4addr_ntoa(&event->ip_info.netmask, buf, sizeof(buf));
        ESP_LOGI(TAG, "Netmask: %s", buf);

        xEventGroupSetBits(s_eth_event_group, ETH_GOT_IP_BIT);
    }
}

// ── Ethernet initialisation (internal EMAC + LAN8720 over RMII) ────────────

static esp_eth_handle_t eth_init_lan8720(void)
{
    // ── Power-enable the PHY ────────────────────────────────────────────
    // Drive the enable/power GPIO high and give the LAN8720 a moment to come
    // out of power-down before we drive the RMII clock and touch MDIO.
    gpio_config_t pwr = {};
    pwr.mode         = GPIO_MODE_OUTPUT;
    pwr.pin_bit_mask = 1ULL << LAN8720_POWER_GPIO;
    ESP_ERROR_CHECK(gpio_config(&pwr));
    gpio_set_level(static_cast<gpio_num_t>(LAN8720_POWER_GPIO), 1);
    vTaskDelay(pdMS_TO_TICKS(10));

    // ── Internal EMAC (RMII) config ─────────────────────────────────────
    // Start from the IDF default (sets sane dma_burst_len / intr_priority /
    // interface=RMII), then pin the board-specific SMI pins and clock source.
    eth_esp32_emac_config_t emac_cfg = ETH_ESP32_EMAC_DEFAULT_CONFIG();
    emac_cfg.smi_gpio.mdc_num  = LAN8720_MDC_GPIO;
    emac_cfg.smi_gpio.mdio_num = LAN8720_MDIO_GPIO;
    emac_cfg.interface         = EMAC_DATA_INTERFACE_RMII;
    // ESP32 sources the 50 MHz RMII reference clock from its internal APLL and
    // outputs it on GPIO0 — this is the board's ETH_CLOCK_GPIO0_OUT wiring.
    // NOTE: GPIO0 is also a boot-strapping pin; driving the clock out of it can
    // interfere with auto-download mode. If flashing becomes flaky, hold the
    // BOOT button (or break the clock) during the esptool sync.
    // v6: the EMAC_APPL_CLK_OUT_GPIO enum is gone — clock_config.rmii.clock_gpio is
    // now a plain int GPIO number (see eth_mac_clock_config_t in esp_eth_mac_esp.h).
    // GPIO0 is the only RMII CLK-OUT capable pad on the classic ESP32.
    emac_cfg.clock_config.rmii.clock_mode = EMAC_CLK_OUT;
    emac_cfg.clock_config.rmii.clock_gpio = GPIO_NUM_0;  // 50 MHz RMII ref clock out on GPIO0

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    esp_eth_mac_t* mac = esp_eth_mac_new_esp32(&emac_cfg, &mac_config);

    // ── PHY config ──────────────────────────────────────────────────────
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.phy_addr       = LAN8720_PHY_ADDR;
    phy_config.reset_gpio_num = LAN8720_PHY_RST_GPIO;
    esp_eth_phy_t* phy = esp_eth_phy_new_lan87xx(&phy_config);

    // ── Install driver ──────────────────────────────────────────────────
    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth_handle = nullptr;
    ESP_ERROR_CHECK(esp_eth_driver_install(&eth_config, &eth_handle));

    // ── Set MAC address from ESP32 efuse ────────────────────────────────
    uint8_t mac_addr[6];
    esp_read_mac(mac_addr, ESP_MAC_ETH);
    ESP_ERROR_CHECK(esp_eth_ioctl(eth_handle, ETH_CMD_S_MAC_ADDR, mac_addr));

    return eth_handle;
}

// ── SIP server task ───────────────────────────────────────────────────────

static void sip_server_task(void* pvParameters)
{
    ESP_LOGI(TAG, "Starting SipServer on %s:%d", s_ip_addr.c_str(), SIP_PORT);
    SipServer* srv = new SipServer(s_ip_addr, SIP_PORT);
    // Publish with release so the HTTP task's acquire-load sees a fully-constructed
    // object the moment it observes the non-null pointer.
    g_sipServer.store(srv, std::memory_order_release);
    ESP_LOGI(TAG, "SIP server is RUNNING.  Point softphones at %s:%d",
             s_ip_addr.c_str(), SIP_PORT);

    unsigned long lastHeartbeat = 0;

    // Issue #185: subscribe to the Task Watchdog Timer so a tick() that never
    // returns (stuck on a lock, a runaway loop) produces a logged, controlled
    // reset instead of a silently unresponsive board. esp_task_wdt_add(NULL)
    // subscribes the CALLING (this) task; only this task's own loop below may
    // feed it via esp_task_wdt_reset() -- the TWDT has no "reset on behalf of
    // another task" call, by design (see sdkconfig.defaults for the PANIC=y
    // that makes a timeout actually reset the board). A failed subscription is
    // logged and non-fatal: better an unmonitored SIP task than no SIP task.
    esp_err_t wdtErr = esp_task_wdt_add(NULL);
    if (wdtErr != ESP_OK) {
        ESP_LOGE(TAG, "esp_task_wdt_add failed (%s) -- this task's stalls will go undetected",
                 esp_err_to_name(wdtErr));
    }

    while (true)
    {
        srv->getHandler().tick();
        // Fed once per 1 s loop, well inside the 5 s default TWDT timeout
        // (CONFIG_ESP_TASK_WDT_TIMEOUT_S). Harmless no-op if the add above failed.
        (void)esp_task_wdt_reset();
        vTaskDelay(pdMS_TO_TICKS(1000));
        unsigned long nowSec = (unsigned long)(esp_timer_get_time() / 1000000);
        if (nowSec - lastHeartbeat >= 30)
        {
            lastHeartbeat = nowSec;
            // Reset reason repeated on every heartbeat, not just the one-shot
            // boot-time log above: a serial reader that attaches after boot
            // would otherwise never learn why the board last came up. This
            // line is guaranteed to repeat within 30 s of attaching at any
            // point in the session.
            ESP_LOGI(TAG, "Heartbeat — IP: %s  Uptime: %lus  ResetReason: %s",
                     s_ip_addr.c_str(), nowSec, pdResetReasonString(esp_reset_reason()));
        }
    }

    vTaskDelete(nullptr);
}

static void http_server_task(void* pvParameters)
{
    // Start the dashboard IMMEDIATELY — do not wait for g_sipServer. On an
    // unprovisioned device the SIP stack is held dark until an admin
    // credential is committed via this web UI, so waiting here deadlocks
    // onboarding (HTTP ← SIP ← credential ← HTTP). HttpServer null-checks
    // the handler on every endpoint; the live registrar is attached below
    // once the SIP task constructs it.
    ESP_LOGI(TAG, "Starting CGA CRT Dashboard on %s:%d", s_ip_addr.c_str(), HTTP_DASHBOARD_PORT);

    HttpServer http(s_ip_addr, HTTP_DASHBOARD_PORT, nullptr);
    http.start();
    ESP_LOGI(TAG, "CGA CRT Dashboard RUNNING at http://%s:%d/",
             s_ip_addr.c_str(), HTTP_DASHBOARD_PORT);

    // OTA rollback confirmation (see docs/OTA.md): after a few seconds of healthy
    // operation, confirm this image so the bootloader won't roll it back on the
    // next reset. No-op unless the running image is pending verify.
    int otaSettleSec = 0;
    bool otaConfirmed = false;
    bool handlerAttached = false;
    while (true)
    {
        vTaskDelay(pdMS_TO_TICKS(1000));
        SipServer* srv = g_sipServer.load(std::memory_order_acquire);
        if (!handlerAttached && srv != nullptr)
        {
            http.attachHandler(&srv->getHandler());
            // Issue #164: push the persisted ITSP trunk settings into the
            // engine now that it exists. Without this the trunk stays at
            // Config{} (disabled) until someone re-saves the form, so a
            // configured trunk would silently not survive a reboot.
            srv->getHandler().applyStoredTrunkConfig();
            handlerAttached = true;
            ESP_LOGI(TAG, "Dashboard: live SIP registrar attached");
        }
        if (!otaConfirmed && ++otaSettleSec >= 5)
        {
            otaConfirmed = true;
            if (OtaUpdater::isPendingVerify())
            {
                OtaUpdater::markValid();
                ESP_LOGI(TAG, "OTA: new image confirmed valid after healthy boot");
            }
        }
    }

    vTaskDelete(nullptr);
}

// ── Log drain task (Task 1B) ──────────────────────────────────────────────────
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

// ── app_main ──────────────────────────────────────────────────────────────

extern "C" void app_main(void)
{
    // Issue #273: arms the internal-DRAM leak probe. No-op unless
    // CONFIG_HEAP_TRACING is set (sdkconfig.defaults.heap_trace only).
    // MUST be here rather than a global constructor -- constructors run
    // before the scheduler exists; see HeapLeakProbe.hpp.
    pdHeapLeakProbeStart();

    // Issue #185: log the reset cause before anything else can fail and bury
    // it. ESP_RST_TASK_WDT here means a TWDT-subscribed task (sip_server_task,
    // below) actually stalled on the PREVIOUS boot -- the only place a headless
    // unit can report that.
    ESP_LOGI(TAG, "[boot] reset reason: %s", pdResetReasonString(esp_reset_reason()));

    // ── True entropy for esp_random() (issue #420) ──────────────────────────
    // Same reasoning as esp_main_eth.cpp's block: without Wi-Fi/BT, esp_random()
    // is pseudo-random unless the SAR ADC source is on (random.rst), and every
    // security-relevant number on the board -- TLS included -- comes from it.
    // Enabled before anything can draw, and LEFT ON: this transport uses no ADC,
    // no I2S and no RF. On the classic ESP32 the source runs through I2S0 and
    // SAR2 (bootloader_random_esp32.c) -- it does not touch the APLL that clocks
    // the LAN8720's RMII reference out on GPIO0. ANYONE ADDING an ADC or I2S
    // user here must disable it first. Build-verified only: no lan8720 board on
    // the bench as of #420.
    bootloader_random_enable();
    ESP_LOGI(TAG, "[boot] entropy: SAR ADC source enabled and left on -- esp_random() is a TRNG (#420)");

    // ── NVS init (keep ESP_ERROR_CHECK here — unrecoverable without flash) ──
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // ── NVS schema version (issue #181) ─────────────────────────────
    // BEFORE applyFlashSeed(): the seed writer CREATES the very NVS namespaces the
    // "is this a pre-versioning device?" probe looks for, so running it first would
    // make every provisioned board look freshly installed and skip the migrations it
    // actually needs. Like applyFlashSeed() this touches only nvs/esp_log, never
    // esp_wifi, so it links on the pure-Ethernet transports. Logs its own outcome.
    DeviceConfig::ensureSchemaVersion();

    // ── Flash-time configuration seed ───────────────────────────────
    // Runs on the pure-Ethernet transports too, even though this build has no WiFi
    // radio and the seed's AP/STA fields are meaningless here. The seed also carries
    // wifi_mode (and will carry more fields), and applying it exactly once is gated
    // on the cfgseed_gen counter — so skipping it on Ethernet would mean a board
    // later reflashed to a WiFi variant silently ignores its flash-time config.
    // DeviceConfig deliberately does NOT include esp_wifi.h, so this links here.
    if (DeviceConfig::applyFlashSeed())
    {
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

    // ── Networking stack ────────────────────────────────────────────────
    // netif + default event loop are non-retryable boot prerequisites; abort on failure
    // (matching the display build) rather than logging and then crashing deeper on an
    // uninitialized stack. UdpServer's socket back-off is the recoverable-retry layer.
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    s_eth_event_group = xEventGroupCreate();

    // ── Register event handlers ─────────────────────────────────────────
    // Use the _instance_ form (the bare esp_event_handler_register is deprecated
    // since IDF v4.2 and returns no instance handle, so a re-init path would stack
    // duplicate handlers → double dispatch). Matches the wifi/display builds.
    ESP_ERROR_CHECK(esp_event_handler_instance_register(ETH_EVENT, ESP_EVENT_ANY_ID,
                                               &eth_event_handler, nullptr, nullptr));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_ETH_GOT_IP,
                                               &ip_event_handler, nullptr, nullptr));

    // ── Create default netif for Ethernet ───────────────────────────────
    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    s_eth_netif = esp_netif_new(&netif_cfg);

    // ── Initialise LAN8720 (internal EMAC over RMII) ────────────────────
    esp_eth_handle_t eth_handle = eth_init_lan8720();

    // ── Glue driver to netif ────────────────────────────────────────────
    // Both calls can fail (glue alloc on OOM; attach returns esp_err_t). Discarding
    // them left the driver installed but unconnected to lwIP, so the board waited
    // forever for a DHCP lease that could never arrive — fail loudly instead.
    auto eth_glue = esp_eth_new_netif_glue(eth_handle);
    if (eth_glue == nullptr) {
        ESP_LOGE(TAG, "FATAL: esp_eth_new_netif_glue failed (out of memory)");
        if (s_eth_event_group) { vEventGroupDelete(s_eth_event_group); s_eth_event_group = nullptr; }
        return;
    }
    ESP_ERROR_CHECK(esp_netif_attach(s_eth_netif, eth_glue));

    // ── Static IP (optional) ────────────────────────────────────────────
#if USE_STATIC_IP
    esp_netif_dhcpc_stop(s_eth_netif);
    esp_netif_ip_info_t ip_info = {};
    esp_netif_str_to_ip4(STATIC_IP,      &ip_info.ip);
    esp_netif_str_to_ip4(STATIC_GATEWAY,  &ip_info.gw);
    esp_netif_str_to_ip4(STATIC_NETMASK,  &ip_info.netmask);
    esp_netif_set_ip_info(s_eth_netif, &ip_info);
    ESP_LOGI(TAG, "Static IP configured: %s", STATIC_IP);
#endif

    // ── Start Ethernet ──────────────────────────────────────────────────
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));
    ESP_LOGI(TAG, "Waiting for Ethernet link + IP ...");

    // ── Wait for IP ─────────────────────────────────────────────────────
    EventBits_t bits = xEventGroupWaitBits(s_eth_event_group,
                                           ETH_GOT_IP_BIT,
                                           pdFALSE, pdTRUE,
                                           pdMS_TO_TICKS(30000));
    if (!(bits & ETH_GOT_IP_BIT))
    {
        ESP_LOGE(TAG, "FATAL: No IP after 30 s.  Check cable / link / DHCP.");
        if (s_eth_event_group) { vEventGroupDelete(s_eth_event_group); s_eth_event_group = nullptr; }
        return;
    }

    // ── Task 1D: INFRA mode — start DHCP server on Ethernet netif if requested
    {
        uint8_t topology_mode = 0;
        nvs_handle_t nvs_h;
        if (nvs_open("storage", NVS_READONLY, &nvs_h) == ESP_OK) {
            nvs_get_u8(nvs_h, "wifi_mode", &topology_mode);
            nvs_close(nvs_h);
        }
        if (topology_mode == TOPOLOGY_INFRA) {
            esp_err_t dhcps_err = esp_netif_dhcps_start(s_eth_netif);
            if (dhcps_err != ESP_OK && dhcps_err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED) {
                ESP_LOGW(TAG, "dhcps_start on eth netif returned %d", dhcps_err);
            } else {
                ESP_LOGI(TAG, "INFRA: DHCP server started on Ethernet netif");
            }
        }
    }

    // ── Task 1C: provisioning gate ───────────────────────────────────────────
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

    // ── Email (issue #159): start the SMTP worker task before the dashboard ────
    // that can queue sends into it. See the matching comment in esp_main_eth.cpp.
    SmtpClient::init();

    // ── Launch HTTP dashboard on Core 0 (always — needed to provision) ─────────
    xTaskCreatePinnedToCore(&http_server_task, "http_dashboard", 8192, nullptr, 4, nullptr, 0);

    if (!is_provisioned) {
        ESP_LOGW(TAG, "[boot] device unprovisioned — SIP stack held dark until credential committed");

        // Bounded wait (see esp_main.cpp): reboot to retry if no credential arrives
        // within the cap rather than hang forever with no watchdog on this gate.
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

        nvs_handle_t nvs_h;
        if (nvs_open("storage", NVS_READWRITE, &nvs_h) == ESP_OK) {
            nvs_set_u8(nvs_h, "provisioned", 1);
            nvs_commit(nvs_h);
            nvs_close(nvs_h);
        }
        ESP_LOGI(TAG, "[boot] credential set — unblocking SIP stack");
    }

    // ── Launch SIP server on Core 1 (gated on provisioning) ──────────────────
    xTaskCreatePinnedToCore(&sip_server_task, "sip_server", 8192, nullptr, 5, nullptr, 1);
}

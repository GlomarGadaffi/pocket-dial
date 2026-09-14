/*
 * esp_main_eth.cpp — ESP-IDF entry point for SipServer over W5500 Ethernet
 *
 * Targets: Waveshare ESP32-S3-ETH + PoE module
 *          (ESP32-S3R8 + W5500 via SPI, 10/100 Mbps)
 *
 * Initialises the W5500 Ethernet MAC/PHY through the esp_eth driver,
 * waits for a DHCP lease (or applies a static IP), then launches the
 * SIP registrar/proxy on the assigned address.
 *
 * Build:   idf.py set-target esp32s3 && idf.py build
 *
 * Pin mapping matches the Waveshare ESP32-S3-ETH schematic.
 * Verify against YOUR board revision before flashing.
 */

#include <cstring>
#include <string>
#include <atomic>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_idf_version.h"
#include "esp_eth.h"
// W5500 driver headers. ESP-IDF v6.0 split the W5500 MAC/PHY driver out of the
// core esp_eth component into the standalone `espressif/w5500` managed component
// (see main/idf_component.yml), which ships these dedicated headers. On v5.x the
// same API was declared by esp_eth.h and these headers did not exist, so this
// used to be gated behind `#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(6,0,0)`.
// v6.0 is now the enforced floor (main/CMakeLists.txt fails at configure time
// below it), so the gate — and the cppcheck syntaxError suppression the host
// lint job needed to get past it — are gone.
#include "esp_eth_mac_w5500.h"
#include "esp_eth_phy_w5500.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_mac.h"     // esp_read_mac, ESP_MAC_ETH
#include "esp_timer.h"   // esp_timer_get_time

#include "driver/gpio.h"
#include "driver/spi_master.h"

#include "lwip/err.h"
#include "lwip/sys.h"

#include "SipServer.hpp"
#include "HttpServer.hpp"
#include "OtaUpdater.hpp"
#include "AdminAuth.hpp"
#include "DeviceConfig.hpp"
#include "LogQueue.hpp"
#include "TimeSync.hpp"

// ── Tag for ESP_LOG ────────────────────────────────────────────────────────
static const char* TAG = "SipServerETH";

// ── W5500 SPI pin map (board-selected) ────────────────────────────────────
//   Chosen at build time by main/CMakeLists.txt from -D PD_ETH_BOARD=<board>:
//     elite     → LilyGO T-ETH-ELITE S3  (ESP32-S3-WROOM-1 + W5500)  ← DEFAULT
//     waveshare → Waveshare ESP32-S3-ETH (W5500, PoE)
//   Defaults to the Elite when neither macro is defined, so a stray build of
//   this file targets the board that's actually on the bench.
//   Both maps below are hardware-verified: the Elite continuously, the Waveshare
//   as of #155. A wrong pin here is not a soft failure -- esp_eth_driver_install()
//   returns ESP_ERR_TIMEOUT and the ESP_ERROR_CHECK at eth_init_w5500() aborts
//   the boot, so the board reset-loops with no network to diagnose it over.
#if defined(PD_ETH_BOARD_WAVESHARE)
#  define W5500_BOARD_NAME "Waveshare ESP32-S3-ETH"
// Verified on hardware 2026-09-07 (issue #155). The previous map here had SCLK
// and MISO transposed, CS and INT transposed, and no reset line; it did not just
// fail to link, it timed out inside esp_eth_driver_install() and the
// ESP_ERROR_CHECK aborted the boot, so the board sat in a reset loop
// (108 consecutive rst:0xc in one capture). These values are the ones the
// ESP32_AdBlocker_Reborn firmware has been running on this exact board.
#  define W5500_SCLK_GPIO  13
#  define W5500_MISO_GPIO  12
#  define W5500_MOSI_GPIO  11
#  define W5500_CS_GPIO    14
#  define W5500_INT_GPIO   10
#  define W5500_RST_GPIO   9    // Waveshare wires a real reset line; the Elite does not
#else  // PD_ETH_BOARD_ELITE (default)
#  define W5500_BOARD_NAME "LilyGO T-ETH-ELITE S3"
#  define W5500_SCLK_GPIO  48
#  define W5500_MISO_GPIO  47
#  define W5500_MOSI_GPIO  21
#  define W5500_CS_GPIO    45
#  define W5500_INT_GPIO   14   // Elite ETH_INT
#  define W5500_RST_GPIO   -1   // Elite ETH_RST not wired to a GPIO
#endif

#define W5500_SPI_HOST    SPI2_HOST
#define W5500_SPI_CLOCK   40    // MHz — max stable through the S3 GPIO matrix on this
                                // pin set (verified on hardware: 80 MHz hard-fails with
                                // ESP_ERR_TIMEOUT at driver install; the GPSPI divides an
                                // 80 MHz source by integers, so requests in 40..79 all
                                // land on 40 actual). The old 36 quietly ran at 26.7.

// ── Static IP fallback (set USE_STATIC_IP to 1 to skip DHCP) ──────────────
#define USE_STATIC_IP     0
#define STATIC_IP         "192.168.1.200"
#define STATIC_GATEWAY    "192.168.1.1"
#define STATIC_NETMASK    "255.255.255.0"

// ── SIP configuration ─────────────────────────────────────────────────────
#define SIP_PORT          5060

// ── Topology constants ─────────────────────────────────────────────────────
// Ethernet builds always receive IP from upstream (CLIENT behaviour).
// INFRA mode on ETH means the device also runs a DHCP server on the loopback
// netif (edge case for lab setups). Default: 0 = no loopback DHCP server.
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

        // Start the wall clock now that there is a route. Non-blocking and
        // idempotent, so a DHCP renew or a cable bounce re-entering this handler
        // costs nothing. Deliberately NOT awaited: the SIP registrar must come up
        // whether or not a time server is reachable, and every consumer already
        // has to handle timesync::isSynced() == false.
        timesync::start();

        xEventGroupSetBits(s_eth_event_group, ETH_GOT_IP_BIT);
    }
}

// ── Ethernet initialisation ───────────────────────────────────────────────

static esp_eth_handle_t eth_init_w5500(void)
{
    ESP_LOGI(TAG, "W5500 board: %s — SCLK=%d MISO=%d MOSI=%d CS=%d INT=%d RST=%d @ %d MHz",
             W5500_BOARD_NAME, W5500_SCLK_GPIO, W5500_MISO_GPIO, W5500_MOSI_GPIO,
             W5500_CS_GPIO, W5500_INT_GPIO, W5500_RST_GPIO, W5500_SPI_CLOCK);

    // ── SPI bus ─────────────────────────────────────────────────────────
    spi_bus_config_t buscfg = {};
    buscfg.miso_io_num   = W5500_MISO_GPIO;
    buscfg.mosi_io_num   = W5500_MOSI_GPIO;
    buscfg.sclk_io_num   = W5500_SCLK_GPIO;
    buscfg.quadwp_io_num = -1;
    buscfg.quadhd_io_num = -1;
    ESP_ERROR_CHECK(spi_bus_initialize(W5500_SPI_HOST, &buscfg, SPI_DMA_CH_AUTO));

    // ── SPI device for W5500 ────────────────────────────────────────────
    spi_device_interface_config_t devcfg = {};
    devcfg.command_bits   = 16;   // W5500 uses 16-bit address phase
    devcfg.address_bits   = 8;    // 8-bit control phase
    devcfg.mode           = 0;
    devcfg.clock_speed_hz = W5500_SPI_CLOCK * 1000 * 1000;
    devcfg.spics_io_num   = W5500_CS_GPIO;
    devcfg.queue_size     = 20;

#if W5500_INT_GPIO >= 0
    // ── GPIO ISR service (required for the W5500 INT pin) ───────────────
    // The esp_eth W5500 driver registers an ISR on int_gpio_num when it
    // starts. On ESP-IDF v6 the GPIO ISR service is NOT auto-installed, so
    // without this the handler-add fails ("gpio: ... isr service is not
    // installed") and the driver never receives link/RX interrupts — the
    // link silently never comes up even with a cable attached. Idempotent:
    // ESP_ERR_INVALID_STATE means another subsystem already installed it.
    {
        esp_err_t isr_rc = gpio_install_isr_service(0);
        if (isr_rc != ESP_OK && isr_rc != ESP_ERR_INVALID_STATE)
        {
            ESP_ERROR_CHECK(isr_rc);
        }
    }
#endif

    // ── MAC config ──────────────────────────────────────────────────────
    // ESP-IDF v5.1+ changed the macro to accept (spi_host, &spi_devcfg);
    // the driver now allocates the SPI device internally.
    eth_w5500_config_t w5500_config = ETH_W5500_DEFAULT_CONFIG(W5500_SPI_HOST, &devcfg);
    w5500_config.int_gpio_num = static_cast<gpio_num_t>(W5500_INT_GPIO);

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    esp_eth_mac_t* mac = esp_eth_mac_new_w5500(&w5500_config, &mac_config);

    // ── PHY config ──────────────────────────────────────────────────────
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.autonego_timeout_ms = 0; // W5500 has internal PHY
    phy_config.reset_gpio_num      = static_cast<gpio_num_t>(W5500_RST_GPIO);
    esp_eth_phy_t* phy = esp_eth_phy_new_w5500(&phy_config);

    // ── Install driver ──────────────────────────────────────────────────
    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth_handle = nullptr;
    esp_err_t err = esp_eth_driver_install(&eth_config, &eth_handle);
    if (err == ESP_ERR_TIMEOUT)
    {
        ESP_LOGE(TAG, "W5500 did not respond on SCLK=%d MISO=%d MOSI=%d CS=%d. "
                      "Check that PD_ETH_BOARD (%s) matches your hardware.",
                 W5500_SCLK_GPIO, W5500_MISO_GPIO, W5500_MOSI_GPIO,
                 W5500_CS_GPIO, W5500_BOARD_NAME);
    }
    ESP_ERROR_CHECK(err);

    // ── Set MAC address from ESP32 efuse (base + 1) ─────────────────────
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
    while (true)
    {
        srv->getHandler().tick();
        vTaskDelay(pdMS_TO_TICKS(1000));
        unsigned long nowSec = (unsigned long)(esp_timer_get_time() / 1000000);
        if (nowSec - lastHeartbeat >= 30)
        {
            lastHeartbeat = nowSec;
            ESP_LOGI(TAG, "Heartbeat — IP: %s  Uptime: %lus",
                     s_ip_addr.c_str(), nowSec);
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
static void log_drain_task(void* /*arg*/)
{
    while (1) {
        LogQueue::drainToUart();
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// ── app_main ──────────────────────────────────────────────────────────────

extern "C" void app_main(void)
{
    // ── NVS init (keep ESP_ERROR_CHECK here — unrecoverable without flash) ──
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

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
    xTaskCreatePinnedToCore(log_drain_task, "log_drain", 2048, nullptr, 1, nullptr, 0);

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

    // ── Initialise W5500 ────────────────────────────────────────────────
    esp_eth_handle_t eth_handle = eth_init_w5500();

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
        ESP_LOGE(TAG, "FATAL: No IP after 30 s.  Check cable / PoE / DHCP.");
        if (s_eth_event_group) { vEventGroupDelete(s_eth_event_group); s_eth_event_group = nullptr; }
        return;
    }

    // ── Task 1D: INFRA mode — start DHCP server on loopback netif if requested
    {
        uint8_t topology_mode = 0;
        nvs_handle_t nvs_h;
        if (nvs_open("storage", NVS_READONLY, &nvs_h) == ESP_OK) {
            nvs_get_u8(nvs_h, "wifi_mode", &topology_mode);
            nvs_close(nvs_h);
        }
        if (topology_mode == TOPOLOGY_INFRA) {
            // Ethernet INFRA: enable DHCP server on the Ethernet netif so
            // directly-connected phones on the LAN segment get leases.
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

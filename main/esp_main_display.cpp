#include <cstring>
#include <cstdio>
#include <atomic>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_timer.h"
#include "mdns.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "driver/spi_master.h"
#include "driver/ledc.h"

// standard Espressif esp_lcd panel/touch drivers
#include "esp_lcd_axs15231b.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_io.h"

// LVGL & UI Layer
#include "lvgl.h"
#include "ui.h"

// SIP & Servers
#include <string>
#include <vector>
#include <tuple>
#include <utility>
#include <unordered_set>
#include "SipServer.hpp"
#include "HttpServer.hpp"
#include "OtaUpdater.hpp"
#include "DnsServer.hpp"
#include "DeviceConfig.hpp"
#include "IPHelper.hpp"
#include "SmtpClient.hpp"
#include "host_compat.h"
#include "HeapLeakProbe.hpp"   // issue #273 leak probe (no-op unless CONFIG_HEAP_TRACING)

static const char *TAG = "main_display";

// Board Pin mappings (Guition cheap black display JC3248W535)
#define TFT_CS      45
#define TFT_SCK     47
#define TFT_D0      21
#define TFT_D1      48
#define TFT_D2      40
#define TFT_D3      39
#define TFT_BL      1
#define TFT_TE      38   // Tearing-Effect (vblank) output from the panel

#define TOUCH_SDA   4
#define TOUCH_SCL   8
// NOTE: the JC3248W535's AXS15231B touch controller shares the display silicon and
// is read over I2C only — it has NO dedicated INT/RST routed to a usable GPIO. The
// reference board map (esp-idf-jc3248w535-axs15231b/main/board.h) defines neither,
// and GPIO 11/12 (previously mis-assigned here as TOUCH_INT/TOUCH_RST) are actually
// the microSD CMD/CLK lines on this board. We therefore drive touch in polled mode
// (int/rst = GPIO_NUM_NC); see hardware_touch_init().

// Onboarding credentials.
//
// ONBOARDING_PASS used to be the literal "12345678", baked into every unit and
// published in this repo. The captive-portal AP below is WPA_WPA2_PSK, so the
// encryption was purely decorative: anyone within radio range knew the key, and
// with it the dashboard, the SIP signalling and the RTP media on that AP. The
// passphrase is now per-device, generated from the hardware CSPRNG on first use
// and persisted in NVS — see DeviceConfig.hpp. It is still shown on the LVGL
// onboarding screen (and encoded into the join QR), which is the whole reason
// this variant can afford a secret nobody wrote down in advance.
#define ONBOARDING_SSID "My-Ap"

// Standalone (normal operating) AP SSID. Named once because it is now used twice:
// by the bringup AND by the on-glass credentials splash, which would silently show
// the wrong network to join if the two ever drifted apart.
#define STANDALONE_SSID "esp32-sipserver"

// Cached at boot in app_main() and held for the process lifetime. ui.cpp copies
// the string into its labels/QR immediately, but the AP itself is re-read on any
// later bringup, so a file-scope home for it is both cheap and unambiguous.
static std::string g_apPsk;

// Active server objects. g_sipServer is built by sip_server_task and read by the
// http/status tasks; atomic with acquire/release so a reader never observes a
// half-built object or a hoisted-out-of-loop poll (it also future-proofs the read
// against a cross-core move).
static std::atomic<SipServer*> g_sipServer{nullptr};
static HttpServer* g_httpServer = nullptr;
static DnsServer* g_dnsServer = nullptr;
static QueueHandle_t s_log_queue = NULL;

// Recursive mutex guarding ALL LVGL access. LVGL is single-threaded, but the renderer
// (lvgl_task on core 1), system_status_task, and the main task all mutate the object
// tree. Every lv_*/ui_* call from outside lvgl_task must hold this, or a concurrent
// lv_timer_handler() layout walk faults (LoadProhibited in get_prop_core).
static SemaphoreHandle_t s_lvgl_mux = NULL;
static inline bool lvgl_lock(int timeout_ms) {
    return s_lvgl_mux && xSemaphoreTakeRecursive(s_lvgl_mux,
               timeout_ms < 0 ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
}
static inline void lvgl_unlock(void) { if (s_lvgl_mux) xSemaphoreGiveRecursive(s_lvgl_mux); }

// Tearing-Effect (TE) vsync. The panel pulses TFT_TE (GPIO38) at the start of vertical
// blanking once TEON (0x35) is enabled in the init sequence. The flush callback waits for
// this pulse before writing each frame, so the whole-screen redraw lands during blanking
// (tear-free: a full frame clocks out in ~15 ms, inside the ~16.7 ms 60 Hz scan period).
static SemaphoreHandle_t s_te_sem = NULL;
static void IRAM_ATTR te_isr_handler(void *arg) {
    BaseType_t hp = pdFALSE;
    if (s_te_sem) xSemaphoreGiveFromISR(s_te_sem, &hp);
    if (hp) portYIELD_FROM_ISR();
}

// Banded flush. LVGL runs in FULL_REFRESH mode — this AXS15231B panel garbles on partial
// windowed writes, so the whole 320x480 frame is repainted each refresh (do NOT switch to
// partial; it looks fine in code and corrupts on the glass). The SPI master can't DMA straight
// from PSRAM, so flush_cb copies the frame out one band at a time into a small internal
// DMA-capable bounce buffer, clocking each band to the panel and signalling LVGL after the last.
#define FLUSH_BAND_ROWS 80
static SemaphoreHandle_t s_flush_done_sem = NULL;  // given by the SPI transfer-done callback
static lv_color_t       *s_band_buf       = NULL;  // internal DMA bounce (320 x FLUSH_BAND_ROWS)

static std::string g_localIp = "192.168.4.1";
static int g_stationNum = 0;
static bool g_setupComplete = false;

// Cached operational Wi-Fi config, read once from NVS at boot (Fix #7). wifi_mode only
// changes via a topology switch, which reboots — so these never go stale at runtime.
// system_status_task uses these instead of re-opening NVS every tick under the LVGL
// mutex (flash I/O held under s_lvgl_mux stalls the render path / risks TE-vsync misses).
static uint8_t g_wifiMode      = 0;
static char    g_wifiSsid[33]  = {0};

// Captive-portal decay: if no one confirms config within this window, the device "decays"
// into open Standalone AP mode so it's a usable PBX unattended. The web "I'm configuring"
// confirm (HttpServer /api/configuring) sets g_decayHold to pause the countdown. The flag is
// owned by HttpServer (shared with the dashboard) so it links cleanly in every transport.
#define CAPTIVE_DECAY_SECONDS 300   // 5 minutes
extern volatile bool g_decayHold;

// Task scheduler loop counters
static int prevStations = -1;
static int prevExtensions = -1;
static int prevSessions = -1;

// Forward event declarations
static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data);

// ─── FreeRTOS background log interceptor ───
// We redirect ESP_LOGX outputs directly to the on-screen scroll area in addition to Serial.
extern "C" {
    vprintf_like_t original_log_vprintf = NULL;
    int screen_log_vprintf(const char *fmt, va_list tag) {
        char buf[256];
        int len = vsnprintf(buf, sizeof(buf) - 1, fmt, tag);
        if (len > 0) {
            // Trim carriage returns and newlines
            while(len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) {
                buf[len-1] = '\0';
                len--;
            }
            if (len > 0 && s_log_queue) {
                // esp_log_set_vprintf hooks ALL ESP_LOGx, including any logged from
                // ISR context. The plain xQueueSend must never run in an ISR, so
                // dispatch the FromISR variant when we are in one (M-3).
                if (xPortInIsrContext()) {
                    BaseType_t hp = pdFALSE;
                    xQueueSendFromISR(s_log_queue, buf, &hp);
                    if (hp) portYIELD_FROM_ISR();
                } else {
                    xQueueSend(s_log_queue, buf, 0);  // non-blocking; drop if full
                }
            }
        }
        if (original_log_vprintf) {
            return original_log_vprintf(fmt, tag);
        }
        return len;
    }
}

// ─── Low Level Hardware Panel & Touch init ───
static void hardware_display_init(lv_disp_drv_t* disp_drv) {
    ESP_LOGI(TAG, "Initializing AXS15231B Backlight (LEDC PWM)...");
    // The JC3248W535 backlight is PWM-driven, not a plain on/off GPIO. Driving it with a
    // bare GPIO-high leaves it dim/under-driven; LEDC at full duty gives real brightness.
    ledc_timer_config_t bl_timer = {};
    bl_timer.speed_mode      = LEDC_LOW_SPEED_MODE;
    bl_timer.duty_resolution = LEDC_TIMER_10_BIT;
    bl_timer.timer_num       = LEDC_TIMER_1;
    bl_timer.freq_hz         = 5000;
    bl_timer.clk_cfg         = LEDC_AUTO_CLK;
    ESP_ERROR_CHECK(ledc_timer_config(&bl_timer));
    ledc_channel_config_t bl_chan = {};
    bl_chan.gpio_num   = TFT_BL;
    bl_chan.speed_mode = LEDC_LOW_SPEED_MODE;
    bl_chan.channel    = LEDC_CHANNEL_0;
    bl_chan.timer_sel  = LEDC_TIMER_1;
    bl_chan.intr_type  = LEDC_INTR_DISABLE;
    bl_chan.duty       = 1023;  // 100% on a 10-bit resolution
    bl_chan.hpoint     = 0;
    ESP_ERROR_CHECK(ledc_channel_config(&bl_chan));

    ESP_LOGI(TAG, "Initializing LCD QSPI Panel Bus...");
    // Field assignment rather than AXS15231B_PANEL_BUS_QSPI_CONFIG: that macro lists
    // spi_bus_config_t's anonymous-union fields out of declaration order, which is a
    // hard error in C++ (this is a .cpp). Equivalent result, order-independent.
    spi_bus_config_t bus_config = {};
    bus_config.sclk_io_num     = TFT_SCK;
    bus_config.data0_io_num    = TFT_D0;
    bus_config.data1_io_num    = TFT_D1;
    bus_config.data2_io_num    = TFT_D2;
    bus_config.data3_io_num    = TFT_D3;
    bus_config.max_transfer_sz = 320 * 480 * sizeof(uint16_t);
    ESP_ERROR_CHECK(spi_bus_initialize(SPI2_HOST, &bus_config, SPI_DMA_CH_AUTO));

    ESP_LOGI(TAG, "Initializing Panel IO handle...");
    esp_lcd_panel_io_handle_t io_handle = NULL;
    esp_lcd_panel_io_spi_config_t io_config = AXS15231B_PANEL_IO_QSPI_CONFIG(
        TFT_CS, 
        [](esp_lcd_panel_io_handle_t panel_io, esp_lcd_panel_io_event_data_t *edata, void *user_ctx) -> bool {
            // Signals completion of ONE band's DMA. flush_cb waits on this per band and calls
            // lv_disp_flush_ready() itself only after the final band.
            BaseType_t hp = pdFALSE;
            if (s_flush_done_sem) xSemaphoreGiveFromISR(s_flush_done_sem, &hp);
            return hp == pdTRUE;
        },
        disp_drv
    );
    ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)SPI2_HOST, &io_config, &io_handle));

    ESP_LOGI(TAG, "Instantiating axs15231b panel driver...");
    esp_lcd_panel_handle_t panel_handle = NULL;
    esp_lcd_panel_dev_config_t panel_dev_config = {};
    panel_dev_config.reset_gpio_num = GPIO_NUM_NC; // Reset pin is not defined
    // ESP-IDF 6.0 renamed esp_lcd_panel_dev_config_t::rgb_endian -> rgb_ele_order
    // (and the LCD_RGB_ENDIAN_* enum -> LCD_RGB_ELEMENT_ORDER_*).
    panel_dev_config.rgb_ele_order = LCD_RGB_ELEMENT_ORDER_BGR;
    panel_dev_config.bits_per_pixel = 16;
    
    axs15231b_vendor_config_t vendor_config = {};
    vendor_config.flags.use_qspi_interface = 1;
    panel_dev_config.vendor_config = &vendor_config;
    
    ESP_ERROR_CHECK(esp_lcd_new_panel_axs15231b(io_handle, &panel_dev_config, &panel_handle));
    ESP_ERROR_CHECK(esp_lcd_panel_reset(panel_handle));
    ESP_ERROR_CHECK(esp_lcd_panel_init(panel_handle));
    // NOTE: this driver's disp_on_off handler has INVERTED semantics — its bool parameter
    // means "off" (true => DISPOFF, false => DISPON), not the usual esp_lcd "on" meaning.
    // So `false` turns the display ON. Passing `true` here was sending DISPOFF and blanking
    // the panel (black screen) regardless of backlight/GRAM. The working reference also
    // calls this with false.
    ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(panel_handle, false));

    // Tearing-Effect vsync input: the panel pulses TFT_TE at the start of vertical blanking
    // (TEON 0x35 is sent in the init sequence). The flush_cb waits on s_te_sem so each
    // whole-frame redraw is written during blanking -> tear-free.
    s_te_sem = xSemaphoreCreateBinary();
    s_flush_done_sem = xSemaphoreCreateBinary();
    gpio_config_t te_cfg = {};
    te_cfg.mode = GPIO_MODE_INPUT;
    te_cfg.pin_bit_mask = 1ULL << TFT_TE;
    te_cfg.intr_type = GPIO_INTR_POSEDGE;
    gpio_config(&te_cfg);
    gpio_install_isr_service(0);  // harmless if already installed
    gpio_isr_handler_add((gpio_num_t)TFT_TE, te_isr_handler, NULL);

    disp_drv->user_data = panel_handle;
}

static esp_lcd_touch_handle_t hardware_touch_init() {
    ESP_LOGI(TAG, "Initializing Touch I2C Bus...");
    // New i2c_master driver (present since 5.2, mandatory on 6.0 where the legacy
    // driver/i2c.h was removed). Field assignment keeps it C++ designated-init safe.
    i2c_master_bus_config_t i2c_bus_conf = {};
    i2c_bus_conf.i2c_port = I2C_NUM_0;
    i2c_bus_conf.sda_io_num = (gpio_num_t)TOUCH_SDA;
    i2c_bus_conf.scl_io_num = (gpio_num_t)TOUCH_SCL;
    i2c_bus_conf.clk_source = I2C_CLK_SRC_DEFAULT;
    i2c_bus_conf.glitch_ignore_cnt = 7;
    i2c_bus_conf.flags.enable_internal_pullup = true;
    i2c_master_bus_handle_t i2c_bus = NULL;
    ESP_ERROR_CHECK(i2c_new_master_bus(&i2c_bus_conf, &i2c_bus));

    esp_lcd_panel_io_handle_t touch_io = NULL;
    esp_lcd_panel_io_i2c_config_t touch_io_config = ESP_LCD_TOUCH_IO_I2C_AXS15231B_CONFIG();
    // The AXS15231B config macro predates the i2c_master driver and leaves scl_speed_hz
    // at 0, which i2c_master_bus_add_device rejects ("invalid scl frequency"). Set it.
    touch_io_config.scl_speed_hz = 400000;
    // ESP-IDF 6.0 dropped the legacy esp_lcd_new_panel_io_i2c and promoted the _v2
    // (i2c_master_bus_handle_t) signature to the canonical name.
    ESP_ERROR_CHECK(esp_lcd_new_panel_io_i2c(i2c_bus, &touch_io_config, &touch_io));

    ESP_LOGI(TAG, "Creating axs15231b touch driver...");
    esp_lcd_touch_handle_t touch_handle = NULL;
    esp_lcd_touch_config_t touch_config = {};
    touch_config.x_max = 320;
    touch_config.y_max = 480;
    // No dedicated touch INT/RST GPIO on the JC3248W535 (GPIO 11/12 are the SD CMD/CLK
    // lines, not touch). NC => the driver polls coordinates over I2C, matching the
    // known-good reference. Driving the SD pins as touch INT/RST broke nothing visibly
    // because read_data polls anyway, but it mis-claimed shared pins and could leave the
    // panel waiting on an interrupt that never represents a real touch.
    touch_config.rst_gpio_num = GPIO_NUM_NC;
    touch_config.int_gpio_num = GPIO_NUM_NC;
    touch_config.flags.swap_xy = 0;
    touch_config.flags.mirror_x = 0;
    touch_config.flags.mirror_y = 0;
    ESP_ERROR_CHECK(esp_lcd_touch_new_i2c_axs15231b(touch_io, &touch_config, &touch_handle));

    return touch_handle;
}

// ─── LVGL Tick & Execution loops ───
static void lvgl_task(void *pvParameters) {
    ESP_LOGI("LVTask", "Core 1 Graphics task running...");
    char log_buf[256];
    TickType_t lastLogPaint = 0;
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(16));   // ~60Hz service cap; guarantees IDLE1 gets the core
        if (lvgl_lock(-1)) {
            // Coalesce + rate-limit on-screen logging. The panel now runs in LVGL PARTIAL
            // refresh mode, so a log append only repaints the ticker's own bounding box (not
            // the whole 320x480 screen). The rate limit is kept as cheap insurance against a
            // log flood thrashing the ticker — but it can no longer snowball into full-screen
            // repaints that starve IDLE1 (task-WDT). Append a few lines at most every ~150ms.
            TickType_t now = xTaskGetTickCount();
            if (now - lastLogPaint >= pdMS_TO_TICKS(150)) {
                int drained = 0;
                while (drained < 8 && xQueueReceive(s_log_queue, log_buf, 0) == pdTRUE) {
                    ui_add_log(log_buf);
                    drained++;
                }
                if (drained > 0) lastLogPaint = now;
            }
            lv_timer_handler();
            lvgl_unlock();
        }
    }
}

// ─── WiFi Bringup logic ───
static void wifi_init_softap(const char* ssid, const char* pass, bool open_network) {
    ESP_LOGI(TAG, "Starting SoftAP Mode SSID:%s", ssid);
    
    esp_netif_create_default_wifi_ap();

    wifi_config_t wifi_config = {};
    strlcpy((char*)wifi_config.ap.ssid, ssid, sizeof(wifi_config.ap.ssid));
    wifi_config.ap.ssid_len = strlen(ssid);
    wifi_config.ap.channel = 1;
    wifi_config.ap.max_connection = 10;
    if (open_network) {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
        wifi_config.ap.password[0] = '\0';
    } else {
        wifi_config.ap.authmode = WIFI_AUTH_WPA_WPA2_PSK;
        strlcpy((char*)wifi_config.ap.password, pass, sizeof(wifi_config.ap.password));
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
}

static bool wifi_init_sta(const char* ssid, const char* pass) {
    ESP_LOGI(TAG, "Attempting Wi-Fi Station connection to SSID: %s", ssid);
    
    esp_netif_t* sta_netif = esp_netif_create_default_wifi_sta();

    wifi_config_t wifi_config = {};
    strlcpy((char*)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
    strlcpy((char*)wifi_config.sta.password, pass, sizeof(wifi_config.sta.password));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Awaiting local network association...");
    esp_err_t connect_err = esp_wifi_connect();
    if (connect_err != ESP_OK) {
        ESP_LOGE(TAG, "WiFi Connect failed!");
        return false;
    }

    // Wait up to 15s for association + DHCP lease. (5s was too tight: on a real router
    // the lease can land ~6-8s after start, causing a false "failed" -> captive portal.)
    int retries = 0;
    while (retries < 15) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(sta_netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
            char ip_str[32];
            esp_ip4addr_ntoa(&ip_info.ip, ip_str, sizeof(ip_str));
            g_localIp = ip_str;
            ESP_LOGI(TAG, "Connected successfully! Local IP is: %s", g_localIp.c_str());
            return true;
        }
        retries++;
        ESP_LOGI(TAG, "WiFi retry count: %d...", retries);
    }
    
    return false;
}

static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT) {
        if (event_id == WIFI_EVENT_AP_STACONNECTED) {
            wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*)event_data;
            g_stationNum++;
            ESP_LOGI(TAG, "station " MACSTR " joined local AP, AID=%d", MAC2STR(event->mac), event->aid);
        } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
            wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*)event_data;
            if (g_stationNum > 0) g_stationNum--;
            ESP_LOGI(TAG, "station " MACSTR " left local AP, AID=%d", MAC2STR(event->mac), event->aid);
        }
    }
}

// ─── Server Tasks on Core 0 ───
static void sip_server_task(void *pvParameters) {
    ESP_LOGI("SipTask", "Starting SipServer engine on Core 0 IP %s:%d", g_localIp.c_str(), 5060);
    SipServer* srv = new SipServer(g_localIp, 5060);
    // Publish with release so the http/status tasks' acquire-load sees a fully
    // constructed object the moment they observe the non-null pointer.
    g_sipServer.store(srv, std::memory_order_release);
    while (1) {
        srv->getHandler().tick();
        vTaskDelay(pdMS_TO_TICKS(30)); // match Arduino 30ms latency cycle
    }
    vTaskDelete(NULL);
}

static void http_server_task(void *pvParameters) {
    ESP_LOGI("HttpTask", "Starting Web CGA CRT dashboard on Core 0 IP %s:80", g_localIp.c_str());
    // Block until the SIP task publishes the handler — but BOUNDED: if the SipServer
    // failed to construct (e.g. OOM after the PSRAM frame buffers), an unbounded poll
    // would hang this task (and the whole dashboard) forever with no watchdog. Give
    // up after ~30 s and self-exit instead of spinning silently.
    SipServer* srv = nullptr;
    for (int i = 0; i < 300 && (srv = g_sipServer.load(std::memory_order_acquire)) == nullptr; ++i) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    if (srv == nullptr) {
        ESP_LOGE("HttpTask", "SipServer never came up after 30 s — dashboard task aborting");
        vTaskDelete(NULL);
        return;
    }
    g_httpServer = new HttpServer(g_localIp, 80, &srv->getHandler());
    g_httpServer->start();
    ESP_LOGI("HttpTask", "CGA Web UI Running successfully!");

    // OTA rollback confirmation (see docs/OTA.md): after a few seconds of healthy
    // operation, confirm this image so the bootloader won't roll it back on the
    // next reset. No-op unless the running image is pending verify.
    int otaSettleSec = 0;
    bool otaConfirmed = false;
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
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

// ─── Periodic system update task ───
static void system_status_task(void *pvParameters) {
    uint32_t ticks = 0;
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(500));
        ticks++;

        if (g_setupComplete) {
            uint32_t uptime = esp_timer_get_time() / 1000000;

            // Query extensions and active VoIP call counts. Load the registrar
            // pointer once (acquire) and use the snapshot for the whole tick.
            SipServer* srv = g_sipServer.load(std::memory_order_acquire);
            int clientCount = srv ? srv->getHandler().getClientCount() : 0;
            int sessionCount = srv ? srv->getHandler().getSessionCount() : 0;

            // Free-heap % for the wallboard vitals line (internal heap; PSRAM excluded so
            // the figure reflects the constrained pool that actually matters for stability).
            int freeHeapPct = -1;
            {
                size_t freeI  = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
                size_t totalI = heap_caps_get_total_size(MALLOC_CAP_INTERNAL);
                if (totalI > 0) freeHeapPct = (int)((freeI * 100) / totalI);
            }

            // ── Build the wallboard snapshot (live calls + roster + DND) from the registrar
            // dashboard API ── All getters snapshot-copy under RequestsHandler's own
            // _snapshotMutex; we never block the SIP core here. Everything is bounded by the
            // registrar pools (32 clients / 8 sessions).
            UiBoardSnapshot board{};
            board.callCount = 0;
            board.extCount = 0;
            board.dndCount = 0;
            board.dndOverflow = 0;
            if (srv) {
                RequestsHandler& h = srv->getHandler();
                auto clients  = h.getActiveClients();   // {ext, ip:port}
                auto sessions = h.getActiveSessions();   // {a, b, stateStr, durationSec}
                auto dndList  = h.getDndExtensions();    // {ext...}

                // DND membership set for roster flags + the chip list.
                std::unordered_set<std::string> dnd(dndList.begin(), dndList.end());

                // Live calls: only "live" sessions (Connected=active glow, Invited=ringing)
                // light a row; teardown states (Bye/Cancel/Busy/Unavailable) don't. Bounded
                // to UI_MAX_CALLS. Also collect the in-call extension set for roster flags.
                std::unordered_set<std::string> inCall;
                for (const auto& s : sessions) {
                    const std::string& a  = std::get<0>(s);
                    const std::string& b  = std::get<1>(s);
                    const std::string& st = std::get<2>(s);
                    int dur = std::get<3>(s);
                    bool active  = (st == "Connected");
                    bool ringing = (st == "Invited");
                    if (!active && !ringing) continue;
                    if (!a.empty() && a != "?") inCall.insert(a);
                    if (!b.empty() && b != "?") inCall.insert(b);
                    if (board.callCount < UI_MAX_CALLS) {
                        UiCall& c = board.calls[board.callCount];
                        strncpy(c.a, a.c_str(), sizeof(c.a) - 1); c.a[sizeof(c.a) - 1] = '\0';
                        strncpy(c.b, b.c_str(), sizeof(c.b) - 1); c.b[sizeof(c.b) - 1] = '\0';
                        c.state = active ? UI_CALL_ACTIVE : UI_CALL_RINGING;
                        c.durationSec = dur;
                        board.callCount++;
                    }
                }

                // Roster: one entry per registered client (bounded to UI_MAX_EXTENSIONS),
                // tagged with its in-call / DND flags.
                for (const auto& c : clients) {
                    if (board.extCount >= UI_MAX_EXTENSIONS) break;
                    UiExt& e = board.exts[board.extCount];
                    strncpy(e.ext, c.first.c_str(), sizeof(e.ext) - 1);
                    e.ext[sizeof(e.ext) - 1] = '\0';
                    e.inCall = inCall.count(c.first) > 0;
                    e.dnd    = dnd.count(c.first) > 0;
                    board.extCount++;
                }

                // DND chips (bounded to UI_MAX_DND_CHIPS; the rest become "+N").
                for (const auto& ext : dndList) {
                    if (board.dndCount < UI_MAX_DND_CHIPS) {
                        strncpy(board.dnd[board.dndCount], ext.c_str(), sizeof(board.dnd[0]) - 1);
                        board.dnd[board.dndCount][sizeof(board.dnd[0]) - 1] = '\0';
                        board.dndCount++;
                    } else {
                        board.dndOverflow++;
                    }
                }
            }

            if (lvgl_lock(100)) {
                ui_update_status(g_localIp, uptime, g_stationNum, clientCount, sessionCount, freeHeapPct);
                ui_update_board(board);
                lvgl_unlock();
            }

            // Log changes to UI
            if (g_stationNum != prevStations) {
                if (prevStations != -1) {
                    ESP_LOGI(TAG, "Stations change detected: %d", g_stationNum);
                }
                prevStations = g_stationNum;
            }
            if (clientCount != prevExtensions) {
                if (prevExtensions != -1) {
                    ESP_LOGI(TAG, "Active SIP extensions changed: %d", clientCount);
                }
                prevExtensions = clientCount;
            }
            if (sessionCount != prevSessions) {
                if (prevSessions != -1) {
                    ESP_LOGI(TAG, "Active sessions changed: %d", sessionCount);
                }
                prevSessions = sessionCount;
            }
        }
    }
}

// ─── Entry main function ───
// ─── Captive-portal decay watchdog ───
// Runs only while the captive portal is up. Counts CAPTIVE_DECAY_SECONDS of "no one is
// configuring" (g_decayHold low); if it elapses, persist a one-shot "decayed" flag and
// reboot into transient Standalone AP. The flag is consumed on the next boot, so decay
// never becomes a permanent boot target.
static void captive_decay_task(void *pvParameters) {
    int elapsed = 0;
    while (elapsed < CAPTIVE_DECAY_SECONDS) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        if (g_decayHold) { elapsed = 0; continue; } // held while a client is configuring
        elapsed++;
    }
    ESP_LOGW(TAG, "Captive portal: no config confirmed in %ds -> decaying to Standalone AP", CAPTIVE_DECAY_SECONDS);
    nvs_handle_t h;
    if (nvs_open("storage", NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u8(h, "decayed", 1);
        nvs_commit(h);   // synchronous: the flag is on flash before this returns
        nvs_close(h);
    }
    // Quiesce the radio before resetting so no Wi-Fi-driven flash/NVS write from
    // another task is in flight across esp_restart() (which does not coordinate with
    // concurrent SPI-flash operations). nvs_commit above already flushed our write.
    esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(200));
    esp_restart();
}

extern "C" void app_main(void) {
    // Issue #273: arms the internal-DRAM leak probe. No-op unless
    // CONFIG_HEAP_TRACING is set (sdkconfig.defaults.heap_trace only).
    // MUST be here rather than a global constructor -- constructors run
    // before the scheduler exists; see HeapLeakProbe.hpp.
    pdHeapLeakProbeStart();

    ESP_LOGI(TAG, "================================================");
    ESP_LOGI(TAG, " POCKET-DIAL ESP-IDF DISPLAY CONTROLLER");
    ESP_LOGI(TAG, "================================================");

    // Initialise Kconfig systems
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // NVS schema version (issue #181). Must land BEFORE applyFlashSeed(): the
    // seed writer CREATES the very NVS namespaces the "is this a pre-versioning
    // device?" probe looks for, so running it first would make every
    // provisioned board look freshly installed and skip the migrations it
    // actually needs. Logs its own outcome — loudly, if this firmware is older
    // than the layout on flash.
    DeviceConfig::ensureSchemaVersion();

    // Flash-time configuration seed. Must land AFTER nvs_flash_init() (it writes
    // NVS) and BEFORE the wifi_mode / wifi_ssid / wifi_pass read further down, so
    // a board configured by the browser flasher boots straight into its configured
    // role instead of the captive portal. No cfgseed partition (OTA-updated units,
    // the 4MB constrained layout) → returns false and changes nothing.
    if (DeviceConfig::applyFlashSeed()) {
        ESP_LOGI(TAG, "[boot] applied flash-time cfgseed");
    }

    // The AP passphrase is generated on first access, so pull it once here — well
    // before any bringup path needs it — rather than at three separate call sites.
    g_apPsk = DeviceConfig::getApPsk();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Register Wi-Fi events
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));

    // 1. Start LCD display graphics engine registers
    // lv_init() MUST run before any other LVGL call: it performs _lv_timer_core_init()
    // and the _lv_ll_init() calls that set the node sizes of LVGL's global timer and
    // display linked lists. Without it, _lv_timer_ll.n_size was uninitialized, so
    // lv_disp_drv_register() -> lv_timer_create() -> _lv_ll_ins_head() requested a
    // garbage-sized allocation and tripped the heap allocator (block_locate_free,
    // assert block_size >= size in tlsf.c). The heap was never corrupt; LVGL was simply
    // never initialized.
    s_lvgl_mux = xSemaphoreCreateRecursiveMutex();
    lv_init();
    ESP_LOGI(TAG, "LVGL core initialized (lv_init)");

    static lv_disp_drv_t disp_drv;
    lv_disp_drv_init(&disp_drv);

    // Low level Panel configuration CS=45, Backlight=1, QSPI lines
    hardware_display_init(&disp_drv);
    // (panel handle is stored in disp_drv.user_data and retrieved inside flush_cb)

    // FULL-screen refresh draw buffer in PSRAM. This panel (AXS15231B QSPI) GARBLES on partial
    // windowed writes — that is a hardware fact established the hard way, see TFT_TE notes — so
    // LVGL must run in full_refresh mode and repaint the whole 320x480 frame each time. One
    // screen-sized PSRAM buffer; the flush still bands it out through s_band_buf, a small internal
    // DMA-capable bounce, because the SPI master can't DMA directly from PSRAM. Do NOT switch this
    // back to partial/double-buffered windowed flushing — it looks correct in code and corrupts
    // on the glass.
    size_t draw_buf_sz = 320 * 480;   // full screen
    lv_color_t *buf1 = (lv_color_t *)heap_caps_malloc(draw_buf_sz * sizeof(lv_color_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    s_band_buf       = (lv_color_t *)heap_caps_malloc(320 * FLUSH_BAND_ROWS * sizeof(lv_color_t), MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
    assert(buf1 != NULL);
    assert(s_band_buf != NULL);

    static lv_disp_draw_buf_t disp_buf;
    lv_disp_draw_buf_init(&disp_buf, buf1, NULL, draw_buf_sz);  // single full-screen buffer
    disp_drv.hor_res = 320;
    disp_drv.ver_res = 480;
    disp_drv.flush_cb = [](lv_disp_drv_t *drv, const lv_area_t *area, lv_color_t *color_map) {
        esp_lcd_panel_handle_t panel = (esp_lcd_panel_handle_t)drv->user_data;
        const int x1 = area->x1, x2 = area->x2;
        const int w  = x2 - x1 + 1;
        // full_refresh hands us the whole screen as a single area, so there is exactly one flush
        // per frame: block for the next TE (vblank) pulse before writing so the frame lands in
        // blanking and doesn't tear. Drain any stale pulse first.
        if (s_te_sem) {
            xSemaphoreTake(s_te_sem, 0);                   // drain any stale pulse
            xSemaphoreTake(s_te_sem, pdMS_TO_TICKS(100));  // wait for the next vblank
        }
        // Copy each band PSRAM -> internal DMA bounce, clock it out, wait for it to finish
        // (s_band_buf is reused, so the bands must be sequential). The driver fills the frame
        // with RAMWR (top band) + RAMWRC continuation, so bands must run top-to-bottom.
        for (int y = area->y1; y <= area->y2; y += FLUSH_BAND_ROWS) {
            int yb = y + FLUSH_BAND_ROWS - 1; if (yb > area->y2) yb = area->y2;
            int rows = yb - y + 1;
            memcpy(s_band_buf, color_map + (size_t)(y - area->y1) * w, (size_t)rows * w * sizeof(lv_color_t));
            esp_lcd_panel_draw_bitmap(panel, x1, y, x2 + 1, yb + 1, s_band_buf);
            xSemaphoreTake(s_flush_done_sem, pdMS_TO_TICKS(100)); // wait for this band's DMA
        }
        lv_disp_flush_ready(drv);
    };
    disp_drv.draw_buf = &disp_buf;
    // FULL refresh: every update repaints all 320x480. Slightly more QSPI traffic, but it is the
    // only mode that renders cleanly on this panel. Keep UI animations discrete (see ui.cpp) so we
    // are not repainting the whole screen continuously.
    disp_drv.full_refresh = 1;
    lv_disp_drv_register(&disp_drv);

    // 2. Initialize touchscreen registers (SDA 4, SCL 8, INT 11, RST 12)
    esp_lcd_touch_handle_t touch_handle = hardware_touch_init();
    static lv_indev_drv_t indev_drv;
    lv_indev_drv_init(&indev_drv);
    indev_drv.type = LV_INDEV_TYPE_POINTER;
    indev_drv.user_data = touch_handle;
    indev_drv.read_cb = [](lv_indev_drv_t *drv, lv_indev_data_t *data) {
        esp_lcd_touch_handle_t touch = (esp_lcd_touch_handle_t)drv->user_data;
        uint16_t touchX[1];
        uint16_t touchY[1];
        uint16_t touchStrength[1];
        uint8_t touchPoints = 0;
        
        esp_lcd_touch_read_data(touch);
        bool pressed = esp_lcd_touch_get_coordinates(touch, touchX, touchY, touchStrength, &touchPoints, 1);
        
        if (pressed && touchPoints > 0) {
            data->point.x = touchX[0];
            data->point.y = touchY[0];
            data->state = LV_INDEV_STATE_PR;
            ui_handle_touch_press(touchX[0], touchY[0]);
        } else {
            data->state = LV_INDEV_STATE_REL;
        }
    };
    lv_indev_drv_register(&indev_drv);

    // 3. Build the logging queue and the HMI BEFORE starting the graphics task.
    // Ordering is load-bearing: lvgl_task drains s_log_queue and calls lv_timer_handler,
    // so (a) the queue must exist or xQueueReceive asserts on a NULL handle, and (b) the
    // UI must be fully built first — LVGL is single-threaded, so the core-1 render task
    // must not run concurrently with ui_init()'s object creation on the main task.
    s_log_queue = xQueueCreate(8, 256);

    // Draw initial empty frame / build the HMI switchboard
    ui_init();

    // Intercept ESP_LOGI and route logs to the on-screen console textarea
    original_log_vprintf = esp_log_set_vprintf(screen_log_vprintf);

    // Start Core 1 graphics loop last: it drives all LVGL rendering from here on.
    xTaskCreatePinnedToCore(&lvgl_task, "lvgl_task", 8192, NULL, 5, NULL, 1);

    // 4. Retrieve saved operational Wi-Fi configuration from NVS
    uint8_t wifi_mode = 0;   // 0 = captive-portal default, 1 = STATION, 2 = explicit Standalone
    uint8_t decayed   = 0;   // one-shot flag set by the captive-decay watchdog before reboot
    char saved_ssid[33] = {0};
    char saved_pass[64] = {0};

    nvs_handle_t nvs_handle;
    if (nvs_open("storage", NVS_READONLY, &nvs_handle) == ESP_OK) {
        if (nvs_get_u8(nvs_handle, "wifi_mode", &wifi_mode) != ESP_OK) wifi_mode = 0;
        if (nvs_get_u8(nvs_handle, "decayed", &decayed)     != ESP_OK) decayed   = 0;
        size_t size = sizeof(saved_ssid);
        if (nvs_get_str(nvs_handle, "wifi_ssid", saved_ssid, &size) != ESP_OK) saved_ssid[0] = '\0';
        size = sizeof(saved_pass);
        if (nvs_get_str(nvs_handle, "wifi_pass", saved_pass, &size) != ESP_OK) saved_pass[0] = '\0';
        nvs_close(nvs_handle);
    } else {
        wifi_mode = 0;
    }

    // Cache the operational config for system_status_task (Fix #7 — see globals above).
    g_wifiMode = wifi_mode;
    strncpy(g_wifiSsid, saved_ssid, sizeof(g_wifiSsid) - 1);
    g_wifiSsid[sizeof(g_wifiSsid) - 1] = '\0';

    // Initialize WiFi driver before any wifi_init_softap / wifi_init_sta calls below
    {
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        ESP_ERROR_CHECK(esp_wifi_init(&cfg));
        esp_wifi_set_ps(WIFI_PS_NONE);
    }

    // ── Email (issue #159): start the SMTP worker task ──────────────────────
    // Before the STATION/Standalone-AP/captive-portal branch below, since all
    // three paths stand up a dashboard that can reach /api/email*, and
    // init() only creates the queue/task -- it does not touch the network,
    // so it does not need to wait for any of those branches to resolve.
    SmtpClient::init();

    // Onboarding model: "up usable, secure later" — the device is NEVER held dark
    // waiting for an admin credential. It boots straight into its normal network role
    // below (STATION if WiFi is saved, else the captive WiFi-onboarding portal, else
    // Standalone AP), so the operator can connect WiFi, reach the dashboard, and SSH in
    // before optionally setting a PIN. "Secured" is the runtime property
    // AdminAuth::isProvisioned(); the dashboard's sensitive endpoints and the on-device
    // sensitive actions self-gate on it once a PIN exists. Setting a PIN is offered (a
    // dismissible prompt + the Perimeter screen), not forced.

    // Consume the one-shot decay flag. If last boot's captive portal timed out, come up in
    // transient Standalone AP this once WITHOUT persisting it, so a later power cycle still
    // returns to the captive portal (decay is never a saved boot target).
    if (decayed) {
        if (nvs_open("storage", NVS_READWRITE, &nvs_handle) == ESP_OK) {
            nvs_erase_key(nvs_handle, "decayed");
            nvs_commit(nvs_handle);
            nvs_close(nvs_handle);
        }
        ESP_LOGW(TAG, "Captive portal timed out last boot -> transient Standalone AP.");
    }

    ESP_LOGI(TAG, "Persisted Network settings: Mode=%d, SSID=%s, decayed=%d", wifi_mode, saved_ssid, decayed);

    // Boot priority: explicit Standalone (or a transient decay) -> Standalone AP;
    // else saved STATION creds -> try to join as client (fall back to captive portal);
    // else -> captive portal onboarding with the decay watchdog.
    bool go_standalone = decayed || (wifi_mode == 2);
    bool go_captive    = false;

    if (!go_standalone && saved_ssid[0] != '\0') { // ─── STATION: try the saved AP first ───
        ESP_LOGI(TAG, "STATION mode: attempting to join '%s'...", saved_ssid);
        if (wifi_init_sta(saved_ssid, saved_pass)) {
            if (lvgl_lock(-1)) { ui_set_onboarding_mode(false); lvgl_unlock(); }
            xTaskCreatePinnedToCore(&sip_server_task,  "sip_server_task",  8192, NULL, 5, NULL, 0);
            xTaskCreatePinnedToCore(&http_server_task, "http_server_task", 8192, NULL, 4, NULL, 0);
            g_setupComplete = true;
        } else {
            ESP_LOGW(TAG, "Station association failed -> captive portal.");
            go_captive = true;
        }
    } else if (!go_standalone) {
        go_captive = true;
    }

    if (go_standalone) { // ─── Standalone AP (explicit radio choice, or decayed fallback) ───
        // Standalone used to be unconditionally open. It now follows the operator's
        // DeviceConfig choice, which still DEFAULTS to open so an already-deployed
        // fleet is not cut off by a firmware update (see DeviceConfig.hpp).
        const bool ap_secure = DeviceConfig::isApSecure();
        ESP_LOGI(TAG, "Standalone AP Mode (%s, SIP up).", ap_secure ? "WPA2-PSK" : "open network");
        if (ap_secure) {
            // Also logged to serial for anyone with a cable (already inside the
            // physical trust boundary) and for CI captures — but serial is no longer
            // the ONLY place this appears: on this variant the passphrase is now put
            // on the glass by ui_show_ap_credentials() below, which is the whole
            // point of the board having a screen.
            ESP_LOGI(TAG, "Standalone AP passphrase (WPA2): %s", g_apPsk.c_str());
        }
        if (lvgl_lock(-1)) {
            ui_set_onboarding_mode(false);
            if (ap_secure) {
                // A timed, dismissible splash over the live wallboard — NOT an
                // onboarding screen: standalone is the normal operating state, so
                // the board must not be trapped in a setup view. It clears itself
                // after ~90 s (or on a tap) and a long press re-summons it. Nothing
                // is shown for an open AP; there is no passphrase to read.
                //
                // Deliberately BEFORE wifi_init_softap(): the SSID string below is a
                // compile-time literal, so the credentials on the glass are correct
                // the moment the radio comes up rather than a second later.
                ui_show_ap_credentials(STANDALONE_SSID, g_apPsk.c_str());
            }
            lvgl_unlock();
        }
        g_localIp = "192.168.4.1";
        wifi_init_softap(STANDALONE_SSID, g_apPsk.c_str(), !ap_secure);
        xTaskCreatePinnedToCore(&sip_server_task,  "sip_server_task",  8192, NULL, 5, NULL, 0);
        xTaskCreatePinnedToCore(&http_server_task, "http_server_task", 8192, NULL, 4, NULL, 0);
        g_setupComplete = true;
    }

    if (go_captive) { // ─── Captive portal onboarding + decay watchdog ───
        ESP_LOGI(TAG, "Captive portal Setup AP: SSID=%s", ONBOARDING_SSID);
        // The generated passphrase is rendered on the LVGL onboarding screen and
        // encoded into the join QR by ui_set_onboarding_mode(), which is what makes
        // a per-device secret usable here at all — the operator reads it off the
        // glass instead of off this source file. Also logged for the serial console.
        ESP_LOGI(TAG, "Captive portal passphrase (WPA2): %s", g_apPsk.c_str());
        if (lvgl_lock(-1)) { ui_set_onboarding_mode(true, ONBOARDING_SSID, g_apPsk.c_str()); lvgl_unlock(); }
        wifi_init_softap(ONBOARDING_SSID, g_apPsk.c_str(), false); // secure onboarding AP

        // DNS redirect (port 53) + config web portal (port 80), both at 192.168.4.1
        g_dnsServer = new DnsServer();
        g_dnsServer->start("192.168.4.1");
        g_localIp = "192.168.4.1";
        g_httpServer = new HttpServer(g_localIp, 80, nullptr);
        g_httpServer->start();

        // mDNS so the portal also answers at http://pocketdial.local/ (station/standalone
        // modes get mDNS from the SIP server; the captive portal has no SIP server, so do it
        // here). Matches the SipServer hostname/service for consistency.
        if (mdns_init() == ESP_OK) {
            mdns_hostname_set("pocketdial");
            mdns_instance_name_set("Pocket-Dial Setup");
            mdns_service_add(NULL, "_http", "_tcp", 80, NULL, 0);
        }

        ESP_LOGI(TAG, "Captive onboarding active at http://192.168.4.1/ or pocketdial.local (decays in %ds)", CAPTIVE_DECAY_SECONDS);
        xTaskCreatePinnedToCore(&captive_decay_task, "decay_task", 3072, NULL, 3, NULL, 0);
    }

    // ── SSH / esp_console engine (Ticket 2) ─────────────────────────────────
    // Available in EVERY network role — operational STATION/Standalone AND during
    // captive onboarding — so the operator can reach SSH before securing the device.
    // All paths have a live netif/IP by here. start() reads ssh_enabled from NVS and
    // fails closed.
    //
    // Plumb the real network identity into the SSH sysop-terminal TUI so its banner
    // 5. Spin up periodic status and battery updater task
    xTaskCreatePinnedToCore(&system_status_task, "status_task", 4096, NULL, 3, NULL, 0);
}

#ifndef LOG_QUEUE_HPP
#define LOG_QUEUE_HPP

// LogQueue.hpp — header-only, non-blocking UART log queue for ESP-IDF builds.
//
// Why this exists:
//   The non-display builds (esp_main.cpp, esp_main_eth.cpp,
//   esp_main_eth_lan8720.cpp) originally logged synchronously to UART from
//   real-time tasks, which blocked on the UART mutex. This helper installs a
//   non-blocking vprintf hook (via esp_log_set_vprintf) that enqueues log lines
//   into a FreeRTOS queue. A dedicated low-priority drain task dequeues and
//   writes them to stderr so the real-time tasks never block on I/O.
//
//   The display build (esp_main_display.cpp) already implements its own
//   s_log_queue / screen_log_vprintf hook — this header is NOT included there.
//
// Thread-safety:
//   The enqueue hook (log_queue_vprintf) is called from arbitrary task contexts.
//   It uses xQueueSend with timeout=0 (non-blocking, drops if full) — never
//   blocks, never uses FromISR because ESP-IDF log calls are not made from ISRs.
//   drainToUart() is called from a single drain task — no concurrent dequeue.
//
// Usage:
//   In app_main(), after nvs_flash_init():
//       LogQueue::create();
//       xTaskCreatePinnedToCore(log_drain_task, "log_drain", 2048, nullptr, 1, nullptr, 0);
//
//   The drain task body:
//       while (1) { LogQueue::drainToUart(); vTaskDelay(pdMS_TO_TICKS(10)); }

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)

#include <cstdio>
#include <cstring>
#include <cstdarg>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "esp_log.h"

namespace LogQueue
{
    // Per-line buffer size and queue depth. Increase LINE_BYTES if you see
    // truncated log lines; increase QUEUE_DEPTH if the drain task falls behind
    // during bursts (dropped lines are preferable to blocking the SIP task).
    static constexpr int LINE_BYTES  = 256;
    static constexpr int QUEUE_DEPTH = 16;

    // The single queue handle. Set by create() and read by the hook and drain.
    // Deliberately not extern to avoid ODR issues in header-only code; each
    // translation unit that includes this header shares the same function-local
    // static via the inline accessor below. Because all three entry points
    // (esp_main*.cpp) are compiled as separate translation units but only ONE
    // is linked into a given firmware image, there is exactly one instance at
    // runtime.
    static QueueHandle_t s_queue = nullptr;

    // Non-blocking vprintf hook installed via esp_log_set_vprintf().
    // Formats the log line into a stack buffer then enqueues it with
    // timeout=0. If the queue is full the line is silently dropped —
    // never blocks.
    static int log_queue_vprintf(const char* fmt, va_list args)
    {
        if (s_queue == nullptr) {
            // Queue not yet created — fall back to vprintf so we don't lose
            // early boot messages entirely.
            return vprintf(fmt, args);
        }

        // Format into a stack buffer. The +1 for the null terminator is
        // intentional; vsnprintf always null-terminates within the provided size.
        char buf[LINE_BYTES];
        int n = vsnprintf(buf, sizeof(buf), fmt, args);
        if (n <= 0) {
            return n;
        }

        // Non-blocking send: drop line if full (never block a real-time task).
        xQueueSend(s_queue, buf, 0);
        return n;
    }

    // Create the queue and install the vprintf hook.
    // Call once from app_main() after NVS init, before spawning any tasks.
    // depth     — number of log lines the queue can buffer before dropping
    // lineBytes — max bytes per line (must match LINE_BYTES; parameter is
    //             accepted for API symmetry with the display build's helper
    //             but the actual buffer size is the compile-time constant)
    static inline QueueHandle_t create(int depth = QUEUE_DEPTH,
                                       int lineBytes = LINE_BYTES)
    {
        (void)lineBytes;  // compile-time constant — size cannot vary at runtime
        if (s_queue != nullptr) {
            return s_queue;  // already created
        }
        s_queue = xQueueCreate(depth, LINE_BYTES);
        if (s_queue != nullptr) {
            esp_log_set_vprintf(log_queue_vprintf);
        }
        return s_queue;
    }

    // Optional second sink for every drained line. Registered by the platform
    // entry point, NOT by this header -- LogQueue deliberately knows nothing about
    // syslog, the network, or anything that can fail, so a tee that misbehaves
    // cannot take the log path down with it.
    //
    // The tee runs on the drain task, AFTER the line has already reached the UART.
    // That ordering is the point: serial is the sink that always works, and it must
    // never be delayed or lost because a remote collector is slow or unreachable.
    using Tee = void (*)(const char* line);
    static Tee s_tee = nullptr;
    static inline void setTee(Tee t) { s_tee = t; }

    // Dequeue one log line and write it to stderr.
    // Call repeatedly from a low-priority drain task.
    // blockTicks — how long to wait for a line before returning (default 10 ms)
    static inline void drainToUart(TickType_t blockTicks = pdMS_TO_TICKS(10))
    {
        if (s_queue == nullptr) {
            return;
        }
        char buf[LINE_BYTES];
        if (xQueueReceive(s_queue, buf, blockTicks) == pdTRUE) {
            // Ensure null-termination even if something went wrong during enqueue.
            buf[LINE_BYTES - 1] = '\0';
            fputs(buf, stderr);
            if (s_tee != nullptr) {
                s_tee(buf);
            }
        }
    }

} // namespace LogQueue

#else // Non-ESP build: provide no-ops so including this header in host tests is safe.

namespace LogQueue
{
    static inline void* create(int = 16, int = 256) { return nullptr; }
    static inline void drainToUart(unsigned = 10) {}
    using Tee = void (*)(const char* line);
    static inline void setTee(Tee) {}
}

#endif // ESP_PLATFORM

#endif // LOG_QUEUE_HPP

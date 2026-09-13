#ifndef PD_PSRAM_TASK_HPP
#define PD_PSRAM_TASK_HPP

// #100: place selected FreeRTOS task stacks + TCBs in PSRAM (8 MB) instead of the scarce ~290 KB
// internal-RAM heap. The per-call anchor media tasks (RtpReceiver / RtpSender / GET-stream rx) and
// the transient TLS workers (makecall / answer / dropcall) each take 6–12 KB of stack; with N
// concurrent calls those stacks exhaust internal RAM and xTaskCreate starts failing — the measured
// concurrent-call ceiling (the freeHeap telemetry hides it because that counts PSRAM). Moving these
// stacks to PSRAM lifts the ceiling toward the per-call socket/CPU limits instead.
//
// SAFE ONLY for tasks that never perform a flash / NVS write THEMSELVES: when the flash cache is
// disabled for a write, code accessing a PSRAM stack faults. The media/TLS tasks here do socket +
// TLS I/O only (NVS/CDR writes run on the SIP/anchor task, which is frozen during the flash op, so
// the PSRAM-stack tasks are simply not scheduled in that window). Do NOT use this for any task that
// itself calls nvs_*/esp_partition_*/OTA.
//
// Tasks created WithCaps MUST be deleted with vTaskDeleteWithCaps (including self-delete:
// vTaskDeleteWithCaps(NULL)) so the PSRAM stack+TCB are reclaimed. Host builds get nothing (the
// callers are all inside ESP_PLATFORM guards).

#if defined(ESP_PLATFORM) || defined(ESP32)
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/idf_additions.h"   // xTaskCreate*WithCaps / vTaskDeleteWithCaps
#include "esp_heap_caps.h"            // MALLOC_CAP_SPIRAM

// PSRAM, byte-addressable — the stack + TCB allocation caps for an off-internal-RAM task.
#define PD_TASK_STACK_CAPS (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)
#endif

#endif // PD_PSRAM_TASK_HPP

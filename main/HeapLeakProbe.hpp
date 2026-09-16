#pragma once

// Issue #273 leak probe. Call pdHeapLeakProbeStart() early in app_main().
//
// The call site needs no #if: when CONFIG_HEAP_TRACING is off — which is every
// build except the sdkconfig.defaults.heap_trace profile — this resolves to an
// inline empty function and the optimizer deletes it.
//
// MUST BE CALLED FROM app_main(), NOT FROM A GLOBAL CONSTRUCTOR. The first
// revision of this probe self-registered from a file-scope constructor to avoid
// touching the four transport-specific mains, on the stated basis that ESP-IDF
// runs global C++ constructors from main_task with the scheduler already up.
// That is false, and it reboot-looped the bench.
//
// esp_system/startup.c: start_cpu0_default() calls __libc_init_array() (and
// __do_global_ctors_1()) and the comment immediately below that call reads
// "After this stage, other CPU start running with the cache, however the
// scheduler (and ipc service) is not available." esp_startup_start_app(),
// which creates main_task and starts the scheduler, is called AFTER. So a
// constructor runs BEFORE the scheduler exists, and xTaskCreate() there
// produced a deterministic FreeRTOS SMP assert ~3.8 s into every boot:
//
//   assert failed: prvSelectHighestPriorityTaskSMP tasks.c:3642
//                  (xTaskScheduled == ( ( BaseType_t ) 1 ))
//
// app_main() runs on main_task, after the scheduler is up and both cores are
// live, which is the property the constructor was wrongly assumed to have.

#include "sdkconfig.h"

#if CONFIG_HEAP_TRACING
void pdHeapLeakProbeStart();
#else
inline void pdHeapLeakProbeStart() {}
#endif

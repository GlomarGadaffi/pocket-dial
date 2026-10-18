#pragma once

// FlashWriter -- the one task that does the NVS writes the CDR ring and the NVS
// writer hand off (#991). A task that writes flash needs a plain internal stack
// (the #277 rule, PsramTask.hpp), so each such task costs a whole internal
// stack and a TCB; cdr_persist and nvs_writer were two of them, this is one.
//
// Each source keeps its own depth-1 queue(s), which its producers fill with
// xQueueOverwrite and never block on: CdrRing::persist() (the ring snapshot)
// and nvswriter::stage() (one queue per key). After an overwrite the producer
// calls wake(). The task runs passOnce(), then waits for a notification. A
// pass takes at most ONE unit from each queue, in a fixed order (the CDR ring,
// then the NVS keys in Key order), so a source that never stops producing gets
// one unit a pass and cannot starve another: a unit waits at most for the unit
// in progress plus one unit of every other queue. A wake that lands during a
// pass is not lost: the next ulTaskNotifyTake returns at once and the next pass
// looks at every queue again.
//
// A source is reached only once it is ready: CdrRing publishes its queue, and
// nvswriter its running flag, after this task exists and everything they own
// is made (release on publish, acquire in the task), and neither deletes
// anything after publishing. Before that its writePending() returns 0.
//
// Not merged (#991): cdr_archive (CdrArchive.cpp). One unit of its work is a
// drain of up to 32 CSV rows to the SD card over SPI, each a stat + fopen +
// fputs + fclose through FatFs, with a 2 s command timeout per SD command
// (esp_main_eth.cpp sd_mount) and up to 10 s waiting for the volume lock that
// the voicemail archive and the hold-music upload also take
// (CONFIG_FATFS_TIMEOUT_MS, IDF default). A device-table or *72 write queued
// behind that would wait seconds. Its rows are separate records, not a
// snapshot, so a depth-1 overwrite queue would also drop CDR lines.

#include <cstddef>

namespace flashwriter
{
	// One pass: each source in template order, once. A source writes what its
	// depth-1 queue(s) hold -- at most one unit per queue -- and returns how many
	// units it wrote. Non-type template parameters, not run-time pointers, so the
	// calls stay direct and the stack gate's call graph walks into each source.
	template <unsigned (*... Source)()>
	unsigned passOnce()
	{
		unsigned n = 0;
		((n += Source()), ...);   // a comma fold runs left to right
		return n;
	}

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// Boot-time (single-threaded) and idempotent: creates the task the first
	// time, and again on a later call if that one failed. False when the task
	// does not exist; the caller unwinds what it made and logs.
	bool start();

	// After a producer overwrote its queue. Never blocks; a no-op until start()
	// succeeded.
	void wake();
#endif
}

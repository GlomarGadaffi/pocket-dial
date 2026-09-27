#pragma once

// CoreDumpStore -- read-side access to the panic handler's flash coredump
// (issue #382). The WRITE side is IDF's own panic handler, enabled by
// CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH in sdkconfig.defaults; this module only
// reports, reads back and erases what it left in the `coredump` partition, so a
// panic nobody was watching on serial is still recoverable over HTTP
// (/api/coredump*) -- without esptool, whose resets can park .244 in ROM
// download mode (#338).
//
// Host builds have no flash: every call reports "no dump" unless a test has
// installed a fake image with setImageForTest().

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace CoreDumpStore
{
	struct Info
	{
		bool supported = false;   // firmware built with coredump-to-flash
		bool present = false;     // the partition holds a dump
		uint32_t size = 0;        // bytes, as stored (raw flash image)
	};

	// Fixed-size, so caching and copying it never touches the heap.
	struct Summary
	{
		bool valid = false;       // stored checksum verified
		char task[16] = {};       // name of the task that panicked
		uint32_t pc = 0;          // its program counter
		char elfSha[17] = {};     // SHA-256 prefix of the ELF that produced it
		char reason[64] = {};     // panic reason, e.g. "LoadProhibited"
	};

	// No flash access (#405): returns what prime() found at boot, as updated by
	// erase(). That is the whole truth at runtime -- only a panic writes a dump,
	// so a new one appears only across a reboot, and prime() runs every boot.
	// Probing flash here instead (image_get + partition_find + flash_read) put
	// the flash driver's deep call chain on every /api/status poll, on 4 KB
	// per-connection threads: the ~836 B of stack #405 measured going missing.
	// Before prime() has run it probes directly, which only the accept loop can
	// reach (prime() runs before the first accept).
	Info query();

	// The "present" rule, pure so the host suite tests the same code the board
	// runs. IDF's own check trusts the first word alone -- any value from 4 up
	// to the partition size counts as a dump -- so stale bytes left in the
	// region by an older partition layout read back as a bogus dump. A real
	// flash image is [u32 size][u32 version][u32 ...] followed by an ELF, so
	// the ELF magic must also sit at byte 12. `head` is the first 16 bytes.
	bool looksLikeDump(const uint8_t* head, size_t headLen, uint32_t storedSize,
		uint32_t partitionSize);
	// Verifies the checksum and parses the dump ONCE, on the caller's stack --
	// call it from a task with stack to spare (HttpServer::start() does, on the
	// 8 KB http_server_task), never from a 4 KB per-connection thread.
	void prime();
	// The result prime() cached; no flash work. Empty until prime() has run.
	Summary summary();
	// Copies [offset, offset + len) of the stored image. False on any bounds or
	// flash error, never a partial copy. Uses the location prime() cached, so
	// each chunk is one flash read, not a re-probe of the partition.
	bool read(uint32_t offset, uint8_t* out, size_t len);
	// Also invalidates the cached Info and Summary, so a caller that erases
	// (the erase route, factory reset) needs no second call to keep query()
	// and summary() truthful.
	bool erase();

#if !defined(ESP_PLATFORM)
	// Test-only: an empty vector means "no dump". Models a panic + reboot: the
	// new image is probed and cached exactly as prime() would at boot.
	void setImageForTest(std::vector<uint8_t> image);
	// Test-only: how many times the stored image was probed or read -- the host
	// stand-in for "touched flash". /api/status must not move it (#405).
	uint32_t flashAccessCountForTest();
#endif
}

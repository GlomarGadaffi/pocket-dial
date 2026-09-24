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

	struct Summary
	{
		bool valid = false;       // stored checksum verified
		std::string task;         // name of the task that panicked
		uint32_t pc = 0;          // its program counter
		std::string elfSha;       // SHA-256 prefix of the ELF that produced it
		std::string reason;       // panic reason, e.g. "LoadProhibited"
	};

	// Cheap: reads only the first 16 bytes. Safe on the ungated status route.
	Info query();

	// The "present" rule, pure so the host suite tests the same code the board
	// runs. IDF's own check trusts the first word alone -- any value from 4 up
	// to the partition size counts as a dump -- so stale bytes left in the
	// region by an older partition layout read back as a bogus dump. A real
	// flash image is [u32 size][u32 version][u32 ...] followed by an ELF, so
	// the ELF magic must also sit at byte 12. `head` is the first 16 bytes.
	bool looksLikeDump(const uint8_t* head, size_t headLen, uint32_t storedSize,
		uint32_t partitionSize);
	// Verifies the checksum over the whole image, so only on an explicit request.
	Summary summary();
	// Copies [offset, offset + len) of the stored image. False on any bounds or
	// flash error, never a partial copy.
	bool read(uint32_t offset, uint8_t* out, size_t len);
	bool erase();

#if !defined(ESP_PLATFORM)
	// Test-only: an empty vector means "no dump".
	void setImageForTest(std::vector<uint8_t> image);
#endif
}

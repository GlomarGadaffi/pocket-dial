#pragma once

// NvsWriterLogic.hpp -- the policy of the NVS writer task (#986 slice 2).
//
// The problem: a REGISTER adoption and the *72/*73 codes called nvs_set_str +
// nvs_commit with RequestsHandler::_mutex held. A flash write is tens of ms
// and a page garbage collection is more, and every other task that wants
// _mutex (the 20 ms anchor workers, the 911 lane) waits behind it.
//
// The fix has the cdr_persist shape (CdrRing.cpp): the caller, still under
// _mutex, only serialises the table into a per-key staging slot (reserved at
// boot, PSRAM where the build has it; static on the host) and
// overwrites that key's depth-1 queue; the flash_writer task (FlashWriter.cpp,
// #991, shared with the CDR ring) takes it and does the nvs_* calls. Everything here is the part that is not FreeRTOS,
// so the host suite runs the same code the board runs:
//
//   * stage():   refuse during a factory reset, refuse (never truncate) a blob
//                larger than the slot, otherwise overwrite the key's queue.
//                Never blocks and never allocates. The caller serialises
//                callers of one key (both hold _mutex).
//   * drainOnce(): per key with a blob waiting, register as a resetguard
//                writer BEFORE taking it, so the factory reset's
//                waitForWritersIdle() covers exactly the time the writer holds
//                data; a blob taken while a reset runs is discarded unwritten.
//
// The queue is a Transport: FreeRTOS queues on the board, DepthOneMailboxes on
// the host. Each key has its OWN queue, so a *72 never overwrites a
// device-table blob; within a key the newest complete snapshot replaces an
// unwritten older one (last write wins, which is right for state blobs).
//
// Slice 4 (#986) adds the DID table as the third key. Its blob is not one NVS
// string but a fixed-layout snapshot that DidMapping::writeSnapshot() applies
// slot by slot; the policy here is the same, and what that buys is the config
// import: a clear and N sets of the table leave the writer one snapshot (the
// last) when it has not yet taken the earlier ones, instead of N+1 commits under
// RequestsHandler::_mutex.
//
// #997 adds the telephony API config ("tapicfg") as the fourth key, minus its
// client secrets: those are written synchronously by TelephonyApiConfig, only
// when one changed, and never pass through a slot, a queue or the scratch.
//
// Power-fail window: from stage() until the writer's nvs_commit returns. In
// RAM the table is already right; on flash the previous snapshot stays valid
// (an NVS commit is atomic per item) until the new one lands. The window is the
// writer's wake latency (priority 1) plus the NVS write, longer if that write
// triggers a page garbage collection, plus at most the unit in progress and one
// unit of every other queue of the shared writer (#991: the CDR ring's blob and
// the other keys).

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

#include "ResetGuard.hpp"

#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
#include <algorithm>
#include <mutex>
#include <vector>
#endif

namespace nvswriter
{
	// DidMap is not one NVS string like the other two: its blob is a fixed-layout
	// snapshot of the DID table that DidMapping::writeSnapshot() applies slot by
	// slot in the "didmap" namespace (#986 slice 4).
	//
	// Telephony is the "tapicfg" table WITHOUT the client secrets (#997): the snapshot
	// holds every slot's type, enabled flag, URL, client id and route DN and the active
	// slot, and TelephonyApiConfig::writeSnapshot() unpacks it into the same keys the
	// whole-table write always used. The secret is never staged: it would sit, in the
	// clear and unzeroised, in the staging slot, the queue item and the writer's scratch.
	enum class Key : uint8_t { Devices = 0, Forwards = 1, DidMap = 2, Telephony = 3 };
	constexpr size_t kKeyCount = 4;
	constexpr size_t indexOf(Key k) { return static_cast<size_t>(k); }
	constexpr Key keyAt(size_t i) { return static_cast<Key>(i); }

	// One queue item: the payload length, then the payload and its NUL. `Cap`
	// counts the data bytes INCLUDING the NUL, so the longest payload is Cap-1.
	template <size_t Cap>
	struct Slot
	{
		uint32_t len = 0;
		char data[Cap] = {};
	};
	constexpr size_t kDataOffset = sizeof(uint32_t);
	static_assert(offsetof(Slot<4>, data) == kDataOffset, "a Slot is len, then data: drainOnce() reads it that way");

	struct SlotRef
	{
		void* item = nullptr;       // what the queue copies in and out
		uint32_t* len = nullptr;
		char* data = nullptr;
		size_t cap = 0;             // data bytes including the NUL
		size_t itemBytes = 0;       // sizeof(Slot<cap>)
	};

	template <size_t Cap>
	SlotRef refOf(Slot<Cap>& s)
	{
		return SlotRef{&s, &s.len, s.data, Cap, sizeof(Slot<Cap>)};
	}

	// Fixed-buffer appender. All-or-nothing per append: an append that does not
	// fit sets the overflow flag and writes nothing, so a blob is either whole
	// or refused -- never truncated, which would persist a table that loads
	// back with rows missing.
	class BlobWriter
	{
	public:
		BlobWriter(char* buf, size_t cap) : _buf(buf), _cap(cap), _over(cap == 0) {}

		void str(std::string_view s)
		{
			if (_over) return;
			if (s.size() > _cap - 1 - _len) { _over = true; return; }
			if (!s.empty()) std::memcpy(_buf + _len, s.data(), s.size());
			_len += s.size();
		}
		void ch(char c) { str(std::string_view(&c, 1)); }
		// For a value that cannot be represented in the layout (a DID field longer
		// than its cell): refused like an overflow, never cut short.
		void fail() { _over = true; }
		void uint(uint32_t v)
		{
			char rev[10] = {};
			size_t n = 0;
			do
			{
				rev[n++] = static_cast<char>('0' + (v % 10));
				v /= 10;
			} while (v != 0);
			char out[10] = {};
			for (size_t i = 0; i < n; ++i) out[i] = rev[n - 1 - i];
			str(std::string_view(out, n));
		}

		// Writes the NUL. False if any append was refused.
		bool finish()
		{
			if (_over) return false;
			_buf[_len] = '\0';
			return true;
		}
		size_t size() const { return _len; }
		bool overflowed() const { return _over; }

	private:
		char* _buf;
		size_t _cap;
		size_t _len = 0;
		bool _over;
	};

	enum class StageResult : uint8_t
	{
		Ok,
		Reset,        // a factory reset is running: refused, counted as suppressed
		TooBig,       // would not fit the slot: refused, counted
		NotRunning,   // the writer task never started (board only)
	};

	struct Stats
	{
		uint32_t staged = 0;       // blobs accepted into a queue
		uint32_t overwrites = 0;   // ...of which replaced a blob nobody had taken yet
		uint32_t tooBig = 0;       // refused: larger than the slot
		uint32_t suppressed = 0;   // refused or discarded because a factory reset runs
		uint32_t written = 0;      // sink returned true
		uint32_t failed = 0;       // sink returned false, or the item was malformed
	};

	// Transport requirements (all non-blocking):
	//   bool overwrite(Key, const void* item)  copy item in, replacing any unread
	//                                          one; true if one was replaced
	//   bool receive(Key, void* item)          copy the waiting item out, if any
	//   bool waiting(Key) const
	template <class Transport>
	class Stager
	{
	public:
		Stager(Transport& t, const std::array<SlotRef, kKeyCount>& slots, void* scratch)
			: _t(t), _slots(slots), _scratch(scratch)
		{
		}

		// `fill(BlobWriter&)` serialises into the key's staging slot. A refused
		// stage leaves whatever the queue already holds untouched.
		template <class Fill>
		StageResult stage(Key k, Fill&& fill)
		{
			if (resetguard::inProgress())
			{
				_suppressed.fetch_add(1);
				return StageResult::Reset;
			}
			const SlotRef& s = _slots[indexOf(k)];
			BlobWriter w(s.data, s.cap);
			fill(w);
			if (!w.finish())
			{
				_tooBig.fetch_add(1);
				return StageResult::TooBig;
			}
			*s.len = static_cast<uint32_t>(w.size());
			if (_t.overwrite(k, s.item)) _overwrites.fetch_add(1);
			_staged.fetch_add(1);
			return StageResult::Ok;
		}

		// One pass over the keys. `sink(Key, const char* nulTerminated, size_t len)`
		// returns whether the write succeeded. Returns how many keys it wrote.
		template <class Sink>
		unsigned drainOnce(Sink&& sink)
		{
			unsigned wrote = 0;
			for (size_t i = 0; i < kKeyCount; ++i)
			{
				const Key k = keyAt(i);
				if (!_t.waiting(k)) continue;
				// Registered BEFORE the take: the writer is a resetguard writer for
				// exactly the time it holds data, so a reset's waitForWritersIdle()
				// either waits for this write or finds the flag already set.
				resetguard::WriteScope scope;
				if (!_t.receive(k, _scratch)) continue;
				if (!scope.allowed())
				{
					_suppressed.fetch_add(1);
					continue;
				}
				uint32_t len = 0;
				std::memcpy(&len, _scratch, sizeof(len));
				char* data = static_cast<char*>(_scratch) + kDataOffset;
				if (len >= _slots[i].cap)
				{
					_failed.fetch_add(1);
					continue;
				}
				data[len] = '\0';
				if (sink(k, static_cast<const char*>(data), static_cast<size_t>(len)))
				{
					++wrote;
					_written.fetch_add(1);
				}
				else
				{
					_failed.fetch_add(1);
				}
			}
			return wrote;
		}

		Stats stats() const
		{
			Stats s;
			s.staged = _staged.load();
			s.overwrites = _overwrites.load();
			s.tooBig = _tooBig.load();
			s.suppressed = _suppressed.load();
			s.written = _written.load();
			s.failed = _failed.load();
			return s;
		}
		void resetStats()
		{
			_staged.store(0);
			_overwrites.store(0);
			_tooBig.store(0);
			_suppressed.store(0);
			_written.store(0);
			_failed.store(0);
		}

	private:
		Transport& _t;
		std::array<SlotRef, kKeyCount> _slots;
		void* _scratch;
		std::atomic<uint32_t> _staged{0};
		std::atomic<uint32_t> _overwrites{0};
		std::atomic<uint32_t> _tooBig{0};
		std::atomic<uint32_t> _suppressed{0};
		std::atomic<uint32_t> _written{0};
		std::atomic<uint32_t> _failed{0};
	};

#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
	// The host's queues: what xQueueOverwrite / xQueueReceive do on a length-1
	// queue, one per key. Host only; the board uses FreeRTOS queues.
	class DepthOneMailboxes
	{
	public:
		explicit DepthOneMailboxes(const std::array<SlotRef, kKeyCount>& slots)
		{
			for (size_t i = 0; i < kKeyCount; ++i) _box[i].bytes.assign(slots[i].itemBytes, 0);
		}

		bool overwrite(Key k, const void* item)
		{
			std::lock_guard<std::mutex> g(_m);
			Box& b = _box[indexOf(k)];
			const bool replaced = b.full;
			std::memcpy(b.bytes.data(), item, b.bytes.size());
			b.full = true;
			return replaced;
		}
		bool receive(Key k, void* item)
		{
			std::lock_guard<std::mutex> g(_m);
			Box& b = _box[indexOf(k)];
			if (!b.full) return false;
			std::memcpy(item, b.bytes.data(), b.bytes.size());
			b.full = false;
			return true;
		}
		bool waiting(Key k) const
		{
			std::lock_guard<std::mutex> g(_m);
			return _box[indexOf(k)].full;
		}

		// Test seam: the payload waiting for `k` (empty when nothing waits).
		std::string_view payload(Key k) const
		{
			std::lock_guard<std::mutex> g(_m);
			const Box& b = _box[indexOf(k)];
			if (!b.full) return {};
			uint32_t len = 0;
			std::memcpy(&len, b.bytes.data(), sizeof(len));
			return std::string_view(reinterpret_cast<const char*>(b.bytes.data()) + kDataOffset, len);
		}
		void clear()
		{
			std::lock_guard<std::mutex> g(_m);
			for (Box& b : _box)
			{
				b.full = false;
				std::fill(b.bytes.begin(), b.bytes.end(), static_cast<unsigned char>(0));
			}
		}
		// Test seam (#997): whether `needle` is anywhere in any key's queue storage, whole
		// item, whether or not it is still waiting. A FreeRTOS queue does not wipe its
		// storage when the writer takes an item, so the host's boxes do not either.
		bool holdsForTest(std::string_view needle) const
		{
			std::lock_guard<std::mutex> g(_m);
			for (const Box& b : _box)
			{
				const std::string_view all(reinterpret_cast<const char*>(b.bytes.data()), b.bytes.size());
				if (all.find(needle) != std::string_view::npos) return true;
			}
			return false;
		}

	private:
		struct Box
		{
			std::vector<unsigned char> bytes;
			bool full = false;
		};
		mutable std::mutex _m;
		std::array<Box, kKeyCount> _box;
	};
#endif
}

#ifndef PD_BOOT_TASK_SLOTS_HPP
#define PD_BOOT_TASK_SLOTS_HPP

// #1126: which boot-allocated tasks did not get their stack, and which emergency-path worker is absent.
//
// A StaticTaskSlot is allocated once at construction. If it fails, the task never exists and the board
// carries on. Before this, the only trace was one rate-limited log line and a null stackHwm_* on
// /api/status. This keeps the facts where /api/status and tick() can read them, on host and on the
// board alike (pure atomics, no ESP symbols):
//   * failures(): how many slots of each kind failed to allocate at boot (a count, so tel_media_rx
//     reads "2 of N slots").
//   * workerAbsent(): the task is known not to be running (slot failed, or the create failed).
//   * alertDue()/markAlerted(): the emergency-path tasks get ONE operator alert each, latched.
// Visibility only: nothing here gates, delays or refuses a call, and nothing allocates.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace pd
{
	enum class BootTask : uint8_t
	{
		TelSweep = 0,   // the 911/933 orphan sweep (#977): an EMERGENCY-PATH task
		TelMediaRx,
		RtpMediaRx,
		RtpMediaTx,
		ConfMixTick,
		Count
	};

	class BootTaskSlots
	{
	public:
		static constexpr std::size_t kCount = static_cast<std::size_t>(BootTask::Count);

		static const char* name(BootTask t) { return kRows[idx(t)].name; }
		static bool emergencyPath(BootTask t) { return kRows[idx(t)].emergencyPath; }

		// StaticTaskSlot::alloc()'s outcome for the slot named `taskName`. An unknown name is ignored.
		void noteAlloc(const char* taskName, bool ok)
		{
			for (std::size_t i = 0; i < kCount; ++i)
			{
				if (std::strcmp(kRows[i].name, taskName) != 0) continue;
				if (!ok)
				{
					_failures[i].fetch_add(1, std::memory_order_relaxed);
					_absent[i].store(true, std::memory_order_relaxed);
				}
				return;
			}
		}

		// The task's create outcome at start(): true running, false absent.
		void setWorker(BootTask t, bool running) { _absent[idx(t)].store(!running, std::memory_order_relaxed); }

		uint32_t failures(BootTask t) const { return _failures[idx(t)].load(std::memory_order_relaxed); }
		bool workerAbsent(BootTask t) const { return _absent[idx(t)].load(std::memory_order_relaxed); }

		// The first emergency-path task that is absent and not yet alerted.
		bool alertDue(BootTask& out) const
		{
			for (std::size_t i = 0; i < kCount; ++i)
			{
				if (!kRows[i].emergencyPath) continue;
				if (_absent[i].load(std::memory_order_relaxed) && !_alerted[i].load(std::memory_order_relaxed))
				{
					out = static_cast<BootTask>(i);
					return true;
				}
			}
			return false;
		}
		void markAlerted(BootTask t) { _alerted[idx(t)].store(true, std::memory_order_relaxed); }

#if !defined(ESP_PLATFORM) && !defined(ESP32)
		// Host tests only: back to a clean boot.
		void resetForTest()
		{
			for (std::size_t i = 0; i < kCount; ++i)
			{
				_failures[i].store(0);
				_absent[i].store(false);
				_alerted[i].store(false);
			}
		}
#endif

	private:
		struct Row { const char* name; bool emergencyPath; };
		static constexpr Row kRows[kCount] = {
			{"tel_sweep", true}, {"tel_media_rx", false}, {"rtp_media_rx", false},
			{"rtp_media_tx", false}, {"conf_mix_tick", false},
		};
		static constexpr std::size_t idx(BootTask t) { return static_cast<std::size_t>(t); }

		std::atomic<uint32_t> _failures[kCount] = {};
		std::atomic<bool>     _absent[kCount] = {};
		std::atomic<bool>     _alerted[kCount] = {};
	};

	inline BootTaskSlots& bootTaskSlots()
	{
		static BootTaskSlots s;
		return s;
	}
}

#endif // PD_BOOT_TASK_SLOTS_HPP

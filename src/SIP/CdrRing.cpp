// CdrRing.cpp: the CDR ring buffer, extracted out of RequestsHandler.
#include "CdrRing.hpp"

#include <chrono>
#include <cstdlib>

#include "PbxPersist.hpp"

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "nvs_flash.h"
#include "nvs.h"
#endif

namespace
{
	using pbxpersist::deserializeBlob;

	// NVS namespace holding the persisted CDR ring (distinct from
	// pbxpersist::kNvsNamespace — the CDR blob has its own key shape and is
	// unrelated to the PBX feature-config tables).
	constexpr auto NVS_CDR_NS = "cdrlog";

	// Same clock RequestsHandler::nowEpochMs() uses; duplicated here rather than
	// reached through an engine indirection, since it is stateless and this
	// class otherwise needs no engine service at all (see class comment).
	uint64_t nowEpochMs()
	{
		return static_cast<uint64_t>(
			std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now().time_since_epoch()).count());
	}
}

const CallDetailRecord& CdrRing::record(const std::shared_ptr<Session>& session,
	std::string_view srcNumber, std::string_view destNumber)
{
	CallDetailRecord rec;
	rec.caller = std::string(srcNumber);
	rec.callee = std::string(destNumber);

	uint64_t startMs = nowEpochMs();
	uint32_t durationSec = 0;
	CdrResult result = CdrResult::Failed;

	if (session)
	{
		auto now = std::chrono::steady_clock::now();
		startMs = static_cast<uint64_t>(
			std::chrono::duration_cast<std::chrono::milliseconds>(
				session->getStartTime().time_since_epoch()).count());

		switch (session->getState())
		{
			// Both Connected and Bye are "answered": a normal call ends via BYE, which
			// sets the state to Bye (NOT Connected) just before endCall() runs, while
			// the echo (777) path tears down straight from Connected. Session::setState
			// resets _startTime to the connect instant on the Connected transition and
			// the later Bye transition does NOT touch it, so getStartTime() still marks
			// the answer instant in both cases — talk time is now - startTime.
			case Session::State::Connected:
			case Session::State::Held:   // call torn down mid-hold → still Answered (#73)
			case Session::State::Bye:
				result = CdrResult::Answered;
				{
					int64_t secs = static_cast<int64_t>(
						std::chrono::duration_cast<std::chrono::seconds>(
							now - session->getStartTime()).count());
					if (secs < 0) secs = 0;
					durationSec = static_cast<uint32_t>(secs);
				}
				break;
			case Session::State::Busy:        result = CdrResult::Busy;        break;
			case Session::State::Cancel:      result = CdrResult::Cancelled;   break;
			case Session::State::Unavailable: result = CdrResult::Unavailable; break;
			default:                          result = CdrResult::Failed;      break;
		}
	}

	rec.startMs = startMs;
	rec.durationSec = durationSec;
	rec.result = result;

	// Fixed ring write: overwrite the oldest slot once full (no heap growth).
	const size_t writtenIdx = _head;
	_ring[writtenIdx] = std::move(rec);
	_head = (_head + 1) % POCKETDIAL_CDR_RECORDS;
	if (_count < POCKETDIAL_CDR_RECORDS)
	{
		++_count;
	}

	// Persist the ring so records survive reboot (write-through on teardown; no-op
	// on host). Caller (RequestsHandler::endCall) holds _mutex. See persist()
	// for the wear note.
	persist();

	return _ring[writtenIdx];
}

std::vector<CallDetailRecord> CdrRing::snapshot() const
{
	std::vector<CallDetailRecord> out;
	out.reserve(_count);
	for (size_t i = 0; i < _count; ++i)
	{
		// _head points one past the newest; walk backwards with wrap.
		size_t idx = (_head + POCKETDIAL_CDR_RECORDS - 1 - i) % POCKETDIAL_CDR_RECORDS;
		out.push_back(_ring[idx]);
	}
	return out;
}

std::string CdrRing::lastCallerFor(std::string_view calleeExt) const
{
	for (size_t i = 0; i < _count; ++i)
	{
		size_t idx = (_head + POCKETDIAL_CDR_RECORDS - 1 - i) % POCKETDIAL_CDR_RECORDS;
		if (_ring[idx].callee == calleeExt && !_ring[idx].caller.empty())
		{
			return _ring[idx].caller;
		}
	}
	return std::string();
}

void CdrRing::load()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	nvs_handle_t h;
	if (nvs_open(NVS_CDR_NS, NVS_READWRITE, &h) != ESP_OK)
	{
		return;
	}
	size_t len = 0;
	if (nvs_get_str(h, "ring", nullptr, &len) == ESP_OK && len > 0)
	{
		std::string buf(len, '\0');
		if (nvs_get_str(h, "ring", buf.data(), &len) == ESP_OK)
		{
			if (!buf.empty() && buf.back() == '\0') buf.pop_back();
			// Record: caller \t callee \t startMs \t durationSec \t result(int)
			for (const auto& rec : deserializeBlob(buf))
			{
				if (rec.size() < 5) continue;
				if (_count >= POCKETDIAL_CDR_RECORDS) break;
				CallDetailRecord r;
				r.caller = rec[0];
				r.callee = rec[1];
				r.startMs = static_cast<uint64_t>(strtoull(rec[2].c_str(), nullptr, 10));
				r.durationSec = static_cast<uint32_t>(strtoul(rec[3].c_str(), nullptr, 10));
				int ri = atoi(rec[4].c_str());
				r.result = (ri >= 0 && ri <= static_cast<int>(CdrResult::Failed))
					? static_cast<CdrResult>(ri) : CdrResult::Failed;
				// Records were serialized oldest-first; append preserving order.
				_ring[_head] = std::move(r);
				_head = (_head + 1) % POCKETDIAL_CDR_RECORDS;
				++_count;
			}
		}
	}
	nvs_close(h);
#endif
}

void CdrRing::clearAll()
{
	_ring = {};
	_head = 0;
	_count = 0;
	persist();
}

void CdrRing::persist()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// Serialize the ring oldest-first (same order load() replays). Bounded by
	// POCKETDIAL_CDR_RECORDS, so the blob is fixed-footprint. Write-through on each
	// teardown: the CDR ring is small (default 32) and calls end infrequently
	// relative to flash endurance, so a per-call rewrite is acceptable — see summary.
	std::string blob;
	for (size_t i = 0; i < _count; ++i)
	{
		size_t idx = (_head + POCKETDIAL_CDR_RECORDS - _count + i) % POCKETDIAL_CDR_RECORDS;
		const CallDetailRecord& r = _ring[idx];
		blob += r.caller; blob += '\t';
		blob += r.callee; blob += '\t';
		blob += std::to_string(r.startMs); blob += '\t';
		blob += std::to_string(r.durationSec); blob += '\t';
		blob += std::to_string(static_cast<int>(r.result)); blob += '\n';
	}
	nvs_handle_t h;
	if (nvs_open(NVS_CDR_NS, NVS_READWRITE, &h) == ESP_OK)
	{
		nvs_set_str(h, "ring", blob.c_str());
		nvs_commit(h);
		nvs_close(h);
	}
#endif
}

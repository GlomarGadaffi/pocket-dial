// VoicemailArchive.cpp -- Issue #246 (voicemail Stage 3 of #194).
#include "VoicemailArchive.hpp"

#include <cstdio>
#include <cstring>

#if defined(PD_ETH_HAS_SD)
#include <sys/stat.h>
#endif

namespace
{
	void wr16(uint8_t* p, uint16_t v)
	{
		p[0] = static_cast<uint8_t>(v & 0xFF);
		p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
	}

	void wr32(uint8_t* p, uint32_t v)
	{
		p[0] = static_cast<uint8_t>(v & 0xFF);
		p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
		p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
		p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
	}

	constexpr uint16_t kWaveFormatMulaw = 7;
	constexpr uint32_t kSampleRateHz = 8000;
}

namespace vmarchive
{

void buildWavHeader(size_t dataBytes, uint8_t* out)
{
	// Byte-for-byte the layout HoldMusic::parseUlawWav() walks: RIFF/WAVE,
	// an 18-byte fmt chunk (tag 7 = WAVE_FORMAT_MULAW, mono, 8 kHz, 8 bits,
	// cbSize=0), a 4-byte fact chunk (sample count -- 1 byte/sample for 8-bit
	// mono, so equal to dataBytes), then the data chunk header. See #194 s1d
	// for why this exact shape (not the 44-byte PCM-style header) is
	// required: WAVE_FORMAT_MULAW readers expect the fact chunk and the
	// 18-byte fmt, not the 16-byte tag-1 shape.
	const uint32_t riffSize = static_cast<uint32_t>(50 + dataBytes);   // total - 8
	const uint32_t dataSize = static_cast<uint32_t>(dataBytes);

	std::memcpy(out + 0, "RIFF", 4);
	wr32(out + 4, riffSize);
	std::memcpy(out + 8, "WAVE", 4);

	std::memcpy(out + 12, "fmt ", 4);
	wr32(out + 16, 18);                      // fmt chunk size
	wr16(out + 20, kWaveFormatMulaw);        // wFormatTag
	wr16(out + 22, 1);                       // nChannels
	wr32(out + 24, kSampleRateHz);           // nSamplesPerSec
	wr32(out + 28, kSampleRateHz);           // nAvgBytesPerSec (1 byte/sample)
	wr16(out + 32, 1);                       // nBlockAlign
	wr16(out + 34, 8);                       // wBitsPerSample
	wr16(out + 36, 0);                       // cbSize

	std::memcpy(out + 38, "fact", 4);
	wr32(out + 42, 4);                       // fact chunk size
	wr32(out + 46, dataSize);                // dwSampleLength

	std::memcpy(out + 50, "data", 4);
	wr32(out + 54, dataSize);
	// Caller appends `dataBytes` of raw mu-law starting at out + kWavHeaderBytes.
}

WriterQueue::WriterQueue(size_t capacity) : _buf(capacity) {}

bool WriterQueue::push(const QueuedRecording& rec)
{
	std::lock_guard<std::mutex> lock(_m);
	if (_count >= _buf.size()) return false;
	_buf[(_head + _count) % _buf.size()] = rec;
	++_count;
	return true;
}

bool WriterQueue::pop(QueuedRecording& out)
{
	std::lock_guard<std::mutex> lock(_m);
	if (_count == 0) return false;
	out = _buf[_head];
	_head = (_head + 1) % _buf.size();
	--_count;
	return true;
}

size_t WriterQueue::size() const
{
	std::lock_guard<std::mutex> lock(_m);
	return _count;
}

void WriterQueue::clear()
{
	std::lock_guard<std::mutex> lock(_m);
	_head = 0;
	_count = 0;
}

void drainAll(WriterQueue& queue, Sink& sink, uint8_t* const* stagingBufs)
{
	QueuedRecording rec;
	while (queue.pop(rec))
	{
		if (rec.stagingSlot < 0) continue;   // defensive: never a valid job
		sink.write(rec, stagingBufs[rec.stagingSlot]);
	}
}

#if defined(PD_ETH_HAS_SD)

namespace
{
	constexpr const char* kArchiveDir = "/sdcard/vm";

	class FatFsSink final : public Sink
	{
	public:
		void write(const QueuedRecording& rec, const uint8_t* mulaw) override
		{
			std::lock_guard<std::mutex> lock(_ioMutex);

			// mkdir() failing with EEXIST is the expected steady state after
			// the first message from any given extension -- same as
			// CdrArchive.cpp's init(). Best-effort: a failure here just means
			// the fopen() below fails too, already handled.
			::mkdir(kArchiveDir, 0775);
			char dir[80];
			std::snprintf(dir, sizeof(dir), "%s/%s", kArchiveDir, rec.extension);
			::mkdir(dir, 0775);

			char name[48];
			if (rec.epochSeconds != 0)
			{
				std::snprintf(name, sizeof(name), "%llu",
					static_cast<unsigned long long>(rec.epochSeconds));
			}
			else
			{
				// Wall clock never synced -- name by boot-relative sequence
				// rather than drop the message (unlike cdrarchive::record(),
				// which drops a CDR row in this case: a voicemail is worth
				// more than its timestamp). The index row below still
				// records epochSeconds=0 so a retrieval menu can say "time
				// unknown" instead of inventing a date.
				std::snprintf(name, sizeof(name), "boot-%llu",
					static_cast<unsigned long long>(rec.sequence));
			}

			char tmpPath[160], finalPath[160];
			std::snprintf(tmpPath, sizeof(tmpPath), "%s/%s.wav.tmp", dir, name);
			std::snprintf(finalPath, sizeof(finalPath), "%s/%s.wav", dir, name);

			std::FILE* f = std::fopen(tmpPath, "wb");
			if (f == nullptr) return;   // best-effort: card may have been pulled mid-run

			uint8_t header[kWavHeaderBytes];
			buildWavHeader(rec.length, header);
			const bool wroteHeader = std::fwrite(header, 1, sizeof(header), f) == sizeof(header);
			const bool wroteData = std::fwrite(mulaw, 1, rec.length, f) == rec.length;
			std::fclose(f);

			if (!wroteHeader || !wroteData)
			{
				std::remove(tmpPath);   // truncated write -- don't leave a half-file behind
				return;
			}

			// Write-order (#194 prereq 1b): audio finalized and renamed into
			// place BEFORE the index row is appended, so a crash between the
			// two leaves an orphaned .tmp (sweepable at boot) rather than an
			// index entry pointing at a file that doesn't exist yet.
			if (std::rename(tmpPath, finalPath) != 0)
			{
				std::remove(tmpPath);
				return;
			}

			// Minimal per-mailbox index, one row per message. The retrieval
			// menu (a later slice, not yet built) is this file's first real
			// consumer -- schema may grow once that lands; kept deliberately
			// small for now rather than guessing fields nothing reads yet.
			char idxPath[160];
			std::snprintf(idxPath, sizeof(idxPath), "%s/index.csv", dir);
			std::FILE* idx = std::fopen(idxPath, "a");
			if (idx == nullptr) return;   // audio is safely on disk even if this append fails
			std::fprintf(idx, "%s,%llu,%zu,%s\n", name,
				static_cast<unsigned long long>(rec.epochSeconds), rec.length, rec.callId);
			std::fclose(idx);
		}

	private:
		// Same reasoning as CdrArchive.cpp's FatFsSink::_ioMutex: serializes
		// concurrent write() calls (at most POCKETDIAL_MAX_VOICEMAIL_LEGS
		// worth queued at once, drained one at a time by the single writer
		// task -- this is a leaf lock against a future second caller, not a
		// contended one today).
		std::mutex _ioMutex;
	};
}

Sink& productionSink()
{
	static FatFsSink s;
	return s;
}

#endif  // PD_ETH_HAS_SD

}  // namespace vmarchive

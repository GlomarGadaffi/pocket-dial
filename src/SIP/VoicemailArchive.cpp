// VoicemailArchive.cpp -- Issue #246 (voicemail Stage 3 of #194).
#include "VoicemailArchive.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#if defined(PD_ETH_HAS_SD)
#include <dirent.h>     // wipe(): opendir/readdir (#450)
#include <sys/stat.h>
#include <unistd.h>     // wipe(): rmdir (#450)
#include "PoolConfig.hpp"
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

void drainAll(WriterQueue& queue, Sink& sink, uint8_t* const* stagingBufs,
	const std::function<void(const QueuedRecording&)>& afterWrite)
{
	QueuedRecording rec;
	while (queue.pop(rec))
	{
		if (rec.stagingSlot < 0) continue;   // defensive: never a valid job
		sink.write(rec, stagingBufs[rec.stagingSlot]);
		if (afterWrite) afterWrite(rec);
	}
}

void chompIndexLine(char* line)
{
	size_t n = std::strlen(line);
	while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
	{
		line[--n] = '\0';
	}
}

bool parseTombstoneLine(const char* line, char* nameOut, size_t nameCap)
{
	const size_t prefixLen = std::strlen(kTombstonePrefix);
	if (std::strncmp(line, kTombstonePrefix, prefixLen) != 0) return false;
	std::snprintf(nameOut, nameCap, "%s", line + prefixLen);
	return true;
}

bool parseEntryLine(const char* line, MessageInfo& info)
{
	const char* p1 = std::strchr(line, ',');
	if (!p1) return false;
	const char* p2 = std::strchr(p1 + 1, ',');
	if (!p2) return false;
	const char* p3 = std::strchr(p2 + 1, ',');
	if (!p3) return false;

	const size_t nameLen = static_cast<size_t>(p1 - line);
	if (nameLen == 0 || nameLen >= sizeof(info.name)) return false;
	std::memcpy(info.name, line, nameLen);
	info.name[nameLen] = '\0';

	info.epochSeconds = std::strtoull(p1 + 1, nullptr, 10);
	info.length = static_cast<size_t>(std::strtoull(p2 + 1, nullptr, 10));
	std::snprintf(info.callId, sizeof(info.callId), "%s", p3 + 1);
	return true;
}

#if defined(PD_ETH_HAS_SD)

namespace
{
	constexpr const char* kArchiveDir = "/sdcard/vm";

	class FatFsSink final : public Sink
	{
	public:
		// #450: the tree is exactly /sdcard/vm/<extension>/<file>, so two fixed
		// readdir loops cover it: no recursion, no allocation. One path buffer
		// (this can run on a 4 KB HTTP connection stack), with the directory
		// prefix reused for its files. A name that would not fit is skipped
		// rather than remove()d mangled -- same rule as CdrArchive's wipe().
		void wipe() override
		{
			std::lock_guard<std::mutex> lock(_ioMutex);
			DIR* top = ::opendir(kArchiveDir);
			if (top == nullptr) return;   // nothing recorded yet
			struct dirent* ext;
			while ((ext = ::readdir(top)) != nullptr)
			{
				if (ext->d_name[0] == '.') continue;   // "." / ".."
				char path[300];
				const int dirLen = std::snprintf(path, sizeof(path), "%s/%s", kArchiveDir, ext->d_name);
				if (dirLen < 0 || static_cast<size_t>(dirLen) >= sizeof(path)) continue;
				DIR* d = ::opendir(path);
				if (d == nullptr)
				{
					std::remove(path);   // a stray file directly under the root
					continue;
				}
				struct dirent* f;
				while ((f = ::readdir(d)) != nullptr)
				{
					if (f->d_name[0] == '.') continue;
					const size_t room = sizeof(path) - static_cast<size_t>(dirLen);
					const int n = std::snprintf(path + dirLen, room, "/%s", f->d_name);
					if (n >= 0 && static_cast<size_t>(n) < room) std::remove(path);
					path[dirLen] = '\0';   // back to the directory for the next entry
				}
				::closedir(d);
				::rmdir(path);
			}
			::closedir(top);
		}

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

namespace
{
	class FatFsSource final : public Source
	{
	public:
		size_t listMessages(const char* extension, MessageInfo* out, size_t maxCount) const override
		{
			char idxPath[160];
			std::snprintf(idxPath, sizeof(idxPath), "%s/%s/index.csv", kArchiveDir, extension);

			std::lock_guard<std::mutex> lock(_ioMutex);

			// Pass 1: collect every tombstoned name (bounded the same way the
			// listing itself is -- see PoolConfig.hpp's
			// POCKETDIAL_VOICEMAIL_MAX_MESSAGES_PER_BOX comment for why a
			// fixed array, not a growing one, here too).
			char tombstoned[POCKETDIAL_VOICEMAIL_MAX_MESSAGES_PER_BOX][sizeof(MessageInfo::name)];
			size_t tombstoneCount = 0;

			std::FILE* f = std::fopen(idxPath, "r");
			if (f == nullptr) return 0;   // no mailbox directory yet -- not an error

			char line[512];
			while (std::fgets(line, sizeof(line), f) != nullptr)
			{
				chompIndexLine(line);
				if (tombstoneCount >= POCKETDIAL_VOICEMAIL_MAX_MESSAGES_PER_BOX) continue;
				if (parseTombstoneLine(line, tombstoned[tombstoneCount], sizeof(tombstoned[0])))
				{
					++tombstoneCount;
				}
			}

			// Pass 2: re-scan for real entries, skipping anything tombstoned.
			std::rewind(f);
			size_t count = 0;
			while (count < maxCount && std::fgets(line, sizeof(line), f) != nullptr)
			{
				chompIndexLine(line);
				MessageInfo info;
				if (!parseEntryLine(line, info)) continue;   // a tombstone row, or malformed -- skip

				bool skip = false;
				for (size_t i = 0; i < tombstoneCount; ++i)
				{
					if (std::strcmp(tombstoned[i], info.name) == 0) { skip = true; break; }
				}
				if (skip) continue;

				out[count++] = info;
			}
			std::fclose(f);
			return count;
		}

		size_t readMessage(const char* extension, const char* name,
			uint8_t* out, size_t capacity) const override
		{
			if (isTombstoned(extension, name)) return 0;

			char path[160];
			std::snprintf(path, sizeof(path), "%s/%s/%s.wav", kArchiveDir, extension, name);

			std::lock_guard<std::mutex> lock(_ioMutex);
			std::FILE* f = std::fopen(path, "rb");
			if (f == nullptr) return 0;

			std::fseek(f, 0, SEEK_END);
			const long fileSize = std::ftell(f);
			if (fileSize < static_cast<long>(kWavHeaderBytes))
			{
				std::fclose(f);
				return 0;
			}
			const size_t dataLen = static_cast<size_t>(fileSize) - kWavHeaderBytes;
			if (dataLen > capacity)
			{
				// Refuse outright rather than truncate -- see Source::readMessage's
				// doc comment for why a clipped playback is worse than a clean 0.
				std::fclose(f);
				return 0;
			}

			std::fseek(f, static_cast<long>(kWavHeaderBytes), SEEK_SET);
			const size_t got = std::fread(out, 1, dataLen, f);
			std::fclose(f);
			return got == dataLen ? got : 0;
		}

		bool markDeleted(const char* extension, const char* name) override
		{
			char idxPath[160];
			std::snprintf(idxPath, sizeof(idxPath), "%s/%s/index.csv", kArchiveDir, extension);

			std::lock_guard<std::mutex> lock(_ioMutex);
			std::FILE* idx = std::fopen(idxPath, "a");
			if (idx == nullptr) return true;   // no mailbox -- nothing to tombstone, already "deleted"
			std::fprintf(idx, "%s%s\n", kTombstonePrefix, name);
			std::fclose(idx);
			return true;
		}

	private:
		bool isTombstoned(const char* extension, const char* name) const
		{
			char idxPath[160];
			std::snprintf(idxPath, sizeof(idxPath), "%s/%s/index.csv", kArchiveDir, extension);

			std::lock_guard<std::mutex> lock(_ioMutex);
			std::FILE* f = std::fopen(idxPath, "r");
			if (f == nullptr) return false;

			char line[512];
			char candidate[sizeof(MessageInfo::name)];
			bool found = false;
			while (std::fgets(line, sizeof(line), f) != nullptr)
			{
				chompIndexLine(line);
				if (parseTombstoneLine(line, candidate, sizeof(candidate)) &&
					std::strcmp(candidate, name) == 0)
				{
					found = true;
					break;
				}
			}
			std::fclose(f);
			return found;
		}

		// Same reasoning as FatFsSink::_ioMutex above -- a leaf lock, not a
		// contended one today (one SD-I/O task drives both Sink and Source).
		mutable std::mutex _ioMutex;
	};
}

Source& productionSource()
{
	static FatFsSource s;
	return s;
}

#endif  // PD_ETH_HAS_SD

}  // namespace vmarchive

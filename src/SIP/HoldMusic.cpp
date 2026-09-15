#include "HoldMusic.hpp"
#include "RtpSender.hpp"
#include "RtpReceiver.hpp"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <cerrno>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_random.h"
#include <lwip/inet.h>
#else
#include <cstdlib>
// inet_addr / htons live here off-device; lwip/inet.h supplies them on the board.
#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif
#endif

namespace
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
constexpr const char* TAG = "HoldMusic";
#endif

// Little-endian readers. The RIFF container is LE regardless of host byte order,
// so read byte-wise rather than casting — a cast would be wrong on a BE host and
// would also trip an unaligned access on some targets.
uint16_t rd16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint32_t rd32(const uint8_t* p)
{
	return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8)
	     | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

constexpr uint16_t kWaveFormatMulaw = 7;

}  // namespace

bool HoldMusic::parseUlawWav(const uint8_t* data, size_t len,
                             size_t& outOffset, size_t& outBytes)
{
	// RIFF header is 12 bytes; a fmt chunk header another 8. Anything shorter
	// cannot describe audio at all.
	if (data == nullptr || len < 44) return false;
	if (std::memcmp(data, "RIFF", 4) != 0)   return false;
	if (std::memcmp(data + 8, "WAVE", 4) != 0) return false;

	bool   haveFmt   = false;
	size_t dataOff   = 0;
	size_t dataLen   = 0;

	// Walk the chunk list. Deliberately NOT "skip 44 bytes": a µ-law WAV carries an
	// 18-byte fmt chunk plus a fact chunk, and writers may insert LIST/INFO before
	// data, so the canonical PCM offset lands in the middle of a header.
	size_t pos = 12;
	while (pos + 8 <= len)
	{
		const uint8_t* id = data + pos;
		const uint32_t sz = rd32(data + pos + 4);
		const size_t body = pos + 8;

		// `data` is handled BEFORE the bounds check below, and deliberately so.
		// Callers parse a HEADER PREFIX — loadClip() reads ~1 KB to validate the
		// format before allocating megabytes for a file that might be 44.1 kHz
		// stereo. The data chunk's payload is then legitimately outside the buffer,
		// so requiring it to be resident rejected every real clip. All we need from
		// this chunk is its offset and declared length; the caller clamps that
		// against the true file size.
		if (std::memcmp(id, "data", 4) == 0)
		{
			dataOff = body;
			dataLen = sz;
			break;          // nothing after data matters to us
		}

		// Every OTHER chunk we must be able to step OVER, so it does have to be
		// fully present. A chunk claiming to run past the buffer is malformed or
		// truncated: stop rather than trusting the size, since this is a file that
		// arrived from outside.
		if (sz > len || body + sz > len) break;

		if (std::memcmp(id, "fmt ", 4) == 0)
		{
			if (sz < 16) return false;
			const uint16_t fmtTag   = rd16(data + body + 0);
			const uint16_t channels = rd16(data + body + 2);
			const uint32_t rate     = rd32(data + body + 4);
			const uint16_t bits     = rd16(data + body + 14);

			// Reject loudly instead of playing garbage. A 44.1 kHz stereo PCM file
			// read as µ-law is full-scale noise at 5.5x speed, and the operator has
			// no way to tell that from "the hardware is broken".
			if (fmtTag != kWaveFormatMulaw) return false;
			if (channels != 1)              return false;
			if (rate != SAMPLE_RATE_HZ)     return false;
			if (bits != 8)                  return false;
			haveFmt = true;
		}
		// Chunks are word-aligned: an odd size carries a pad byte that is not
		// counted in the size field.
		pos = body + sz + (sz & 1u);
	}

	if (!haveFmt || dataLen == 0) return false;

	// One whole tick minimum, or the pacing task has nothing to send. Checked
	// against the DECLARED length; loadClip() re-checks what it actually read,
	// since a truncated file can declare more than it carries.
	if (dataLen < BYTES_PER_TICK) return false;

	outOffset = dataOff;
	outBytes  = dataLen;
	return true;
}

size_t HoldMusic::advanceCursor(size_t cursor, size_t clipBytes)
{
	if (clipBytes == 0) return 0;
	const size_t next = cursor + BYTES_PER_TICK;
	// Wrap by modulo rather than "if (next >= clip) next = 0": the latter drops the
	// tail of the clip whenever the length is not a whole number of ticks, which is
	// almost always, producing a click and a shortened loop every time round.
	return next % clipBytes;
}

void HoldMusic::buildGainTable(float gainDb, uint8_t outTable[256])
{
	const float scale = std::pow(10.0f, gainDb / 20.0f);
	for (int code = 0; code < 256; ++code)
	{
		const int16_t pcm = RtpReceiver::mulawDecode(static_cast<uint8_t>(code));
		float scaled = static_cast<float>(pcm) * scale;
		// Clamp before the cast: µ-law's own encoder clips at 32635, but letting a
		// float wrap an int16 first would fold a loud sample to the opposite sign,
		// which is heard as a crack rather than as clipping.
		if (scaled >  32767.0f) scaled =  32767.0f;
		if (scaled < -32768.0f) scaled = -32768.0f;
		outTable[code] = RtpSender::linearToUlaw(static_cast<int16_t>(scaled));
	}
}

HoldMusic::HoldMusic()
{
	for (int i = 0; i < 256; ++i) _gainTable[i] = static_cast<uint8_t>(i);
}

HoldMusic::~HoldMusic()
{
	stop();
	std::lock_guard<std::mutex> lk(_mutex);
	freeClipLocked();
}

void HoldMusic::freeClipLocked()
{
	if (_clip != nullptr)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		heap_caps_free(_clip);
#else
		std::free(_clip);
#endif
		_clip = nullptr;
	}
	_clipBytes.store(0, std::memory_order_release);
	_cursor = 0;
}

void HoldMusic::setGainDb(float db)
{
	uint8_t table[256];
	buildGainTable(db, table);
	{
		std::lock_guard<std::mutex> lk(_mutex);
		std::memcpy(_gainTable, table, sizeof(table));
		// Unity is the common case and skipping the per-byte lookup keeps the tick
		// a straight memcpy, which is the whole point of storing µ-law.
		_gainIsUnity = (db > -0.01f && db < 0.01f);
	}
	_gainDb.store(db, std::memory_order_release);
}

unsigned HoldMusic::listenerCount() const
{
	std::lock_guard<std::mutex> lk(_mutex);
	unsigned n = 0;
	for (const auto& l : _listeners) if (l.used) ++n;
	return n;
}

bool HoldMusic::loadClip(const std::string& path)
{
	std::FILE* f = std::fopen(path.c_str(), "rb");
	if (f == nullptr) return false;

	std::fseek(f, 0, SEEK_END);
	const long total = std::ftell(f);
	std::fseek(f, 0, SEEK_SET);
	if (total <= 0)
	{
		std::fclose(f);
		return false;
	}

	// Read the header region first so a wrong-format file is rejected WITHOUT
	// allocating megabytes for it. 1 KB comfortably covers RIFF + fmt + fact +
	// any LIST/INFO a converter added.
	uint8_t head[1024];
	const size_t headLen = std::fread(head, 1, sizeof(head) < static_cast<size_t>(total)
	                                           ? sizeof(head) : static_cast<size_t>(total), f);
	size_t dataOff = 0, dataLen = 0;
	if (!parseUlawWav(head, headLen, dataOff, dataLen))
	{
		std::fclose(f);
		return false;
	}
	if (dataOff + dataLen > static_cast<size_t>(total)) dataLen = static_cast<size_t>(total) - dataOff;

	// ── HEAP ALLOCATION, AND WHY IT IS ALLOWED HERE ──────────────────────────
	// The engine invariant is "no dynamic allocation in RTOS tasks after init":
	// pools and static buffers only, because heap churn on a long-running node
	// fragments and then fails at the worst moment. This allocation is a
	// deliberate, narrow exception and it is worth being explicit about:
	//
	//   * It is NOT on any media or packet path. The pacing task allocates
	//     nothing, ever — it writes into a fixed stack buffer and memcpys from
	//     an already-resident clip.
	//   * It is one-shot and bounded: a single block, capped at 8 MB by the
	//     upload route, replacing any previous one rather than accumulating.
	//   * It runs on the boot task or the HTTP task, never on the SIP or RTP
	//     tasks, so a failure or a slow allocation cannot stall call handling.
	//   * The alternative — a fixed static buffer — would have to be sized for
	//     the largest clip anyone might ever upload, permanently, on a device
	//     where most users load none at all.
	//
	// PSRAM by preference: the clip is large, long-lived and only ever read
	// sequentially, which is exactly what PSRAM is good at. Internal RAM is scarce
	// and needed for task stacks and the SIP pools.
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	uint8_t* buf = static_cast<uint8_t*>(heap_caps_malloc(dataLen, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
	if (buf == nullptr) buf = static_cast<uint8_t*>(heap_caps_malloc(dataLen, MALLOC_CAP_8BIT));
#else
	uint8_t* buf = static_cast<uint8_t*>(std::malloc(dataLen));
#endif
	if (buf == nullptr)
	{
		std::fclose(f);
		return false;
	}

	std::fseek(f, static_cast<long>(dataOff), SEEK_SET);
	const size_t got = std::fread(buf, 1, dataLen, f);
	std::fclose(f);

	if (got < BYTES_PER_TICK)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		heap_caps_free(buf);
#else
		std::free(buf);
#endif
		return false;
	}

	{
		std::lock_guard<std::mutex> lk(_mutex);
		freeClipLocked();          // replace: the old clip's listeners keep playing the new one
		_clip = buf;
		_cursor = 0;
		_clipBytes.store(got, std::memory_order_release);
	}

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	ESP_LOGI(TAG, "clip loaded: %s (%u bytes, %u s)", path.c_str(),
		static_cast<unsigned>(got), static_cast<unsigned>(got / SAMPLE_RATE_HZ));
#endif
	return true;
}

int HoldMusic::addListener(const std::string& destIp, uint16_t destPort)
{
	if (!_running.load(std::memory_order_acquire)) return -1;
	if (destPort == 0 || destIp.empty()) return -1;

	std::lock_guard<std::mutex> lk(_mutex);
	for (size_t i = 0; i < kMaxListeners; ++i)
	{
		if (_listeners[i].used) continue;

		Listener& l = _listeners[i];
		l.used = true;
		l.seq  = 0;
		l.timestamp = 0;
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		l.ssrc = esp_random();
#else
		l.ssrc = 0x5A5A0000u | static_cast<uint32_t>(i);
#endif
		std::memset(&l.dest, 0, sizeof(l.dest));
		l.dest.sin_family = AF_INET;
		l.dest.sin_port   = htons(destPort);
		l.dest.sin_addr.s_addr = inet_addr(destIp.c_str());
		return static_cast<int>(i);
	}
	return -1;   // every orbit already listening
}

void HoldMusic::removeListener(int id)
{
	if (id < 0 || static_cast<size_t>(id) >= kMaxListeners) return;
	std::lock_guard<std::mutex> lk(_mutex);
	_listeners[id].used = false;
}

int HoldMusic::addTap(TapFn fn, void* ctx)
{
	if (!_running.load(std::memory_order_acquire)) return -1;
	if (fn == nullptr) return -1;

	std::lock_guard<std::mutex> lk(_mutex);
	for (size_t i = 0; i < POCKETDIAL_MAX_ANCHOR_CALLS; ++i)
	{
		if (_taps[i].used) continue;
		_taps[i].used = true;
		_taps[i].fn   = fn;
		_taps[i].ctx  = ctx;
		return static_cast<int>(i);
	}
	return -1;   // every anchor call already tapped in
}

void HoldMusic::removeTap(int id)
{
	if (id < 0 || static_cast<size_t>(id) >= POCKETDIAL_MAX_ANCHOR_CALLS) return;
	std::lock_guard<std::mutex> lk(_mutex);
	_taps[id].used = false;
	_taps[id].fn   = nullptr;
	_taps[id].ctx  = nullptr;
}

// Platform-independent (no socket, no task) so both runLoop() (ESP) and
// deliverTickForTest() (host) can call it. Caller holds _mutex.
bool HoldMusic::tickLocked(uint8_t out[BYTES_PER_TICK])
{
	const size_t clipLen = _clipBytes.load(std::memory_order_acquire);
	if (_clip == nullptr || clipLen == 0) return false;

	// The clip wraps mid-frame, so a tick can straddle the loop point. Copy in
	// two pieces rather than clamping, or every loop would emit a short frame.
	const size_t first = (_cursor + BYTES_PER_TICK <= clipLen)
		? BYTES_PER_TICK : (clipLen - _cursor);
	std::memcpy(out, _clip + _cursor, first);
	if (first < BYTES_PER_TICK)
	{
		std::memcpy(out + first, _clip, BYTES_PER_TICK - first);
	}

	if (!_gainIsUnity)
	{
		for (size_t i = 0; i < BYTES_PER_TICK; ++i) out[i] = _gainTable[out[i]];
	}

	// Issue #218: the same gain-adjusted tick bytes, handed to anything
	// tapped in (a held MediaBridge) instead of sent over a socket. Same
	// instant as every RTP listener the caller may fan this out to next --
	// one cursor, one hand-out.
	for (auto& t : _taps)
	{
		if (!t.used) continue;
		t.fn(t.ctx, out, BYTES_PER_TICK);
	}

	_cursor = advanceCursor(_cursor, clipLen);
	return true;
}

void HoldMusic::deliverTickForTest()
{
	std::lock_guard<std::mutex> lk(_mutex);
	uint8_t scratch[BYTES_PER_TICK];
	tickLocked(scratch);   // return value not needed -- taps already fired
}

// ─────────────────────────────────────────────────────────────────────────────
//  ESP-only: UDP socket + 20 ms pacing task
// ─────────────────────────────────────────────────────────────────────────────
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)

bool HoldMusic::start()
{
	if (_running.load(std::memory_order_acquire)) return true;
	if (!isLoaded()) return false;      // never advertise a port that will stay silent

	_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (_sock < 0) return false;

	sockaddr_in bindAddr{};
	bindAddr.sin_family = AF_INET;
	bindAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	bindAddr.sin_port = 0;             // ephemeral: read it back for the SDP answer
	if (bind(_sock, reinterpret_cast<sockaddr*>(&bindAddr), sizeof(bindAddr)) < 0)
	{
		close(_sock);
		_sock = -1;
		return false;
	}
	socklen_t alen = sizeof(bindAddr);
	if (getsockname(_sock, reinterpret_cast<sockaddr*>(&bindAddr), &alen) == 0)
	{
		_localPort.store(ntohs(bindAddr.sin_port), std::memory_order_release);
	}

	_stopRequested.store(false, std::memory_order_release);
	_running.store(true, std::memory_order_release);

	// Core 0 alongside the other media tasks, priority just under them: hold music
	// glitching is cosmetic where a live call's RTP is not, so it must never win a
	// scheduling contest against an active bridge.
	if (xTaskCreatePinnedToCore(&HoldMusic::taskTrampoline, "moh_tx", kTaskStackBytes,
	                            this, 5, nullptr, 0) != pdPASS)
	{
		_running.store(false, std::memory_order_release);
		close(_sock);
		_sock = -1;
		return false;
	}
	ESP_LOGI(TAG, "started on UDP port %d", localPort());
	return true;
}

void HoldMusic::stop()
{
	if (!_running.load(std::memory_order_acquire)) return;
	_stopRequested.store(true, std::memory_order_release);
	for (int i = 0; i < 100 && _taskRunning.load(std::memory_order_acquire); ++i)
	{
		vTaskDelay(pdMS_TO_TICKS(5));
	}
	if (_sock >= 0) { close(_sock); _sock = -1; }
	_running.store(false, std::memory_order_release);
	_localPort.store(0, std::memory_order_release);
}

void HoldMusic::taskTrampoline(void* arg)
{
	static_cast<HoldMusic*>(arg)->runLoop();
	vTaskDelete(nullptr);
}

void HoldMusic::runLoop()
{
	_taskRunning.store(true, std::memory_order_release);

	uint8_t packet[RTP_HEADER_BYTES + BYTES_PER_TICK];
	TickType_t next = xTaskGetTickCount();

	while (!_stopRequested.load(std::memory_order_acquire))
	{
		// vTaskDelayUntil, not vTaskDelay: the latter drifts by however long the
		// send took, and a drifting 20 ms tick is a slowly-accumulating gap the far
		// end hears as stuttering.
		vTaskDelayUntil(&next, pdMS_TO_TICKS(PTIME_MS));

		std::lock_guard<std::mutex> lk(_mutex);
		// ── the radio station: ONE read, fanned to everyone ──────────────────
		// tickLocked() reads the cursor, applies gain, invokes any taps
		// (issue #218) and advances the cursor; false means no clip loaded.
		uint8_t* payload = packet + RTP_HEADER_BYTES;
		if (!tickLocked(payload)) continue;

		for (auto& l : _listeners)
		{
			if (!l.used) continue;
			// Marker on the very first packet of a stream (RFC 3550 §5.1): it tells
			// the far end this is the start of a talkspurt so it primes its jitter
			// buffer rather than treating the first frames as late.
			RtpSender::buildRtpHeader(packet, /*marker=*/(l.seq == 0), PAYLOAD_TYPE_PCMU,
				l.seq, l.timestamp, l.ssrc);
			// Check the send. A silently-dropped sendto is exactly the failure that
			// does not reproduce on a bench: the listener hears a gap, the log says
			// nothing, and there is no counter to point at. Rate-limited so a
			// genuinely unreachable peer cannot flood the log at 50 lines/second.
			const int sent = sendto(_sock, packet, sizeof(packet), 0,
				reinterpret_cast<const sockaddr*>(&l.dest), sizeof(l.dest));
			if (sent < 0)
			{
				++_txErrors;
				if ((_txErrors % 250u) == 1u)
				{
					ESP_LOGW(TAG, "sendto failed (errno %d), %u dropped so far",
						errno, static_cast<unsigned>(_txErrors));
				}
			}
			++l.seq;
			l.timestamp += static_cast<uint32_t>(BYTES_PER_TICK);
		}

		// Cursor already advanced inside tickLocked() above.

		// Stack headroom, measured rather than assumed. The task was created with a
		// guessed size; this reports what it actually uses so the number can be set
		// from evidence. Logged once, ~10 s in, when the deepest path (a full
		// listener table) has been exercised.
		if (++_ticks == 500u)
		{
			const UBaseType_t freeWords = uxTaskGetStackHighWaterMark(nullptr);
			ESP_LOGI(TAG, "stack high-water: %u bytes free of %d",
				static_cast<unsigned>(freeWords * sizeof(StackType_t)), kTaskStackBytes);
		}
	}

	_taskRunning.store(false, std::memory_order_release);
}

#else   // ── host build: no socket, no task ───────────────────────────────────

bool HoldMusic::start()
{
	if (!isLoaded()) return false;
	_running.store(true, std::memory_order_release);
	// A fixed non-zero port so the SDP-building paths stay exercisable on the
	// desktop build even though nothing will ever transmit.
	_localPort.store(40100, std::memory_order_release);
	return true;
}

void HoldMusic::stop()
{
	_running.store(false, std::memory_order_release);
	_localPort.store(0, std::memory_order_release);
	std::lock_guard<std::mutex> lk(_mutex);
	for (auto& l : _listeners) l.used = false;
}

#endif

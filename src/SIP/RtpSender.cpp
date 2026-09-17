#include "RtpSender.hpp"

#include <cmath>
#include <cstring>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <unistd.h>
#include <sys/socket.h>
#include "esp_log.h"
#include "esp_random.h"
#include "esp_task_wdt.h"   // Issue #235: rtp_media_tx TWDT subscription
#include "EthAccess.hpp"
#include "ArpLookup.hpp"
#include "DmaFramePool.hpp"
#elif defined(__linux__)
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <chrono>
#include <iostream>
#include <random>
#else
#include <random>   // std::mt19937/random_device on host (SSRC/seq seeding in stubbed start)
#endif

namespace
{
	// Dedicated server media port. Distinct from SIP (5060) and the register-beep /
	// HTTP planes. Fixed (not negotiated) — the single-stream cap means one port is
	// enough, and a fixed port keeps the SDP answer trivial and firewall-predictable.
	constexpr int SERVER_RTP_PORT = 5062;

	// 2π as a double (M_PI is not guaranteed on MSVC without _USE_MATH_DEFINES).
	constexpr double TWO_PI = 6.283185307179586476925286766559;

	// Cross-platform 32-bit random (RTP SSRC / initial seq+timestamp). On ESP we
	// use the hardware RNG. On host/Linux, RFC 3550 §3 wants the SSRC genuinely
	// random (so colliding streams can be told apart) — std::rand() is a single
	// process-wide stream shared and correlated across every caller, which is
	// exactly the property SSRC randomness needs NOT to have. Each thread gets
	// its own std::mt19937, seeded from std::random_device (Issue #108).
#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
	uint32_t rand32()
	{
		thread_local std::mt19937 gen{std::random_device{}()};
		thread_local std::uniform_int_distribution<uint32_t> dist;
		return dist(gen);
	}
#else
	uint32_t rand32()
	{
		return esp_random();
	}
#endif
}

// ── ITU-T G.711 µ-law encode ────────────────────────────────────────────────
// Reference companding: clamp, fold sign, add bias 0x84, find the exponent
// (segment) of the magnitude, take the 4 mantissa bits, then INVERT the byte.
uint8_t RtpSender::linearToUlaw(int16_t pcm)
{
	constexpr int BIAS = 0x84;         // 132
	constexpr int CLIP = 32635;        // 0x7FFF - BIAS

	// Capture and fold the sign; µ-law uses sign-magnitude with the sign in bit 7.
	// Magnitude is computed in `int` (NOT int16_t): negating INT16_MIN (-32768) in a
	// 16-bit type is signed overflow / UB and wraps back to -32768, which silently
	// mis-encodes full-scale negative samples. Widen first, then negate.
	int sign = (pcm >> 8) & 0x80;      // 0x80 for negative samples
	int mag = pcm;
	if (sign != 0)
	{
		mag = -mag;                    // safe: `mag` is a 32-bit int here
	}
	if (mag > CLIP)
	{
		mag = CLIP;
	}
	mag += BIAS;

	// Exponent: position of the highest set bit above bit 7 (segments 0..7).
	int exponent = 7;
	for (int expMask = 0x4000; (mag & expMask) == 0 && exponent > 0; expMask >>= 1)
	{
		--exponent;
	}

	int mantissa = (mag >> (exponent + 3)) & 0x0F;
	uint8_t ulaw = static_cast<uint8_t>(~(sign | (exponent << 4) | mantissa));
	return ulaw;
}

size_t RtpSender::ulawEncodeBuffer(const int16_t* in, size_t count, uint8_t* out)
{
	if (in == nullptr || out == nullptr || count == 0)
	{
		return 0;
	}
	for (size_t i = 0; i < count; ++i)
	{
		out[i] = linearToUlaw(in[i]);
	}
	return count;
}

// ── Continuous sine-tone synthesis → µ-law ──────────────────────────────────
void RtpSender::synthTone(uint8_t* out, int count, double freqHz,
	double& phase, double amplitude)
{
	if (out == nullptr || count <= 0)
	{
		return;
	}
	if (amplitude < 0.0) amplitude = 0.0;
	if (amplitude > 1.0) amplitude = 1.0;

	const double phaseInc = TWO_PI * freqHz / static_cast<double>(SAMPLE_RATE_HZ);
	for (int i = 0; i < count; ++i)
	{
		double s = std::sin(phase) * amplitude * 32767.0;
		int v = static_cast<int>(s);
		if (v > 32767)  v = 32767;
		if (v < -32768) v = -32768;
		out[i] = linearToUlaw(static_cast<int16_t>(v));

		phase += phaseInc;
		if (phase >= TWO_PI)
		{
			phase -= TWO_PI;   // keep phase bounded → no float drift over a long call
		}
	}
}

// ── RTP header (RFC 3550 §5.1), all multi-byte fields network (big-endian) ──
void RtpSender::buildRtpHeader(uint8_t* out, bool marker, uint8_t pt,
	uint16_t seq, uint32_t timestamp, uint32_t ssrc)
{
	// Byte 0: V(2)=2 P(1)=0 X(1)=0 CC(4)=0  → 0x80
	out[0] = 0x80;
	// Byte 1: M(1) PT(7)
	out[1] = static_cast<uint8_t>((marker ? 0x80 : 0x00) | (pt & 0x7F));
	// Bytes 2-3: sequence number (big-endian)
	out[2] = static_cast<uint8_t>((seq >> 8) & 0xFF);
	out[3] = static_cast<uint8_t>(seq & 0xFF);
	// Bytes 4-7: timestamp (big-endian)
	out[4] = static_cast<uint8_t>((timestamp >> 24) & 0xFF);
	out[5] = static_cast<uint8_t>((timestamp >> 16) & 0xFF);
	out[6] = static_cast<uint8_t>((timestamp >> 8) & 0xFF);
	out[7] = static_cast<uint8_t>(timestamp & 0xFF);
	// Bytes 8-11: SSRC (big-endian)
	out[8]  = static_cast<uint8_t>((ssrc >> 24) & 0xFF);
	out[9]  = static_cast<uint8_t>((ssrc >> 16) & 0xFF);
	out[10] = static_cast<uint8_t>((ssrc >> 8) & 0xFF);
	out[11] = static_cast<uint8_t>(ssrc & 0xFF);
}

RtpSender::RtpSender() : _serverRtpPort(SERVER_RTP_PORT)
{
}

RtpSender::~RtpSender()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// Ask the media task to stop, then BLOCK until it has fully exited before this
	// object's storage is reclaimed (the task captures `this`). This runs off the SIP
	// hot path, so a bounded busy-wait is fine; ~500 ms cap backstops a wedged task.
	_stopRequested.store(true, std::memory_order_release);
	for (int i = 0; i < 100 && _taskRunning.load(std::memory_order_acquire); ++i)
	{
		vTaskDelay(pdMS_TO_TICKS(5));
	}
#else
	// Issue #108: destroying a joinable std::thread calls std::terminate, so a
	// stream must never be left running when this object goes away. stop("")
	// (empty callID matches any active stream, per its own doc comment) covers
	// both non-ESP shapes correctly: on Linux it sets _stopRequested and JOINS
	// _senderThread synchronously (see that stop()'s own comment), so the
	// thread is never outliving this object; on the plain host stub there is no
	// real thread at all, so it just clears the (no-task) active flag. Either
	// way this call is safe to make unconditionally, active stream or not
	// (idempotent on an already-idle sender).
	stop("");
#endif
}

std::string RtpSender::activeCallId() const
{
	std::lock_guard<std::mutex> lock(_slotMutex);
	return _callID;
}

// ─────────────────────────────────────────────────────────────────────────────
//  ESP-only: real UDP socket + 20 ms FreeRTOS pacing task
// ─────────────────────────────────────────────────────────────────────────────
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)

bool RtpSender::start(const std::string& destIp, uint16_t destPort, const std::string& callID, FrameProvider provider)
{
	std::lock_guard<std::mutex> lock(_slotMutex);

	// Single-stream cap: refuse a second concurrent stream. Also refuse while a prior
	// task is still tearing itself down (_taskRunning) — that guarantees the new task
	// never overlaps the old one on the shared socket/slot, which in turn lets the
	// exiting task clear _callID/_active/_sock without a racing start() reusing them.
	// The registrar also gates on isActive() before calling.
	if (_active.load(std::memory_order_acquire) || _taskRunning.load(std::memory_order_acquire))
	{
		return false;
	}

	sockaddr_in dest{};
	dest.sin_family = AF_INET;
	dest.sin_port   = htons(destPort);
	if (inet_pton(AF_INET, destIp.c_str(), &dest.sin_addr) != 1)
	{
		ESP_LOGE("RtpSender", "Bad destination IP '%s'", destIp.c_str());
		return false;
	}

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		ESP_LOGE("RtpSender", "socket() failed");
		return false;
	}

	// Bind the dedicated server media port so the source port is deterministic and
	// matches the SDP we advertised (some UAs symmetric-RTP latch the source port).
	sockaddr_in local{};
	local.sin_family      = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_port        = htons(static_cast<uint16_t>(_serverRtpPort));
	if (bind(sock, reinterpret_cast<sockaddr*>(&local), sizeof(local)) < 0)
	{
		// Non-fatal: an ephemeral source port still delivers media to the caller.
		ESP_LOGW("RtpSender", "bind(%d) failed; using ephemeral source port", _serverRtpPort);
	}

	_sock          = sock;
	_dest          = dest;
	_callID        = callID;
	_provider      = provider;
	_l2Ready       = false;
	_l2ResolveTicks = 0;
	_l2IpIdent     = 0;
	_stopRequested.store(false, std::memory_order_release);
	// Mark running BEFORE the task launches so a stop() racing right behind us can't
	// clear the slot before the task exists. The task clears this LAST, on exit.
	_taskRunning.store(true, std::memory_order_release);
	_active.store(true, std::memory_order_release);

	// Issue #49 sibling: the display build reserves Core 1 for LVGL and runs SIP on
	// Core 0; the media task joins SIP on Core 0 so the heavy LVGL full_refresh blits
	// on Core 1 never steal cycles from the 20 ms RTP cadence. Priority 6 (one above
	// the udp_receiver/SIP task at 5) so pacing is not starved by signaling bursts.
	// Handle is nullptr: the task self-manages its lifecycle via _stopRequested /
	// _taskRunning, so we never store (and race on) a TaskHandle_t.
	BaseType_t ok = xTaskCreatePinnedToCore(
		&RtpSender::taskTrampoline,
		"rtp_media_tx",
		6144,   // headroom for lwIP sendto() + tone synth (4KB was marginal)
		this,
		6,
		nullptr,
		0 /* Core 0 */);

	if (ok != pdPASS)
	{
		ESP_LOGE("RtpSender", "xTaskCreatePinnedToCore failed");
		close(_sock);
		_sock = -1;
		_callID.clear();
		_provider = nullptr;
		_taskRunning.store(false, std::memory_order_release);
		_active.store(false, std::memory_order_release);
		return false;
	}

	ESP_LOGI("RtpSender", "Media stream started -> %s:%u (callID=%s) on port %d",
		destIp.c_str(), static_cast<unsigned>(destPort), callID.c_str(), _serverRtpPort);
	return true;
}

bool RtpSender::stop(const std::string& callID)
{
	std::lock_guard<std::mutex> lock(_slotMutex);
	if (!_active.load(std::memory_order_acquire))
	{
		return false;
	}
	// Only stop the matching dialog (ignore a stale BYE for a prior call). An empty
	// callID is the unconditional teardown used by force paths.
	if (!callID.empty() && callID != _callID)
	{
		return false;
	}

	// NON-BLOCKING: just ask the task to finish its current 20 ms frame and tear
	// itself down (it owns the socket close + slot clear in runLoop()). We deliberately
	// do NOT join here: stop() is called by the registrar while it holds the big
	// handler _mutex, and blocking on the media task's cadence stalled ALL SIP
	// signaling (the old code waited up to 500 ms under _mutex). The slot stays
	// _active until the task actually exits, so the single-stream cap remains correct
	// (a re-dial in the brief teardown window simply gets 486 Busy).
	_stopRequested.store(true, std::memory_order_release);
	ESP_LOGI("RtpSender", "Media stream stop requested");
	return true;
}

void RtpSender::taskTrampoline(void* arg)
{
	auto* self = static_cast<RtpSender*>(arg);
	self->runLoop();   // closes the socket + clears the slot under _slotMutex
	// Clearing _taskRunning is the LAST access to `self`: after this the destructor may
	// observe the task as gone and allow the object to be destroyed.
	self->_taskRunning.store(false, std::memory_order_release);
	vTaskDelete(nullptr);
}

void RtpSender::runLoop()
{
	// Snapshot the immutable per-stream socket + destination ONCE under the lock. They
	// are written only in start() before this task is created and are never mutated for
	// the life of the stream, so working off locals removes the cross-thread read of
	// _sock/_dest the hot loop used to do unlocked every frame.
	int           sock;
	sockaddr_in   dest;
	FrameProvider provider;
	{
		std::lock_guard<std::mutex> lock(_slotMutex);
		sock     = _sock;
		dest     = _dest;
		provider = _provider;
	}

	// Per-stream RTP state. Random start seq/timestamp/SSRC per RFC 3550 §5.1.
	uint16_t seq       = static_cast<uint16_t>(rand32());
	uint32_t timestamp = rand32();
	const uint32_t ssrc = rand32();
	double   phase     = 0.0;
	bool     firstPkt  = true;

	// One fixed packet buffer reused every 20 ms — no per-packet heap.
	uint8_t packet[RtpSender::PACKET_BYTES];

	const TickType_t period = pdMS_TO_TICKS(RtpSender::PTIME_MS);
	TickType_t lastWake = xTaskGetTickCount();

	// Issue #235: subscribe to the Task Watchdog (see ConferenceRoom::runDriver's
	// identical comment for the full reasoning). This task is created and
	// destroyed with every stream (start()/stop()), so it MUST unsubscribe
	// before exiting below -- an unsubscribed-but-still-tracked handle left
	// behind by a clean call teardown would otherwise guarantee a watchdog
	// panic on the next timeout instead of protecting anything.
	esp_err_t wdtErr = esp_task_wdt_add(NULL);
	if (wdtErr != ESP_OK)
	{
		ESP_LOGE("RtpSender", "esp_task_wdt_add failed (%s) -- rtp_media_tx stalls will go undetected",
			esp_err_to_name(wdtErr));
	}

	while (!_stopRequested.load(std::memory_order_acquire))
	{
		buildRtpHeader(packet, /*marker=*/firstPkt, RtpSender::PAYLOAD_TYPE_PCMU,
			seq, timestamp, ssrc);

		bool hasAudio = false;
		if (provider)
		{
			hasAudio = provider(packet + RtpSender::RTP_HEADER_BYTES, RtpSender::SAMPLES_PER_PKT);
		}

		if (!hasAudio)
		{
			if (provider)
			{
				// A provider is attached but had nothing this frame (e.g. an anchor
				// underrun) — silence, not the test tone, so a bridged call doesn't
				// suddenly hear 425 Hz.
				std::memset(packet + RtpSender::RTP_HEADER_BYTES, 0xFF, RtpSender::SAMPLES_PER_PKT);
			}
			else
			{
				// No provider at all: the plain 440 test-tone stream (unchanged behavior).
				synthTone(packet + RtpSender::RTP_HEADER_BYTES, RtpSender::SAMPLES_PER_PKT,
					static_cast<double>(RtpSender::DEFAULT_TONE_HZ), phase);
			}
		}

		bool l2Success = false;
		uint32_t localIp, localGw, localNetmask;

		// L2 TX bypass (Issues #282 / #329)
		if (EthAccess::getLocalIpInfo(localIp, localGw, localNetmask))
		{
			if (!_l2Ready || (++_l2ResolveTicks % 250u) == 0u)
			{
				uint32_t destIpHost = ntohl(dest.sin_addr.s_addr);
				uint32_t nextHopHost = ((destIpHost ^ localIp) & localNetmask) == 0 ? destIpHost : localGw;

				sockaddr_in nextHopAddr{};
				nextHopAddr.sin_family = AF_INET;
				nextHopAddr.sin_addr.s_addr = htonl(nextHopHost);

				auto macOpt = ArpLookup::pdLookupMac(nextHopAddr);
				if (macOpt.has_value())
				{
					_l2Ep.dstMac = *macOpt;
					EthAccess::getLocalMac(_l2Ep.srcMac);
					_l2Ep.srcIp = localIp;
					_l2Ep.dstIp = destIpHost;
					_l2Ep.srcPort = static_cast<uint16_t>(_serverRtpPort);
					_l2Ep.dstPort = ntohs(dest.sin_port);

					l2rtp::buildTemplate(_l2Template.data(), _l2Ep, ssrc);
					_l2Ready = true;
				}
				else
				{
					_l2Ready = false;
				}
			}

			if (_l2Ready)
			{
				auto frame = l2rtp::DmaFramePool::acquire();
				if (frame)
				{
					std::memcpy(frame.data(), _l2Template.data(), l2rtp::kHeaderBytes);
					size_t len = l2rtp::patchTick(frame.data(), firstPkt,
						RtpSender::PAYLOAD_TYPE_PCMU, seq, timestamp,
						packet + RtpSender::RTP_HEADER_BYTES, RtpSender::SAMPLES_PER_PKT,
						_l2IpIdent++);

					if (len > 0 && EthAccess::transmitL2(frame.data(), len))
					{
						l2Success = true;
					}
					else
					{
						_l2Ready = false;
						++_l2TxErrors;
					}
				}
				else
				{
					++_l2TxErrors;
				}
			}
		}

		if (!l2Success && sock >= 0)
		{
			sendto(sock, packet, sizeof(packet), 0,
				reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
		}

		firstPkt   = false;
		++seq;
		timestamp += RtpSender::SAMPLES_PER_PKT;   // 160 per 20 ms frame

		// Fed once per 20 ms frame, far inside the 5 s default TWDT timeout.
		// Harmless no-op if the subscription above failed.
		if (wdtErr == ESP_OK)
		{
			(void)esp_task_wdt_reset();
		}

		// Pace at exactly 20 ms; vTaskDelayUntil compensates for send jitter so the
		// stream does not drift relative to the receiver's playout clock.
		vTaskDelayUntil(&lastWake, period);
	}

	if (wdtErr == ESP_OK)
	{
		(void)esp_task_wdt_delete(NULL);
	}

	// This task OWNS its socket: close the local fd and clear the shared slot so a new
	// stream can start. The start()/_taskRunning guard guarantees no start() has
	// re-pointed _sock/_callID under us, so these member writes are unambiguous; the
	// `_sock == sock` check is belt-and-suspenders.
	{
		std::lock_guard<std::mutex> lock(_slotMutex);
		if (sock >= 0)
		{
			close(sock);
		}
		if (_sock == sock)
		{
			_sock = -1;
		}
		_callID.clear();
		_provider = nullptr;
		_active.store(false, std::memory_order_release);
	}
	ESP_LOGI("RtpSender", "Media stream stopped");
}

#elif defined(__linux__)
// ─────────────────────────────────────────────────────────────────────────────
//  Linux desktop: real UDP socket + 20 ms std::thread pacing (Issue #82)
// ─────────────────────────────────────────────────────────────────────────────

bool RtpSender::start(const std::string& destIp, uint16_t destPort, const std::string& callID, FrameProvider provider)
{
	std::lock_guard<std::mutex> lock(_slotMutex);

	if (_active.load(std::memory_order_acquire))
	{
		return false;
	}

	sockaddr_in dest{};
	dest.sin_family = AF_INET;
	dest.sin_port   = htons(destPort);
	if (inet_pton(AF_INET, destIp.c_str(), &dest.sin_addr) != 1)
	{
		std::cerr << "[RtpSender] Bad destination IP '" << destIp << "'" << '\n';
		return false;
	}

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		std::cerr << "[RtpSender] socket() failed" << '\n';
		return false;
	}

	// Bind the dedicated server media port so the source port is deterministic
	// and matches the SDP we advertised (mirrors the ESP path).
	sockaddr_in local{};
	local.sin_family      = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_port        = htons(static_cast<uint16_t>(_serverRtpPort));
	if (bind(sock, reinterpret_cast<sockaddr*>(&local), sizeof(local)) < 0)
	{
		// Non-fatal: an ephemeral source port still delivers media to the caller.
		std::cerr << "[RtpSender] bind(" << _serverRtpPort
			<< ") failed; using ephemeral source port" << '\n';
	}

	_sock     = sock;
	_dest     = dest;
	_callID   = callID;
	_provider = provider;
	_stopRequested.store(false, std::memory_order_release);
	_active.store(true, std::memory_order_release);

	_senderThread = std::thread(&RtpSender::runLoop, this);
	return true;
}

bool RtpSender::stop(const std::string& callID)
{
	{
		std::lock_guard<std::mutex> lock(_slotMutex);
		if (!_active.load(std::memory_order_acquire))
		{
			return false;
		}
		if (!callID.empty() && callID != _callID)
		{
			return false;
		}
		_stopRequested.store(true, std::memory_order_release);
	}
	// Joined OUTSIDE _slotMutex, unlike the ESP path (which deliberately never
	// blocks, so the SIP _mutex is never held for a task's cadence — see that
	// branch's own comment). std::thread has no equivalent to ESP's external
	// _taskRunning poll to fire-and-forget against, and the desktop build's
	// existing host tests require isActive() to already be false the instant
	// stop() returns (Rtp_test.cpp: SingleStreamCap, and the BYE-then-redial
	// case in EndToEnd440InviteEmitsServerSdpAnswer) — so this joins
	// synchronously instead. That does mean a caller holding RequestsHandler's
	// _mutex across a 440 teardown blocks for up to one pacing tick (20 ms)
	// while runLoop() notices _stopRequested and exits — bounded, and only on
	// the 440 diagnostic-tone path (real calls' RTP is peer-to-peer and never
	// touches RtpSender), not the old ESP bug's unbounded-up-to-500ms stall on
	// the mainline signaling path this was originally fixed for.
	//
	// Cleanup (closing the socket, clearing _sock/_callID/_active) happens at
	// the bottom of runLoop(), under _slotMutex — NOT here, and NOT while this
	// function still holds it, or runLoop()'s own lock_guard there would
	// deadlock against this join().
	if (_senderThread.joinable())
	{
		_senderThread.join();
	}
	return true;
}

void RtpSender::runLoop()
{
	// Snapshot the immutable per-stream socket + destination ONCE under the
	// lock, same reasoning as the ESP path: they're written only in start()
	// before this thread exists and never mutated for the stream's life.
	int           sock;
	sockaddr_in   dest;
	FrameProvider provider;
	{
		std::lock_guard<std::mutex> lock(_slotMutex);
		sock     = _sock;
		dest     = _dest;
		provider = _provider;
	}

	uint16_t seq        = static_cast<uint16_t>(rand32());
	uint32_t timestamp  = rand32();
	const uint32_t ssrc = rand32();
	double   phase      = 0.0;
	bool     firstPkt   = true;

	// One fixed packet buffer reused every 20 ms — no per-packet heap.
	uint8_t packet[RtpSender::PACKET_BYTES];

	const auto period = std::chrono::milliseconds(RtpSender::PTIME_MS);
	auto nextWake = std::chrono::steady_clock::now() + period;

	while (!_stopRequested.load(std::memory_order_acquire))
	{
		buildRtpHeader(packet, /*marker=*/firstPkt, RtpSender::PAYLOAD_TYPE_PCMU,
			seq, timestamp, ssrc);

		bool hasAudio = false;
		if (provider)
		{
			hasAudio = provider(packet + RtpSender::RTP_HEADER_BYTES, RtpSender::SAMPLES_PER_PKT);
		}

		if (!hasAudio)
		{
			if (provider)
			{
				// A provider is attached but had nothing this frame — silence,
				// not the test tone (mirrors the ESP path).
				std::memset(packet + RtpSender::RTP_HEADER_BYTES, 0xFF, RtpSender::SAMPLES_PER_PKT);
			}
			else
			{
				synthTone(packet + RtpSender::RTP_HEADER_BYTES, RtpSender::SAMPLES_PER_PKT,
					static_cast<double>(RtpSender::DEFAULT_TONE_HZ), phase);
			}
		}

		if (sock >= 0)
		{
			sendto(sock, packet, sizeof(packet), 0,
				reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
		}

		firstPkt   = false;
		++seq;
		timestamp += RtpSender::SAMPLES_PER_PKT;

		// Pace at exactly 20 ms; sleep_until (not sleep_for) compensates for
		// send jitter so the stream does not drift relative to the receiver's
		// playout clock — same intent as the ESP path's vTaskDelayUntil.
		std::this_thread::sleep_until(nextWake);
		nextWake += period;
	}

	// This thread owns its socket: close the local fd and clear the shared
	// slot so a new stream can start. stop() has already returned by the time
	// any caller could observe this (it joins before returning), so there is
	// no concurrent start() to race here.
	{
		std::lock_guard<std::mutex> lock(_slotMutex);
		if (sock >= 0)
		{
			close(sock);
		}
		if (_sock == sock)
		{
			_sock = -1;
		}
		_callID.clear();
		_provider = nullptr;
		_active.store(false, std::memory_order_release);
	}
}

#else   // ── Host stubs: keep the SDP-answer / cap logic testable, no real I/O ──

bool RtpSender::start(const std::string& /*destIp*/, uint16_t /*destPort*/, const std::string& callID, FrameProvider provider)
{
	std::lock_guard<std::mutex> lock(_slotMutex);
	if (_active.load(std::memory_order_acquire))
	{
		return false;   // single-stream cap still enforced on host (for tests)
	}
	_callID = callID;
	_provider = provider;
	_active.store(true, std::memory_order_release);
	return true;
}

bool RtpSender::stop(const std::string& callID)
{
	std::lock_guard<std::mutex> lock(_slotMutex);
	if (!_active.load(std::memory_order_acquire))
	{
		return false;
	}
	if (!callID.empty() && callID != _callID)
	{
		return false;
	}
	_callID.clear();
	_provider = nullptr;
	_active.store(false, std::memory_order_release);
	return true;
}

#endif

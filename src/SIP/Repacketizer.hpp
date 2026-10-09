#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

// ── Repacketizer (#170) ──────────────────────────────────────────────────────
// Reframes decoded PCM16 of any input size up to MAX_IN into whole FRAME-sample
// (20 ms @ 8 kHz) frames, carrying the remainder. A 10 ms input (80) makes one
// frame per two inputs; a 30 ms input (240) makes three frames per two inputs.
// A 160-sample input into an empty buffer comes straight back out, so a 20 ms
// leg gains nothing from it (MixBus sends one to the ring directly unless a
// remainder is being carried).
//
// Pure: no heap, no locks, no clock. One fixed array, so it is NOT thread-safe;
// the owner keeps one writer (MixBus: the port's rx task).
//
// Usage: push(), then drain with `while (f = front()) { use f[0..FRAME); pop(); }`.
// front() points into the internal buffer (no copy, no caller stack); it is
// valid until the next push() or pop().
//
// Bound: a drained buffer holds < FRAME samples, so CAP = MAX_IN + FRAME - 1
// always takes one MAX_IN push whole. Overrun therefore means the caller pushed
// more than MAX_IN, or pushed again without draining. Then the OLDEST samples
// are discarded (the newest CAP survive, as PlayoutBuffer::write does) and
// dropped() counts SAMPLES, not events. It never blocks.
class Repacketizer
{
public:
    static constexpr size_t FRAME  = 160;                  // output: 20 ms @ 8 kHz == MixBus::FRAME
    static constexpr size_t MAX_IN = 320;                  // largest loss-free input: 40 ms == MediaBridge::MAX_FRAME_SAMPLES
    static constexpr size_t CAP    = MAX_IN + FRAME - 1;   // 479 samples = 958 B

    // Returns the samples offered (n), or 0 for a null/empty push (nothing changes).
    size_t push(const int16_t* in, size_t n)
    {
        if (in == nullptr || n == 0) return 0;
        const size_t offered = n;
        if (n > CAP)                                       // the input alone overflows: keep its newest CAP
        {
            _dropped += static_cast<uint32_t>(n - CAP);
            in += n - CAP;
            n = CAP;
        }
        if (_n + n > CAP)                                  // make room by discarding the oldest buffered
        {
            const size_t over = _n + n - CAP;              // <= _n, because n <= CAP
            std::memmove(_buf, _buf + over, (_n - over) * sizeof _buf[0]);
            _n -= over;
            _dropped += static_cast<uint32_t>(over);
        }
        std::memcpy(_buf + _n, in, n * sizeof _buf[0]);
        _n += n;
        return offered;
    }

    // The oldest whole frame, or nullptr while fewer than FRAME samples are buffered.
    const int16_t* front() const { return _n >= FRAME ? _buf : nullptr; }

    void pop()
    {
        if (_n < FRAME) return;
        _n -= FRAME;
        std::memmove(_buf, _buf + FRAME, _n * sizeof _buf[0]);
    }

    size_t   size() const    { return _n; }                // samples carried
    bool     empty() const   { return _n == 0; }
    uint32_t dropped() const { return _dropped; }          // samples lost to overrun since reset(); wraps at 2^32

    void reset() { _n = 0; _dropped = 0; }

private:
    int16_t  _buf[CAP] = {};
    size_t   _n = 0;
    uint32_t _dropped = 0;
};

static_assert(Repacketizer::CAP == 479, "CAP is MAX_IN + FRAME - 1");
static_assert(sizeof(Repacketizer) <= 1024, "one Repacketizer per MixBus port: keep it under 1 KB");

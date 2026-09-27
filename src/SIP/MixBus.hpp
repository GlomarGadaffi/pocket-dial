#pragma once
#include <atomic>
#include <cstddef>
#include <cstdint>
#include "PlayoutBuffer.hpp"   // pocket-dial's existing ring (src/SIP/PlayoutBuffer.hpp)

// ── Conference mix bus ───────────────────────────────────────────────────────
// The summing junction. Sits between the decode edge (RtpReceiver / anchor rx)
// and the encode edge (RtpSender / anchor tx). Every active port hears the sum
// of all OTHER ports ("minus-self"). The full mix is held in int32 and clipped
// EXACTLY ONCE, on the way out — the running sum is never saturated.
//
// Lifecycle is a per-port state machine driven lock-free against the mix tick:
//   Free --attach()--> Active --detach()--> Draining --(tick reclaims)--> Free
// The tick is the SOLE owner of ring teardown, so a leg leaving never corrupts
// or silences the others (the same single-active-bridge discipline MediaBridge
// already keeps for one leg, generalized here to N).
class MixBus
{
public:
    static constexpr int FRAME     = 160;  // samples/tick; MUST equal RTP ptime (20 ms @ 8 kHz)
    static constexpr int MAX_PORTS = 8;

    MixBus() = default;

    // Cold path (SIP signaling threads).
    int  attach();                 // -> portId in [0,MAX_PORTS), or -1 if full
    void detach(int port);         // non-blocking; tick reclaims at next boundary

    // Hot path (decode / encode tasks). Per-port jitter-absorbing rings.
    bool inputFrame (int port, const int16_t* pcm, size_t n);  // leg -> bus
    bool outputFrame(int port,       int16_t* pcm, size_t n);  // bus -> leg

    // Master clock. Call from exactly ONE periodic driver, every FRAME samples.
    void tick();

    int activePorts() const;

private:
    enum class State : uint8_t { Free = 0, Active = 1, Draining = 2 };

    struct Port
    {
        std::atomic<State> state{State::Free};
        PlayoutBuffer      in;     // leg -> bus  (the input direction a 1:1 MediaBridge doesn't need)
        PlayoutBuffer      out;    // bus -> leg  (same role as MediaBridge's playout buffer)
    };

    Port    _ports[MAX_PORTS];
    int32_t _mix[FRAME] = {};      // wide accumulator — clipped once, at output

    // tick()'s working set. Members, not locals: 2,880 B on the stack gave tick() a
    // 2,928 B frame on conf_mix_tick's 3,072 B stack, and the first 888 call
    // overflowed it (issue #498). Safe as members because tick() has exactly one
    // caller (the single driver, or tickOnce() in tests). 16-byte aligned for the PIE path.
    alignas(16) int16_t _frame[MAX_PORTS][FRAME] = {};
    alignas(16) int16_t _out[FRAME] = {};
};

// The members above only stay 16-byte aligned if the object holding them is. That
// holds for `new`/make_unique: alignof is 16, above the target's 8-byte
// __STDCPP_DEFAULT_NEW_ALIGNMENT__, so C++17 picks the aligned operator new. A raw
// heap_caps_malloc() of an owner would NOT guarantee it -- ConferenceRoom also
// checks at runtime (issue #498).
static_assert(alignof(MixBus) >= 16, "MixBus's mix scratch must stay 16-byte aligned");

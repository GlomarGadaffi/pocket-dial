#pragma once
#include <atomic>
#include <cstddef>
#include <cstdint>
#include "PoolConfig.hpp"     // POCKETDIAL_CONF_LEGS (#479)
#include "PlayoutBuffer.hpp"  // pocket-dial's existing ring (src/SIP/PlayoutBuffer.hpp)
#include "VadGate.hpp"        // #169

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
    static constexpr int FRAME     = 160;  // samples/tick = the ptime WE send (20 ms @ 8 kHz); a leg
                                           // may send another ptime, its in-ring absorbs it (#170)
    // #479: one port per conference leg. Every port carries two rings, fixed with the
    // room at boot, so unused ports were pure internal DRAM on a no-PSRAM build.
    static constexpr int MAX_PORTS = POCKETDIAL_CONF_LEGS;

    // vadGate (#169): when true, tick() leaves a port out of the mix while its VAD gate
    // (VadGate.hpp) is closed. Default off: the mix is exactly the ungated sum.
    explicit MixBus(bool vadGate = false) : _vadGate(vadGate) {}

    // Cold path (SIP signaling threads).
    int  attach();                 // -> portId in [0,MAX_PORTS), or -1 if full
    void detach(int port);         // non-blocking; tick reclaims at next boundary

    // Rule 5 (e911): an emergency port is never VAD-gated. NO call path sets this today,
    // so Rule 5 holds only because the gate is off in every build; a path that can bring an
    // emergency leg onto the bus must call this right after attach(), before its RTP starts
    // (a closed gate would drop the quiet frames that arrive first). Cleared at reclaim.
    void setEmergency(int port, bool on);

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
        std::atomic<bool>  emergency{false};   // #169: bypasses the VAD gate; written by signaling, read by tick
        uint8_t            hang = 0;           // #169: VAD hangover frames left; tick-only, 0 = gate closed
    };

    const bool _vadGate;
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

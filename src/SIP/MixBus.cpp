#include "MixBus.hpp"
#include "mix_kernels.h"
#include <cstring>

// #170: three independent pins of the same frame size must agree.
static_assert(MixBus::FRAME == MIX_FRAME, "MixBus::FRAME must equal mix_kernels' MIX_FRAME");

// ── Lifecycle (cold path) ───────────────────────────────────────────────────
// Invariant maintained by the tick: a Free slot ALWAYS has empty rings (the tick
// clears them on the Draining->Free transition). So attach() need only flip the
// flag — it never races the tick over ring state.
int MixBus::attach()
{
    for (int p = 0; p < MAX_PORTS; ++p)
    {
        State expected = State::Free;
        if (_ports[p].state.compare_exchange_strong(
                expected, State::Active,
                std::memory_order_acq_rel, std::memory_order_relaxed))
        {
            return p;                       // rings guaranteed empty by prior reclaim
        }
    }
    return -1;                              // bus full
}

void MixBus::detach(int port)
{
    if (port < 0 || port >= MAX_PORTS) return;
    State expected = State::Active;
    // Request teardown only. Reclamation (ring clear + return to Free) is the
    // tick's job, so we never free ring state under a concurrent tick read.
    _ports[port].state.compare_exchange_strong(
        expected, State::Draining,
        std::memory_order_acq_rel, std::memory_order_relaxed);
}

void MixBus::setEmergency(int port, bool on)
{
    if (port < 0 || port >= MAX_PORTS) return;
    _ports[port].emergency.store(on, std::memory_order_relaxed);
}

// ── Media I/O (hot path) ────────────────────────────────────────────────────
bool MixBus::inputFrame(int port, const int16_t* pcm, size_t n)
{
    if (port < 0 || port >= MAX_PORTS || pcm == nullptr) return false;
    if (_ports[port].state.load(std::memory_order_acquire) != State::Active) return false;
    return _ports[port].in.write(pcm, n) > 0;
}

bool MixBus::outputFrame(int port, int16_t* pcm, size_t n)
{
    if (port < 0 || port >= MAX_PORTS || pcm == nullptr) return false;
    if (_ports[port].state.load(std::memory_order_acquire) != State::Active) return false;
    return _ports[port].out.read(pcm, n);   // false on underrun -> caller emits comfort noise
}

// ── The mix tick = master clock ─────────────────────────────────────────────
void MixBus::tick()
{
    // Scratch is _frame/_out (members, issue #498): this runs on conf_mix_tick's 3 KB stack.
    unsigned char present[MAX_PORTS];

    // (1) Snapshot participation for THIS tick; pull one frame per active port;
    //     reclaim any Draining ports in-band (tick is the sole ring-clearer).
    for (int p = 0; p < MAX_PORTS; ++p)
    {
        State s = _ports[p].state.load(std::memory_order_acquire);

        if (s == State::Draining)
        {
            _ports[p].in.clear();
            _ports[p].out.clear();
            _ports[p].hang = 0;
            _ports[p].emergency.store(false, std::memory_order_relaxed);
            _ports[p].state.store(State::Free, std::memory_order_release); // clean + free
            present[p] = 0;
            continue;
        }

        present[p] = (s == State::Active) ? 1 : 0;
        // #170: take a frame only when a WHOLE one is buffered. A leg at another
        // ptime (30 ms PCMU = 240 samples) leaves an 80-sample residue; reading it
        // partially would consume those real samples and then zero the frame
        // below, losing them. Left in the ring, they lead the next tick's frame.
        // The ring only grows between this check and the read (single reader).
        if (present[p] && (_ports[p].in.getLength() < static_cast<size_t>(FRAME) ||
                           !_ports[p].in.read(_frame[p], FRAME)))
            std::memset(_frame[p], 0, sizeof _frame[p]);   // late leg -> silence this tick

        // #169: a gated-out port contributes a ZEROED frame, and stays present. Clearing
        // present[] instead would make mix_minus_self subtract audio mix_accumulate never
        // added, and would skip the out write so the leg underruns into comfort noise.
        // Rule 5: the only exemption is the port's emergency flag, passed as `bypass`.
        if (_vadGate && present[p])
        {
            const pd::vad::Verdict v = pd::vad::step(
                _ports[p].hang, _frame[p], FRAME, pd::vad::kOpenEnergy, pd::vad::kHangoverFrames,
                _ports[p].emergency.load(std::memory_order_relaxed));
            _ports[p].hang = v.hang;
            if (!v.participates) std::memset(_frame[p], 0, sizeof _frame[p]);
        }
    }

    // (2) Full mix in int32 — NEVER saturate here.            [PIE kernel A]
    mix_accumulate(_mix, _frame, present, MAX_PORTS, FRAME);

    // (3) Fan out: each active port hears (mix - self), saturated once. [PIE kernel B]
    for (int p = 0; p < MAX_PORTS; ++p)
    {
        if (!present[p]) continue;
        mix_minus_self(_out, _mix, _frame[p], FRAME);
        _ports[p].out.write(_out, FRAME);
    }
}

int MixBus::activePorts() const
{
    int n = 0;
    for (int p = 0; p < MAX_PORTS; ++p)
        if (_ports[p].state.load(std::memory_order_acquire) == State::Active) ++n;
    return n;
}

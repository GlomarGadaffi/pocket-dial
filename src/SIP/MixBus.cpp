#include "MixBus.hpp"
#include "mix_kernels.h"
#include <cstring>

// #170: three independent pins of the same frame size must agree.
static_assert(MixBus::FRAME == MIX_FRAME, "MixBus::FRAME must equal mix_kernels' MIX_FRAME");
static_assert(Repacketizer::FRAME == static_cast<size_t>(MixBus::FRAME), "the repacketizer emits the bus's frame");

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

// ── Media I/O (hot path) ────────────────────────────────────────────────────
bool MixBus::inputFrame(int port, const int16_t* pcm, size_t n)
{
    if (port < 0 || port >= MAX_PORTS || pcm == nullptr) return false;
    Port& p = _ports[port];
    if (p.state.load(std::memory_order_acquire) != State::Active) return false;

    // #170: a 20 ms leg (every frame exactly FRAME, nothing carried) takes the ring as it always has.
    Repack rs = p.repackState.load(std::memory_order_acquire);
    if (n == static_cast<size_t>(FRAME) && rs == Repack::Idle)
        return p.in.write(pcm, n) > 0;

    // Anything else is reframed to whole FRAMEs first. A FRAME-sized input also lands here while a
    // remainder is carried, so it queues behind it rather than overtaking it.
    if (rs == Repack::ResetRequested)
        p.repack.reset();                    // the port was reused: drop the last leg's remainder
    if (p.repack.push(pcm, n) == 0) return false;
    while (const int16_t* f = p.repack.front())     // straight from the buffer: no stack copy
    {
        p.in.write(f, Repacketizer::FRAME);
        p.repack.pop();
    }
    p.repackDrops.store(p.repack.dropped(), std::memory_order_relaxed);
    // CAS, not store: if the tick asked for a reset meanwhile, that request must survive.
    p.repackState.compare_exchange_strong(
        rs, p.repack.empty() ? Repack::Idle : Repack::Holding,
        std::memory_order_acq_rel, std::memory_order_relaxed);
    return true;
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
            // #170: the repacketizer belongs to the rx task, so the tick only asks. A remainder
            // carried from this leg is dropped by the next inputFrame on this port, before the
            // new leg's first sample goes in; Idle means nothing is carried, so nothing to ask.
            Repack carried = Repack::Holding;
            _ports[p].repackState.compare_exchange_strong(
                carried, Repack::ResetRequested,
                std::memory_order_acq_rel, std::memory_order_relaxed);
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

uint32_t MixBus::repackDropped(int port) const
{
    if (port < 0 || port >= MAX_PORTS) return 0;
    return _ports[port].repackDrops.load(std::memory_order_relaxed);
}

int MixBus::activePorts() const
{
    int n = 0;
    for (int p = 0; p < MAX_PORTS; ++p)
        if (_ports[p].state.load(std::memory_order_acquire) == State::Active) ++n;
    return n;
}

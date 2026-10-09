#pragma once
#include <cstdint>

// ── VAD energy gate for MixBus participation (issue #169) ────────────────────
// Pure and allocation-free: no globals, no I/O; the hangover counter is passed in
// and handed back. MixBus::tick() calls step() once per port per frame to decide
// whether that port joins the mix.
//
// Energy measure: sum of squares over the frame (docs/CONFERENCE_MIXER.md §6c).
// 160 samples at -32768 sum to 171,798,691,840, above 2^32, hence int64.
//
// Hangover: a frame at or above the open energy re-arms `hang` to hangoverFrames.
// Each quiet frame after that still participates while hang > 0 and counts it down,
// so a talker keeps hangoverFrames quiet frames of tail and the next one is gated.
// A closed gate (hang == 0) opens on the first loud frame, with no attack delay.
//
// Rule 5 (e911): `bypass` forces participation, whatever the frame holds. It is the
// only exemption, and MixBus passes the port's emergency flag as it.
namespace pd::vad
{
    // UNMEASURED placeholders, to be replaced by the .244 idle-vs-speaking energy
    // measurement the issue calls for. 160 samples at RMS 64; 10 frames = 200 ms.
    constexpr int64_t kOpenEnergy      = 160LL * 64 * 64;
    constexpr uint8_t kHangoverFrames  = 10;

    inline int64_t energy(const int16_t* pcm, int n)
    {
        int64_t sum = 0;
        for (int i = 0; pcm != nullptr && i < n; ++i)
        {
            const int32_t s = pcm[i];
            sum += s * s;                      // <= 2^30, fits int32
        }
        return sum;
    }

    struct Verdict
    {
        bool    participates = false;
        uint8_t hang         = 0;              // carry into the next frame's step()
    };

    inline Verdict step(uint8_t hang, const int16_t* pcm, int n,
                        int64_t openEnergy, uint8_t hangoverFrames, bool bypass)
    {
        if (bypass)                               return {true, hang};
        if (energy(pcm, n) >= openEnergy)         return {true, hangoverFrames};
        if (hang > 0)                             return {true, static_cast<uint8_t>(hang - 1)};
        return {false, 0};
    }
}

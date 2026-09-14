#!/usr/bin/env python3
"""Generate music-on-hold tracks from the ElevenLabs music API as 8 kHz G.711 u-law.

Usage:
  python tools/gen_moh.py --key-file PATH [--out DIR] [--seconds 60] [--only NAME ...] [--force]

The API returns 16 kHz stereo PCM16. Each track is downmixed to mono, low-passed
and decimated to 8 kHz, given a short loop crossfade (end blends into start), then
written as <name>.ulaw (raw, what the board plays) and <name>.wav (PCM16 for listening).
"""
import argparse, json, os, struct, sys, urllib.request

TRACKS = {
    "moh_piano": "Calm instrumental hold music for a telephone system. Soft solo piano with light "
                 "string pad, gentle steady tempo around 70 bpm, no vocals, no drums, warm and "
                 "unobtrusive, mid-range focused, loops seamlessly.",
    "moh_guitar": "Relaxed instrumental hold music. Fingerpicked acoustic guitar with a soft "
                  "electric piano, easy tempo, no vocals, no percussion, friendly and light, "
                  "loops seamlessly.",
    "moh_jazz": "Smooth instrumental lounge jazz for telephone hold music. Muted trumpet or "
                "vibraphone melody over soft upright bass and brushed snare, slow tempo, no "
                "vocals, mellow and unobtrusive, loops seamlessly.",
    "moh_funk": "Funky, catchy instrumental hold music. Tight funk groove with wah guitar, "
                "slap bass, clavinet and horn stabs, medium tempo around 105 bpm, upbeat and "
                "playful. Occasional vocalizations like 'ooh' and 'ahh' as backing accents, "
                "but no lyrics and no lead vocal. Loops seamlessly.",
}

CROSSFADE = 8000  # samples at 8 kHz = 1 s


def read_key(path):
    for line in open(path, encoding="utf-8"):
        if line.lower().startswith("elevenlabs"):
            return line.split()[1].strip()
    sys.exit("no 'elevenlabs <key>' line in " + path)


def music(key, prompt, seconds):
    url = "https://api.elevenlabs.io/v1/music?output_format=pcm_16000"
    body = json.dumps({"prompt": prompt, "music_length_ms": seconds * 1000}).encode()
    req = urllib.request.Request(url, data=body, headers={"xi-api-key": key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        sys.exit(f"HTTP {e.code}: {e.read()[:300]}")


def to_mono_8k(pcm16k_stereo):
    n = len(pcm16k_stereo) // 2
    s = struct.unpack("<%dh" % n, pcm16k_stereo[:n * 2])
    mono = [(s[i] + s[i + 1]) / 2 for i in range(0, n - 1, 2)]  # 16 kHz mono
    # 9-tap windowed-sinc low-pass at ~3.4 kHz, then take every other sample
    taps = [0.0157, 0.0505, 0.1131, 0.1780, 0.2054, 0.1780, 0.1131, 0.0505, 0.0157]
    h = len(taps) // 2
    out = []
    for i in range(0, len(mono), 2):
        acc = 0.0
        for k, t in enumerate(taps):
            j = i + k - h
            if 0 <= j < len(mono):
                acc += t * mono[j]
        out.append(acc)
    return out


def loop_crossfade(x, n=CROSSFADE):
    """Blend the last n samples into the first n so the track loops without a click."""
    if len(x) < 3 * n:
        return x
    head, body, tail = x[:n], x[n:len(x) - n], x[len(x) - n:]
    mixed = [tail[i] * (1 - i / n) + head[i] * (i / n) for i in range(n)]
    return body + mixed  # loop point is now body[0]; end of mixed flows into it


def normalise(x, peak=0.7):
    m = max(1.0, max(abs(v) for v in x))
    g = peak * 32767 / m
    return [v * g for v in x]


def pcm_to_ulaw(v):
    v = int(max(-32635, min(32635, v)))
    sign = 0x80 if v < 0 else 0
    v = abs(v) + 0x84
    exp = 7
    while exp > 0 and not (v & (0x4000 >> (7 - exp))):
        exp -= 1
    mant = (v >> (exp + 3)) & 0x0F
    return ~(sign | (exp << 4) | mant) & 0xFF


def write_outputs(out, name, x):
    ulaw = bytes(pcm_to_ulaw(v) for v in x)
    open(os.path.join(out, name + ".ulaw"), "wb").write(ulaw)
    pcm = struct.pack("<%dh" % len(x), *[int(max(-32768, min(32767, v))) for v in x])
    with open(os.path.join(out, name + ".wav"), "wb") as f:
        f.write(b"RIFF" + struct.pack("<I", 36 + len(pcm)) + b"WAVE")
        f.write(b"fmt " + struct.pack("<IHHIIHH", 16, 1, 1, 8000, 16000, 2, 16))
        f.write(b"data" + struct.pack("<I", len(pcm)) + pcm)
    return len(ulaw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key-file", required=True)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "..", "assets", "moh"))
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    key = read_key(a.key_file)
    os.makedirs(a.out, exist_ok=True)
    manifest = {}
    for name in a.only or list(TRACKS):
        raw = os.path.join(a.out, name + ".src.pcm")
        if os.path.exists(raw) and not a.force:
            data = open(raw, "rb").read()
        else:
            print(f"{name}: requesting {a.seconds}s ...", flush=True)
            data = music(key, TRACKS[name], a.seconds)
            open(raw, "wb").write(data)
        x = normalise(loop_crossfade(to_mono_8k(data)))
        n = write_outputs(a.out, name, x)
        manifest[name] = {"prompt": TRACKS[name], "bytes": n, "seconds": round(n / 8000, 1)}
        print(f"{name:12s} {n/8000:5.1f}s  {n/1024:.0f} KB")
    json.dump({"format": "ulaw_8000", "loop_crossfade_samples": CROSSFADE, "tracks": manifest},
              open(os.path.join(a.out, "manifest.json"), "w"), indent=2)


if __name__ == "__main__":
    main()

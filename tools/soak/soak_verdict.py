#!/usr/bin/env python3
"""Verdict for the #401 multi-hour hardware soak.

#401's box: "Multi-hour soak on hardware under realistic call load: no panic,
no stuck leg, heap stable (1 Hz /api/status log attached)". This turns that log
into PASS/FAIL per criterion, so the box is ticked on numbers, not on someone
eyeballing 15,000 lines.

Input: the file tools/soak/status_logger.sh writes, one JSON object per line:
    {"t": <unix seconds>, "s": <the /api/status body, or null if the poll failed>}
Every field judged here is on the unauthenticated route, so the logger needs no
credential.

Usage:
    python3 tools/soak/soak_verdict.py soak-status.jsonl [--min-hours 4] [--allow-no-coredump] [--json]
Exit status 0 = PASS, 1 = FAIL. stdlib only.
"""

import argparse
import json
import statistics
import sys


class Config:
    """Thresholds. Defaults are the #401 soak's; tests shrink the durations."""

    def __init__(self):
        self.min_duration_s = 4 * 3600    # "multi-hour": 4 h minimum
        self.warmup_s = 900               # ignore the first 15 min for heap trends
        self.max_missing_frac = 0.01      # failed polls, as a fraction of all polls
        self.max_gap_s = 30.0             # longest stretch with no good sample
        self.max_call_s = 180             # a session older than this is stuck
        self.quiet_tail_s = 60            # load must stop this long before the end
        self.min_idle_samples = 300       # idle samples needed to judge the heap
        self.min_slope_b_per_h = -1024.0  # idle freeHeapInternal trend floor
        self.max_idle_drift_b = 4096      # first vs last idle median, largest drop
        self.min_free_internal = 16384    # minFreeHeapInternal at the end
        self.min_largest_block = 8192     # smallest idle largestFreeBlockInternal
        self.min_stack_hwm = 512          # bytes free, every stackHwm_* field
        # A board with no coredump partition reports coredump.supported:false
        # (#514/#531); no-new-coredump then cannot see a crash, so it fails
        # unless the operator accepts that. no-reboot still catches a panic.
        self.allow_no_coredump = False


def default_config():
    return Config()


def load(path):
    """Returns (samples sorted by t, number of unusable lines)."""
    samples = []
    bad = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                bad += 1
                continue
            if not isinstance(rec, dict):
                bad += 1
                continue
            t = _num(rec.get("t"))
            s = rec.get("s")
            # A 503/429 refusal body is a JSON object too (#537 review): a
            # sample with no uptime is not a status body, so it is a failed poll.
            if t is None or not isinstance(s, dict) or _num(s.get("uptime")) is None:
                bad += 1
                continue
            samples.append((float(t), s))
    samples.sort(key=lambda x: x[0])
    return samples, bad


def _num(v):
    if isinstance(v, bool):
        return None
    return v if isinstance(v, (int, float)) else None


def _duration_s(text):
    """'MM:SS' or 'HH:MM:SS' (the /api/status session format) -> seconds."""
    total = 0
    for part in str(text).split(":"):
        try:
            total = total * 60 + int(part)
        except ValueError:
            return None
    return total


def _slope(points):
    """Least-squares slope of y over t (units of y per second)."""
    n = len(points)
    mt = sum(t for t, _ in points) / n
    my = sum(y for _, y in points) / n
    num = sum((t - mt) * (y - my) for t, y in points)
    den = sum((t - mt) ** 2 for t, _ in points)
    return num / den if den else 0.0


def _busy(s):
    # #539 shape: an unauthenticated poll gets sessionCount instead of the array.
    count = _num(s.get("sessionCount"))
    parked = _num(s.get("parkedCount"))   # #539: the unauthenticated park count
    return (bool(s.get("sessions") or []) or (count is not None and count > 0)
            or bool(s.get("parkedCalls") or []) or (parked is not None and parked > 0))


def evaluate(samples, bad, cfg):
    """Returns [(name, ok, detail)]; every entry must be ok for a PASS."""
    checks = []

    def add(name, ok, detail):
        checks.append((name, bool(ok), detail))

    if not samples:
        add("samples", False, "no parseable samples")
        return checks

    t0 = samples[0][0]
    t1 = samples[-1][0]
    span = t1 - t0
    add("duration", span >= cfg.min_duration_s,
        f"{span / 3600:.2f} h logged (need >= {cfg.min_duration_s / 3600:.2f} h)")

    total = len(samples) + bad
    frac = bad / total
    gaps = [b[0] - a[0] for a, b in zip(samples, samples[1:])]
    max_gap = max(gaps) if gaps else 0.0
    add("sampling", frac <= cfg.max_missing_frac and max_gap <= cfg.max_gap_s,
        f"{bad} of {total} polls failed ({frac:.2%}); longest gap {max_gap:.0f} s")

    # No panic: uptime never goes backwards, and the reset reason never changes.
    reboots = []
    prev = None
    for t, s in samples:
        u = _num(s.get("uptime"))
        if u is None:
            continue
        if prev is not None and u < prev:
            reboots.append(t - t0)
        prev = u
    reasons = sorted({str(s.get("resetReason")) for _, s in samples if s.get("resetReason") is not None})
    detail = f"{len(reboots)} uptime reset(s)"
    if reboots:
        detail += f", first at +{reboots[0]:.0f} s"
    detail += f"; resetReason seen: {reasons}"
    add("no-reboot", not reboots and len(reasons) <= 1, detail)

    cds = [s.get("coredump") for _, s in samples if isinstance(s.get("coredump"), dict)]
    if any(c.get("supported") is False for c in cds):
        detail = ("the board reports coredump supported:false (no coredump partition), "
                  "so this check cannot see a crash; no-reboot still does")
        if not cfg.allow_no_coredump:
            detail += " (pass --allow-no-coredump to accept that)"
        add("no-new-coredump", cfg.allow_no_coredump, detail)
    elif cds:
        first, last = cds[0], cds[-1]
        was_present = first.get("present") is True
        appeared = (not was_present) and any(c.get("present") is True for c in cds)
        changed = was_present and any(c.get("size") != first.get("size") for c in cds)
        add("no-new-coredump", not appeared and not changed,
            f"start present={first.get('present')} size={first.get('size')}; "
            f"end present={last.get('present')} size={last.get('size')}")
    else:
        add("no-new-coredump", False, "no coredump field in any sample")

    # No stuck leg: no session outlives max_call_s, and the board is quiet at the end.
    longest = 0
    longest_desc = ""
    for t, s in samples:
        for sess in s.get("sessions") or []:
            if not isinstance(sess, dict):
                continue
            d = _duration_s(sess.get("duration", ""))
            if d is not None and d > longest:
                longest = d
                longest_desc = (f"{sess.get('caller')}->{sess.get('callee')} "
                                f"({sess.get('state')}) at +{t - t0:.0f} s")
        # #539 shape: the identity-free age of the oldest session.
        oldest = _num(s.get("oldestSessionSec"))
        if oldest is not None and oldest > longest:
            longest = int(oldest)
            longest_desc = f"oldestSessionSec at +{t - t0:.0f} s"
    detail = f"longest session {longest} s (limit {cfg.max_call_s} s)"
    if longest > cfg.max_call_s:
        detail += f": {longest_desc}"
    add("no-stuck-leg", longest <= cfg.max_call_s, detail)

    tail = [s for t, s in samples if t >= t1 - cfg.quiet_tail_s]
    busy_tail = [s for s in tail if _busy(s)]
    add("quiet-tail", bool(tail) and not busy_tail,
        f"{len(busy_tail)} of {len(tail)} samples in the last {cfg.quiet_tail_s} s "
        f"still show a call or a park (stop the load before stopping the logger)")

    # Heap stable: judged on IDLE samples after warm-up, so call load does not
    # read as a leak.
    idle = [(t, s) for t, s in samples if t >= t0 + cfg.warmup_s and not _busy(s)]
    pts = [(t, _num(s.get("freeHeapInternal"))) for t, s in idle]
    pts = [(t, y) for t, y in pts if y is not None]
    if len(pts) < cfg.min_idle_samples:
        add("heap-stable", False,
            f"only {len(pts)} idle samples after warm-up (need {cfg.min_idle_samples}); "
            f"leave idle gaps in the load")
    else:
        slope_h = _slope(pts) * 3600.0
        k = max(5, len(pts) // 20)
        head = statistics.median(y for _, y in pts[:k])
        tail_m = statistics.median(y for _, y in pts[-k:])
        drop = head - tail_m
        add("heap-stable", slope_h >= cfg.min_slope_b_per_h and drop <= cfg.max_idle_drift_b,
            f"idle freeHeapInternal trend {slope_h:+.0f} B/h (floor {cfg.min_slope_b_per_h:+.0f}); "
            f"first vs last idle median {head:.0f} -> {tail_m:.0f} "
            f"(drop {drop:.0f} B, limit {cfg.max_idle_drift_b})")

    mins = [_num(s.get("minFreeHeapInternal")) for _, s in samples]
    mins = [m for m in mins if m is not None]
    end_min = mins[-1] if mins else None
    add("heap-floor", end_min is not None and end_min >= cfg.min_free_internal,
        f"minFreeHeapInternal at the end {end_min} (floor {cfg.min_free_internal})")

    blocks = [_num(s.get("largestFreeBlockInternal")) for _, s in idle]
    blocks = [b for b in blocks if b is not None]
    add("fragmentation", bool(blocks) and min(blocks) >= cfg.min_largest_block,
        f"smallest idle largestFreeBlockInternal {min(blocks) if blocks else None} "
        f"(floor {cfg.min_largest_block})")

    lows = {}
    for _, s in samples:
        for key, v in s.items():
            if not key.startswith("stackHwm_"):
                continue
            v = _num(v)
            if v is None:
                continue
            lows[key] = v if key not in lows else min(lows[key], v)
    below = {k: v for k, v in lows.items() if v < cfg.min_stack_hwm}
    detail = ("lowest free: " + ", ".join(f"{k[len('stackHwm_'):]}={v}" for k, v in sorted(lows.items()))
              if lows else "no stackHwm_* values")
    add("stack-margin", bool(lows) and not below, f"{detail} (floor {cfg.min_stack_hwm})")

    return checks


def counter_deltas(samples):
    """Informational: how much each counter moved over the run (not judged)."""
    out = {}
    for path in ("packetsProcessed", "packetsDropped", "droppedInvalid", "droppedRate",
                 "l2Tx.poolExhaustions", "mohSockErrors", "mohL2Errors",
                 "httpReadDeadlineDrops", "httpPerSourceRefusals"):
        vals = []
        for _, s in samples:
            v = s
            for part in path.split("."):
                v = v.get(part) if isinstance(v, dict) else None
            v = _num(v)
            if v is not None:
                vals.append(v)
        out[path] = (vals[-1] - vals[0]) if len(vals) >= 2 else None
    return out


def verdict(checks):
    return all(ok for _, ok, _ in checks)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", help="status_logger.sh output (JSON lines)")
    ap.add_argument("--min-hours", type=float, default=4.0)
    ap.add_argument("--warmup-s", type=float, default=900)
    ap.add_argument("--max-call-s", type=int, default=180)
    ap.add_argument("--allow-no-coredump", action="store_true",
                    help="accept a board with no coredump partition (supported:false)")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    args = ap.parse_args(argv)

    cfg = default_config()
    cfg.min_duration_s = args.min_hours * 3600
    cfg.warmup_s = args.warmup_s
    cfg.max_call_s = args.max_call_s
    cfg.allow_no_coredump = args.allow_no_coredump

    samples, bad = load(args.log)
    checks = evaluate(samples, bad, cfg)
    passed = verdict(checks)
    deltas = counter_deltas(samples)
    first = samples[0][1] if samples else {}
    if args.json:
        print(json.dumps({"pass": passed, "version": first.get("version"),
                          "checks": [{"name": n, "ok": ok, "detail": d} for n, ok, d in checks],
                          "counterDeltas": deltas}, indent=1))
    else:
        if first.get("version"):
            print(f"firmware: {first.get('version')}")
        for name, ok, detail in checks:
            print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")
        print("counter deltas (not judged): " +
              ", ".join(f"{k}={v}" for k, v in deltas.items() if v is not None))
        print(f"SOAK VERDICT: {'PASS' if passed else 'FAIL'}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

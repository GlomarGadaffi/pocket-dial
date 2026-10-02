#!/usr/bin/env python3
"""Verdict for the #401 multi-hour hardware soak.

#401's box: "Multi-hour soak on hardware under realistic call load: no panic,
no stuck leg, heap stable (1 Hz /api/status log attached)". This turns that log
into a verdict per criterion, so the box is ticked on numbers, not on someone
eyeballing 15,000 lines.

Three outcomes (#401 item 0.4):
  PASS     every judged check passed.
  FAIL     a check on the BOARD failed: a reboot, a new coredump, a stuck leg, a
           heap trend or floor, missing data, a load below schedule (an idle board
           must not pass), a stack drop vs the previous release, recvErrors, a
           503, a pool-exhausted syslog line, or the idle-quiesce leak gate.
  INVALID  the run cannot judge the board: too short, poll gaps or failed polls,
           a dry-run load report, or a quiesce sample too soon after the last call.
A FAIL outranks INVALID: a run that is both short and rebooted is a FAIL.
Every check reports its value, its limit and its margin (room left before it
fails; negative means it failed by that much).

Input: the file tools/soak/status_logger.sh writes, one JSON object per line:
    {"t": <unix seconds>, "s": <the /api/status body, or null if the poll failed>}
Every field judged here is on the unauthenticated route, so the logger needs no
credential. Optional inputs, each judged only when given:
  --load-report  sip_stress.py --profile's JSON: delivered load vs schedule, and
                 the idle-quiesce gate at its quiesce_check_at
  --baseline     the previous release's `soak_verdict.py --json` output: no task's
                 stack high-water mark may drop by more than 128 B
  --syslog       the board's syslog for the run: no "pool exhausted"/"pool full"

Usage:
    python3 tools/soak/soak_verdict.py soak-status.jsonl [--min-hours 4] [--allow-no-coredump]
        [--load-report load.json] [--baseline prev-verdict.json] [--syslog syslog.txt] [--json]
Exit status 0 = PASS, 1 = FAIL, 3 = INVALID (2 is a usage error). stdlib only.
"""

import argparse
import json
import math
import re
import statistics
import sys

VERDICT_EXIT = {"PASS": 0, "FAIL": 1, "INVALID": 3}
DEFAULT_REGISTRATIONS = 4         # the load's test UAs when neither a flag nor a report says
POOL_LINE = re.compile(r"(?i)\bpool (exhausted|full)\b")
REQUIRED = ("uptime", "resetReason", "freeHeapInternal", "minFreeHeapInternal",
            "largestFreeBlockInternal", "coredump", "recvErrors")
# Counters the idle-quiesce gate wants that /api/status does not export (yet).
# Listed, never judged: the PR that adds them makes the gate judge them.
FIRMWARE_GAPS = (
    "message-pool slots in use (no field; msgPoolRefusals counts refusals, not slots held)",
    "conference legs (getConferenceLegs() is deliberately not exported: it takes the SIP path's lock)",
    "relay/splice entries in use (no field)",
)


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
        self.min_busy_frac = 0.05         # without a load report: an idle board must not pass
        self.max_stack_drop_b = 128       # vs the previous release's lowest free, per task
        self.quiesce_after_s = 200        # the quiesce sample comes this long after the last call
        # Registrations at quiesce, exactly. None: the load report's test UAs (else 4).
        # An explicit value always wins: phones already on the rig count too.
        self.expect_registrations = None
        self.ci_z = 1.96                  # 95 % interval for the heap trend


def default_config():
    return Config()


def load_full(path):
    """Returns (samples sorted by t, number of unusable lines, {HTTP code: count})."""
    samples = []
    bad = 0
    codes = {}
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
                code = _num(rec.get("code"))
                if code is not None:
                    codes[int(code)] = codes.get(int(code), 0) + 1
                continue
            samples.append((float(t), s))
    samples.sort(key=lambda x: x[0])
    return samples, bad, codes


def load(path):
    """Returns (samples sorted by t, number of unusable lines)."""
    samples, bad, _ = load_full(path)
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


def _slope_ci(points, z):
    """(slope, low, high) per second: the OLS slope with a +-z standard-error band.
    The samples are autocorrelated, so the band is optimistic; it is reported, and
    the check itself judges the point estimate as before."""
    n = len(points)
    slope = _slope(points)
    if n < 3:
        return slope, slope, slope
    mt = sum(t for t, _ in points) / n
    my = sum(y for _, y in points) / n
    den = sum((t - mt) ** 2 for t, _ in points)
    if not den:
        return slope, slope, slope
    sse = sum((y - (my + slope * (t - mt))) ** 2 for t, y in points)
    se = math.sqrt(sse / (n - 2) / den)
    return slope, slope - z * se, slope + z * se


def _busy(s):
    # #539 shape: an unauthenticated poll gets sessionCount instead of the array.
    count = _num(s.get("sessionCount"))
    parked = _num(s.get("parkedCount"))   # #539: the unauthenticated park count
    return (bool(s.get("sessions") or []) or (count is not None and count > 0)
            or bool(s.get("parkedCalls") or []) or (parked is not None and parked > 0))


def _count(s, count_key, list_key):
    v = _num(s.get(count_key))
    if v is not None:
        return v
    lst = s.get(list_key)
    return len(lst) if isinstance(lst, list) else None


def _missing(s):
    out = [k for k in REQUIRED if k not in s or s.get(k) is None]
    if "sessions" not in s and "sessionCount" not in s:
        out.append("sessions/sessionCount")
    if not any(k.startswith("stackHwm_") and _num(v) is not None for k, v in s.items()):
        out.append("stackHwm_*")
    return out


def stack_lows(samples):
    lows = {}
    for _, s in samples:
        for key, v in s.items():
            if not key.startswith("stackHwm_"):
                continue
            v = _num(v)
            if v is None:
                continue
            lows[key] = v if key not in lows else min(lows[key], v)
    return lows


def heap_trend(samples, cfg):
    t0 = samples[0][0] if samples else 0
    idle = [(t, s) for t, s in samples if t >= t0 + cfg.warmup_s and not _busy(s)]
    pts = [(t, _num(s.get("freeHeapInternal"))) for t, s in idle]
    return idle, [(t, y) for t, y in pts if y is not None]


def assess(samples, bad, cfg, codes=None, load_report=None, baseline=None, syslog_lines=None):
    """Every check as a dict: name, ok, judged, kind (FAIL or INVALID when it fails),
    detail, value, limit, margin, unit."""
    out = []

    def add(name, ok, detail, kind="FAIL", judged=True, value=None, limit=None, margin=None, unit=None):
        out.append({"name": name, "ok": bool(ok), "judged": judged, "kind": kind, "detail": detail,
                    "value": value, "limit": limit, "margin": margin, "unit": unit})

    def skip(name, why):
        add(name, True, "not judged: " + why, judged=False)

    if not samples:
        add("samples", False, "no parseable samples", kind="INVALID")
        return out

    t0 = samples[0][0]
    t1 = samples[-1][0]
    span = t1 - t0
    add("duration", span >= cfg.min_duration_s,
        f"{span / 3600:.2f} h logged (need >= {cfg.min_duration_s / 3600:.2f} h)", kind="INVALID",
        value=round(span / 3600, 3), limit=round(cfg.min_duration_s / 3600, 3),
        margin=round((span - cfg.min_duration_s) / 3600, 3), unit="h")

    total = len(samples) + bad
    frac = bad / total
    gaps = [b[0] - a[0] for a, b in zip(samples, samples[1:])]
    max_gap = max(gaps) if gaps else 0.0
    add("sampling", frac <= cfg.max_missing_frac and max_gap <= cfg.max_gap_s,
        f"{bad} of {total} polls failed ({frac:.2%}); longest gap {max_gap:.0f} s", kind="INVALID",
        value=max_gap, limit=cfg.max_gap_s, margin=cfg.max_gap_s - max_gap, unit="s")

    lacking = {}
    n_bad = 0
    for _, s in samples:
        miss = _missing(s)
        n_bad += bool(miss)
        for k in miss:
            lacking[k] = lacking.get(k, 0) + 1
    add("data-complete", n_bad == 0,
        f"every one of {len(samples)} samples carries the judged fields" if not n_bad else
        f"{n_bad} of {len(samples)} samples lack: " + ", ".join(f"{k} ({v})" for k, v in sorted(lacking.items())),
        value=n_bad, limit=0, margin=-n_bad, unit="samples")

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
    add("no-reboot", not reboots and len(reasons) <= 1, detail, value=len(reboots), limit=0,
        margin=-len(reboots), unit="resets")

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
    add("no-stuck-leg", longest <= cfg.max_call_s, detail, value=longest, limit=cfg.max_call_s,
        margin=cfg.max_call_s - longest, unit="s")

    tail = [s for t, s in samples if t >= t1 - cfg.quiet_tail_s]
    busy_tail = [s for s in tail if _busy(s)]
    add("quiet-tail", bool(tail) and not busy_tail,
        f"{len(busy_tail)} of {len(tail)} samples in the last {cfg.quiet_tail_s} s "
        f"still show a call or a park (stop the load before stopping the logger)",
        value=len(busy_tail), limit=0, margin=-len(busy_tail), unit="samples")

    # Heap stable: judged on IDLE samples after warm-up, so call load does not
    # read as a leak.
    idle, pts = heap_trend(samples, cfg)
    if len(pts) < cfg.min_idle_samples:
        add("heap-stable", False,
            f"only {len(pts)} idle samples after warm-up (need {cfg.min_idle_samples}); "
            f"leave idle gaps in the load", value=len(pts), limit=cfg.min_idle_samples,
            margin=len(pts) - cfg.min_idle_samples, unit="idle samples")
    else:
        slope, lo, hi = (x * 3600.0 for x in _slope_ci(pts, cfg.ci_z))
        k = max(5, len(pts) // 20)
        head = statistics.median(y for _, y in pts[:k])
        tail_m = statistics.median(y for _, y in pts[-k:])
        drop = head - tail_m
        add("heap-stable", slope >= cfg.min_slope_b_per_h and drop <= cfg.max_idle_drift_b,
            f"idle freeHeapInternal trend {slope:+.0f} B/h (95% CI {lo:+.0f}..{hi:+.0f}, n={len(pts)}; "
            f"floor {cfg.min_slope_b_per_h:+.0f}); first vs last idle median {head:.0f} -> {tail_m:.0f} "
            f"(drop {drop:.0f} B, limit {cfg.max_idle_drift_b}, margin {cfg.max_idle_drift_b - drop:+.0f})",
            value=round(slope, 1), limit=cfg.min_slope_b_per_h, margin=round(slope - cfg.min_slope_b_per_h, 1),
            unit="B/h")

    mins = [_num(s.get("minFreeHeapInternal")) for _, s in samples]
    mins = [m for m in mins if m is not None]
    end_min = mins[-1] if mins else None
    add("heap-floor", end_min is not None and end_min >= cfg.min_free_internal,
        f"minFreeHeapInternal at the end {end_min} (floor {cfg.min_free_internal})",
        value=end_min, limit=cfg.min_free_internal,
        margin=None if end_min is None else end_min - cfg.min_free_internal, unit="B")

    blocks = [_num(s.get("largestFreeBlockInternal")) for _, s in idle]
    blocks = [b for b in blocks if b is not None]
    low_block = min(blocks) if blocks else None
    add("fragmentation", bool(blocks) and low_block >= cfg.min_largest_block,
        f"smallest idle largestFreeBlockInternal {low_block} (floor {cfg.min_largest_block})",
        value=low_block, limit=cfg.min_largest_block,
        margin=None if low_block is None else low_block - cfg.min_largest_block, unit="B")

    lows = stack_lows(samples)
    below = {k: v for k, v in lows.items() if v < cfg.min_stack_hwm}
    detail = ("lowest free: " + ", ".join(f"{k[len('stackHwm_'):]}={v}" for k, v in sorted(lows.items()))
              if lows else "no stackHwm_* values")
    lowest = min(lows.values()) if lows else None
    add("stack-margin", bool(lows) and not below, f"{detail} (floor {cfg.min_stack_hwm})",
        value=lowest, limit=cfg.min_stack_hwm,
        margin=None if lowest is None else lowest - cfg.min_stack_hwm, unit="B")

    prev_lows = (baseline or {}).get("stackLows") if isinstance(baseline, dict) else None
    if not isinstance(prev_lows, dict):
        skip("stack-drop", "no --baseline (the previous release's soak_verdict.py --json)")
    else:
        drops = {k: prev_lows[k] - v for k, v in lows.items() if _num(prev_lows.get(k)) is not None}
        worst = max(drops.values()) if drops else 0
        bad_tasks = {k: d for k, d in drops.items() if d > cfg.max_stack_drop_b}
        add("stack-drop", bool(drops) and not bad_tasks,
            (f"largest drop vs the previous release {worst:+.0f} B (limit {cfg.max_stack_drop_b})" +
             (": " + ", ".join(f"{k[len('stackHwm_'):]} {d:+.0f}" for k, d in sorted(bad_tasks.items()))
              if bad_tasks else "")) if drops else "no task in common with the baseline",
            value=worst, limit=cfg.max_stack_drop_b, margin=cfg.max_stack_drop_b - worst, unit="B")

    rx = [_num(s.get("recvErrors")) for _, s in samples]
    rx = [v for v in rx if v is not None]
    if not rx:
        skip("recv-errors", "no recvErrors values (data-complete fails on that)")
    else:
        delta = rx[-1] - rx[0]
        add("recv-errors", delta == 0, f"recvErrors moved by {delta} over the run (must not move)",
            value=delta, limit=0, margin=-delta, unit="errors")

    if codes is None:
        skip("http-503", "no per-poll HTTP codes (read the log with load_full)")
    else:
        n503 = codes.get(503, 0)
        add("http-503", n503 == 0, f"{n503} poll(s) answered 503 (busy refusal)", value=n503, limit=0,
            margin=-n503, unit="polls")

    if syslog_lines is None:
        skip("pool-exhausted", "no --syslog")
    else:
        hits = [ln.strip() for ln in syslog_lines if POOL_LINE.search(ln)]
        add("pool-exhausted", not hits,
            f"{len(hits)} syslog line(s) say a pool is exhausted or full" + (f", first: {hits[0][:120]}" if hits else ""),
            value=len(hits), limit=0, margin=-len(hits), unit="lines")

    busy_n = sum(1 for _, s in samples if _busy(s))
    if load_report is None:
        frac_busy = busy_n / len(samples)
        add("load-delivered", frac_busy >= cfg.min_busy_frac,
            f"{busy_n} of {len(samples)} samples show a call or a park ({frac_busy:.1%}, need "
            f">= {cfg.min_busy_frac:.0%} without a --load-report): an idle board must not pass",
            value=round(frac_busy, 4), limit=cfg.min_busy_frac, margin=round(frac_busy - cfg.min_busy_frac, 4))
    elif load_report.get("dry_run"):
        add("load-delivered", False, "the --load-report is a dry run: no load was delivered", kind="INVALID")
    else:
        problems = []
        lines = []
        for name, sc in sorted((load_report.get("scenarios") or {}).items()):
            planned, ran, failed = sc.get("planned", 0), sc.get("attempted", 0), sc.get("failed", 0)
            lines.append(f"{name} {ran}/{planned}")
            if ran < planned - 1:
                problems.append(f"{name} ran {ran} of {planned}")
            if failed:
                problems.append(f"{name} {failed} failed")
        regs = load_report.get("registrations") or {}
        if regs.get("failed"):
            problems.append(f"{regs['failed']} REGISTERs failed")
        if not lines:
            problems.append("the report lists no scenarios")
        if busy_n == 0:
            problems.append("no sample shows a call: the load never reached this board")
        add("load-delivered", not problems,
            ("; ".join(problems) if problems else "as planned: " + ", ".join(lines)) +
            f"; {busy_n} busy samples", value=len(problems), limit=0, margin=-len(problems), unit="problems")

    gaps_note = "firmware gaps, not judged: " + "; ".join(FIRMWARE_GAPS)
    q_at = _num((load_report or {}).get("quiesce_check_at"))
    if load_report is None:
        skip("idle-quiesce", "no --load-report (it carries quiesce_check_at)")
    elif q_at is None:
        add("idle-quiesce", False, "the load report has no quiesce_check_at", kind="INVALID")
    else:
        before = [(t, s) for t, s in samples if t <= q_at]
        last_end = _num(load_report.get("last_call_end_at")) or _num(load_report.get("load_end_at"))
        if not before:
            add("idle-quiesce", False, "no sample at or before quiesce_check_at", kind="INVALID")
        else:
            tq, sq = before[-1]
            after = None if last_end is None else tq - last_end
            base = samples[0][1]
            want_regs = cfg.expect_registrations
            if want_regs is None:
                want_regs = len(load_report.get("exts") or []) or DEFAULT_REGISTRATIONS
            if after is not None and after < cfg.quiesce_after_s:
                add("idle-quiesce", False,
                    f"the quiesce sample is {after:.0f} s after the last call (need {cfg.quiesce_after_s} s, "
                    f"past the 180 s session timer)", kind="INVALID", value=round(after),
                    limit=cfg.quiesce_after_s, margin=round(after - cfg.quiesce_after_s), unit="s")
            else:
                diffs, parts = [], []
                for label, ck, lk in (("sessions", "sessionCount", "sessions"),
                                      ("park orbits", "parkedCount", "parkedCalls")):
                    cur, b = _count(sq, ck, lk), _count(base, ck, lk)
                    parts.append(f"{label} {cur} (baseline {b})")
                    if cur is None or b is None or cur != b:
                        diffs.append(label)
                regs = _num(sq.get("clientCount"))
                parts.append(f"registrations {regs} (want exactly {want_regs})")
                if regs != want_regs:
                    diffs.append("registrations")
                add("idle-quiesce", not diffs,
                    f"at +{tq - t0:.0f} s" + (f", {after:.0f} s after the last call" if after is not None else "") +
                    ": " + ", ".join(parts) + (f"; differs: {', '.join(diffs)}" if diffs else "") +
                    "; " + gaps_note, value=len(diffs), limit=0, margin=-len(diffs), unit="fields")
    return out


def evaluate(samples, bad, cfg):
    """Returns [(name, ok, detail)]; every entry must be ok for a PASS. A check that
    is not judged (its input was not given) reads as ok."""
    return [(c["name"], c["ok"], c["detail"]) for c in assess(samples, bad, cfg)]


def overall(results):
    failed = [c for c in results if c["judged"] and not c["ok"]]
    if any(c["kind"] == "FAIL" for c in failed):
        return "FAIL"
    if failed:
        return "INVALID"
    return "PASS"


def counter_deltas(samples):
    """Informational: how much each counter moved over the run (not judged)."""
    out = {}
    for path in ("packetsProcessed", "packetsDropped", "droppedInvalid", "droppedRate",
                 "l2Tx.poolExhaustions", "mohSockErrors", "mohL2Errors",
                 "httpReadDeadlineDrops", "httpPerSourceRefusals", "msgPoolRefusals",
                 "vpeerPoolRefusals", "droppedNoPool"):
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


def _read_json(path):
    with open(path, encoding="utf-8") as f:
        v = json.load(f)
    if not isinstance(v, dict):
        raise ValueError("not a JSON object")
    return v


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", help="status_logger.sh output (JSON lines)")
    ap.add_argument("--min-hours", type=float, default=4.0)
    ap.add_argument("--warmup-s", type=float, default=900)
    ap.add_argument("--max-call-s", type=int, default=180)
    ap.add_argument("--allow-no-coredump", action="store_true",
                    help="accept a board with no coredump partition (supported:false)")
    ap.add_argument("--load-report", default=None, help="sip_stress.py --profile's JSON report")
    ap.add_argument("--baseline", default=None, help="the previous release's --json verdict")
    ap.add_argument("--syslog", default=None, help="the board's syslog for the run")
    ap.add_argument("--expect-registrations", type=int, default=None,
                    help="registrations at quiesce, exactly; always wins over the report "
                         "(default: the report's test UAs, else 4)")
    ap.add_argument("--min-busy-frac", type=float, default=None)
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    args = ap.parse_args(argv)

    cfg = default_config()
    cfg.min_duration_s = args.min_hours * 3600
    cfg.warmup_s = args.warmup_s
    cfg.max_call_s = args.max_call_s
    cfg.allow_no_coredump = args.allow_no_coredump
    if args.expect_registrations is not None:
        cfg.expect_registrations = args.expect_registrations
    if args.min_busy_frac is not None:
        cfg.min_busy_frac = args.min_busy_frac

    try:
        samples, bad, codes = load_full(args.log)
        load_report = _read_json(args.load_report) if args.load_report else None
        baseline = _read_json(args.baseline) if args.baseline else None
        syslog = None
        if args.syslog:
            with open(args.syslog, encoding="utf-8", errors="replace") as f:
                syslog = f.readlines()
    except (OSError, ValueError) as e:
        print(f"SOAK VERDICT: INVALID (cannot read an input: {e})")
        return VERDICT_EXIT["INVALID"]

    results = assess(samples, bad, cfg, codes=codes, load_report=load_report, baseline=baseline,
                     syslog_lines=syslog)
    v = overall(results)
    deltas = counter_deltas(samples)
    first = samples[0][1] if samples else {}
    _, pts = heap_trend(samples, cfg)
    trend = None
    if len(pts) >= 3:
        slope, lo, hi = (x * 3600.0 for x in _slope_ci(pts, cfg.ci_z))
        trend = {"slope_b_per_h": round(slope, 1), "ci95_b_per_h": [round(lo, 1), round(hi, 1)], "n": len(pts)}
    if args.json:
        print(json.dumps({"verdict": v, "pass": v == "PASS", "version": first.get("version"),
                          "checks": results, "counterDeltas": deltas, "stackLows": stack_lows(samples),
                          "heapTrend": trend, "firmwareGaps": list(FIRMWARE_GAPS),
                          "notJudged": [c["name"] for c in results if not c["judged"]]}, indent=1))
    else:
        if first.get("version"):
            print(f"firmware: {first.get('version')}")
        for c in results:
            if not c["judged"]:
                tag = "----"
            elif c["ok"]:
                tag = "PASS"
            else:
                tag = c["kind"]
            margin = ""
            if c["judged"] and c["margin"] is not None:
                margin = f" [margin {c['margin']:+g}{' ' + c['unit'] if c['unit'] else ''}]"
            print(f"{tag:<7} {c['name']}: {c['detail']}{margin}")
        print("counter deltas (not judged): " +
              ", ".join(f"{k}={val}" for k, val in deltas.items() if val is not None))
        print("firmware gaps (not judged): " + "; ".join(FIRMWARE_GAPS))
        print(f"SOAK VERDICT: {v}")
    return VERDICT_EXIT[v]


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""The HTTP-under-load measurement behind the h947_http_load scenario (#947, for #410).

anchor_scenarios.py runs it. This file holds everything that needs no board: the dashboard's poll table, a
nearest-rank percentile, the harness-observed peak concurrency, the run plan and its cap, the raw log and
the summary. tests/tools/test_http_load.py drives each of them on fixed input.

Modes, lightest first, because both watermarks below only ever fall (a heavier run after a lighter one is
the only way to attribute a fall to a run):
  idle            the polls an open dashboard tab makes with nothing expanded: status 2 s, cdr 5 s,
                  admin/status 15 s, ota/status 15 s (index_html.h, the setInterval block)
  dashboard       those, plus the two that need an open panel: trace 1.5 s (Trace toggle on), moh 3 s
                  (PBX settings open)
  dashboard-call  the same, with one held call to the designated far end (no hold, no re-INVITE), in one of
                  two call modes (--call-mode): ringing (the default) is a far end that rings and is not
                  answered, so the window runs for the planned hold and the harness CANCELs as it closes, a
                  valid call only if a 180 Ringing was seen (ringing_call below); answered is a far end that
                  answers, held, then a BYE

One run: a "before" read of /api/status, the pollers, a sequential probe of GET /api/status (the #410 .244
recipe: back to back, one connection at a time), a burst of concurrent GET /api/status, the rest of the
window, an "after" read. The pollers send the admin session (a logged-in dashboard's fetch() does); the probe
and the burst do not (the recipe, and every field read is on the public route).

Read from /api/status, which emits them on main (HttpServer.cpp, sendApiStatus): freeHeapInternal (a
gauge), minFreeHeapInternal and stackHwm_http_conn (since boot, never rise), httpConnWorstRoute,
httpPerSourceRefusals, httpReadDeadlineDrops, httpStatusRefusals, uptime. NOT emitted, so never reported:
a peak or active-connection count (_activeConnections has only activeConnectionsForTest(), a host test
seam), the global 503-busy count (stderr at powers of two), a per-request thread cost. Peak concurrency
here is the harness's own: the most served requests (any answer but 503) in flight at once from this one
address, which the board caps at kMaxConnectionsPerSource.

stdlib only.
"""
import collections
import http.client
import json
import threading
import time

MODES = ("idle", "dashboard", "dashboard-call")
CALL_MODE = "dashboard-call"
CALL_MODES = ("ringing", "answered")
WINDOW_SLACK_MS = 500         # the INVITE leaves a few ms after the window's clock starts: not a short window
STATUS = "/api/status"
STACK_BYTES = 4096            # HttpServer.hpp kHttpConnStackBytes (test_http_load pins it)
PER_SOURCE_CAP = 3            # HttpServer.hpp kMaxConnectionsPerSource (pinned too)
UPTIME_MIN_S = 3600           # #405: a reading right after boot is not evidence
RUN_CAP_MAX = 30              # the #384 approval: no more than 30 calls a run
BURST_WORKERS_MAX = 8         # #368: 12 concurrent requests once starved the W5500's DMA buffers
# index_html.h setInterval(): (path, period s, on in every dashboard). test_http_load pins this table to it.
POLLS = (("/api/status", 2.0, True), ("/api/cdr", 5.0, True), ("/api/admin/status", 15.0, True),
         ("/api/ota/status", 15.0, True), ("/api/trace", 1.5, False), ("/api/moh", 3.0, False))
FIELDS = ("uptime", "freeHeapInternal", "minFreeHeapInternal", "largestFreeBlockInternal",
          "stackHwm_http_conn", "httpConnWorstRoute", "httpPerSourceRefusals", "httpReadDeadlineDrops",
          "httpStatusRefusals")
DEFAULTS = {"modes": MODES, "repeats": 3, "run_cap": 9, "window_s": 60.0, "warm_s": 1.0,
            "probe_polls": 200, "probe_gap_s": 0.0, "burst_workers": 4, "burst_each": 10, "call_mode": "ringing"}


class CapExceeded(Exception):
    pass


def polls_for(mode):
    return [p for p in POLLS if p[2] or mode != "idle"]


# ---------------------------------------------------------------- the plan and its cap
def plan(cfg):
    """[(mode, repeat)] in MODES order: every repeat of a mode before the next, heavier mode."""
    return [(m, r) for m in MODES if m in cfg["modes"] for r in range(1, cfg["repeats"] + 1)]


def run_cap_problems(n_runs, cap):
    if not isinstance(cap, int) or not 1 <= cap <= RUN_CAP_MAX:
        return ["--run-cap must be 1-%d" % RUN_CAP_MAX]
    if n_runs > cap:
        return ["%d runs (modes x repeats) is past --run-cap %d: ring OK is per run with a cap, so raise the cap "
                "on purpose or run fewer" % (n_runs, cap)]
    return []


def config_problems(cfg):
    """Why this configuration may not run, or []. Never echoes a value that is out of range: a far-end
    number pasted into a numeric flag must not come back out."""
    out = []
    modes = cfg["modes"]
    if not modes or any(m not in MODES for m in modes) or len(set(modes)) != len(modes):
        out.append("--http-modes must be a comma list of %s, each once" % ", ".join(MODES))
    repeats_ok = isinstance(cfg["repeats"], int) and 1 <= cfg["repeats"] <= RUN_CAP_MAX
    if not repeats_ok:
        out.append("--repeats must be 1-%d" % RUN_CAP_MAX)
    out += run_cap_problems(len(plan(cfg)) if repeats_ok else 0, cfg["run_cap"])
    if not 1.0 <= cfg["window_s"] <= 3600:
        out.append("--window-s must be 1-3600")
    if not isinstance(cfg["probe_polls"], int) or not 1 <= cfg["probe_polls"] <= 1000:
        out.append("--probe-polls must be 1-1000")
    if not 0 <= cfg["probe_gap_s"] <= 10:
        out.append("--probe-gap-ms must be 0-10000")
    if not isinstance(cfg["burst_workers"], int) or not 1 <= cfg["burst_workers"] <= BURST_WORKERS_MAX:
        out.append("--burst-workers must be 1-%d (the board serves %d per source and refuses the rest with 503)"
                   % (BURST_WORKERS_MAX, PER_SOURCE_CAP))
    if not isinstance(cfg["burst_each"], int) or not 1 <= cfg["burst_each"] <= 1000:
        out.append("--burst-each must be 1-1000")
    if cfg["call_mode"] not in CALL_MODES:
        out.append("--call-mode must be %s" % " or ".join(CALL_MODES))
    return out


class RunBudget:
    """Ring OK is per run, with a cap: take() before every run; the one past the cap raises."""

    def __init__(self, cap):
        self.cap, self.used = cap, 0

    def take(self):
        if self.used >= self.cap:
            raise CapExceeded("run %d is past --run-cap %d: the run stops here" % (self.used + 1, self.cap))
        self.used += 1


# ---------------------------------------------------------------- a ringing-only far end
def ringing_call(m):
    """(kind, text) for a ringing-mode call the far end did not answer, from its run record `m`; kind is "valid",
    "invalid" (the measurement does not count) or "fail" (the far side broke RFC 3261). Valid: a 180 Ringing seen
    before the window closed, the window held for the planned hold_s, then a CANCEL sent at the planned hold (no
    dialog, so no BYE; s9.1) that was answered 200 and ended the INVITE with 487 (s9.2). The 180 is the PBX's own local
    ringback, sent at INVITE time: it does not show the far phone alerting (docs/TEST_HARNESS.md)."""
    ring, win, cancel, hold = m.get("ring_ms"), m.get("window_ms"), m.get("cancel_ms"), m.get("hold_s")
    if ring is None:
        return "invalid", ("no 180 Ringing seen before the INVITE ended (final %s): the far end never rang"
                           % m.get("final"))
    if win is None or hold is None:
        return "invalid", "no window was recorded for the call"
    if ring > win:
        return "invalid", ("the 180 Ringing came at +%d ms, after the window closed at +%d ms" % (ring, win))
    if win < hold * 1000 - WINDOW_SLACK_MS:
        return "invalid", "the window held %.1f s of the planned %g s" % (win / 1000.0, hold)
    if cancel is None:
        return "invalid", ("the INVITE ended %s before the planned hold, with no CANCEL sent (the syslog says "
                           "who ended it)" % m.get("final"))
    if cancel < hold * 1000 - WINDOW_SLACK_MS:
        return "invalid", ("the CANCEL went at +%d ms, before the planned hold of %g s" % (cancel, hold))
    if m.get("cancel_status") != 200:
        return "fail", "the CANCEL was answered %s, not 200 (RFC 3261 s9.2)" % m.get("cancel_status")
    if m.get("final") != 487:
        return "fail", "the INVITE ended %s after the CANCEL, not 487 (RFC 3261 s9.1)" % m.get("final")
    return "valid", ("180 Ringing at +%d ms, window held %.1f s, CANCEL at +%d ms answered 200, INVITE ended 487, "
                     "no BYE" % (ring, win / 1000.0, cancel))


def call_text(m):
    """The summary line's account of a ringing-mode call, or None: any other run says nothing about its call."""
    if m.get("call_mode") != "ringing":
        return None
    if m.get("answered"):
        return "ringing: the far end answered (final %s), held, then BYE" % m.get("final")
    kind, text = ringing_call(m)
    return "ringing: %s, %s" % (kind if kind == "valid" else kind.upper(), text)


# ---------------------------------------------------------------- the two reductions
def nearest_rank(samples, p):
    """Nearest-rank percentile: the smallest sample with at least p% of them at or below it, i.e.
    sorted[ceil(p * n / 100) - 1]. Integer arithmetic, no interpolation (sip_stress.pct interpolates).
    p99 of fewer than 100 samples is the maximum."""
    s = sorted(samples)
    if not s:
        return None
    return s[max(1, -(-p * len(s) // 100)) - 1]


def peak_concurrency(spans):
    """The most (start, end) spans open at once. A span that ends as another starts does not overlap it."""
    events = sorted([(a, 1) for a, _ in spans] + [(b, -1) for _, b in spans])
    cur = peak = 0
    for _, step in events:
        cur += step
        peak = max(peak, cur)
    return peak


# ---------------------------------------------------------------- the traffic
def getter(host, port, timeout=5.0):
    """get(path, cookie) -> (t0, t1, status or None, body, error name or None); t0 before the connect, t1
    after the body. The server answers every request with Connection: close, so each one is a new connection,
    as the dashboard's are."""
    def get(path, cookie=None):
        t0, code, body, err = time.monotonic(), None, b"", None
        try:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            try:
                conn.request("GET", path, headers={"Cookie": "pd_session=" + cookie} if cookie else {})
                resp = conn.getresponse()
                body, code = resp.read(), resp.status
            finally:
                conn.close()
        except (OSError, http.client.HTTPException) as e:
            err = type(e).__name__
        return t0, time.monotonic(), code, body, err
    return get


def status_fields(body):
    """The FIELDS /api/status carried, or None. Only ints, the route label and null are kept."""
    try:
        d = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    return {k: d[k] for k in FIELDS if k in d and (d[k] is None or isinstance(d[k], str)
                                                    or (isinstance(d[k], int) and not isinstance(d[k], bool)))}


class Sink:
    """http-load.jsonl: one JSON object per line, written as it happens (an aborted run keeps its
    evidence). `lines` keeps them for the judge; add() returns the 1-based line number."""

    def __init__(self, path=None):
        self.lines, self.lock = [], threading.Lock()
        self.f = open(path, "a", encoding="utf-8") if path else None

    def add(self, rec):
        line = json.dumps(rec, sort_keys=True)
        with self.lock:
            self.lines.append(line)
            if self.f:
                self.f.write(line + "\n")
                self.f.flush()
            return len(self.lines)

    def close(self):
        if self.f:
            self.f.close()


class RunLoad:
    """One run's traffic. Every request is logged ("req"); every /api/status that answered 200 also logs
    the FIELDS it carried ("status"), labelled with the request's label."""

    def __init__(self, get, sink, run, mode, cookie=None):
        self.get, self.sink, self.run, self.mode, self.cookie = get, sink, run, mode, cookie
        self.base = time.monotonic()
        self.halt = threading.Event()
        self.bursting = threading.Event()        # set while the burst holds the per-source slots
        self.done, self.planned = {}, {}

    def req(self, label, path, authed=False):
        t0, t1, code, body, err = self.get(path, self.cookie if authed else None)
        t = round(t0 - self.base, 4)
        self.sink.add({"k": "req", "run": self.run, "mode": self.mode, "label": label, "path": path, "t": t,
                       "ms": round((t1 - t0) * 1000, 2), "code": code, "bytes": len(body), "err": err})
        if path == STATUS and code == 200:
            fields = status_fields(body)
            if fields is not None:
                self.sink.add(dict(fields, k="status", run=self.run, mode=self.mode, label=label, t=t))

    def safety(self, t0, t1):
        """The harness's own S1 checkpoint (did-mapping + authed status), a served request like any other."""
        self.sink.add({"k": "req", "run": self.run, "mode": self.mode, "label": "safety", "path": "checkpoint",
                       "t": round(t0 - self.base, 4), "ms": round((t1 - t0) * 1000, 2), "code": 200,
                       "bytes": 0, "err": None})

    def _poll(self, path, period):
        nxt = time.monotonic()
        while not self.halt.is_set():
            self.req("poll", path, authed=True)
            nxt += period
            wait = nxt - time.monotonic()
            if wait < 0:                                  # fell behind: stay fixed-rate, do not catch up
                nxt, wait = time.monotonic(), 0
            if self.halt.wait(wait):
                break

    def _probe(self, cfg, until):
        n = 0
        while n < cfg["probe_polls"] and not self.halt.is_set() and time.monotonic() < until:
            self.req("probe", STATUS)
            n += 1
            if cfg["probe_gap_s"]:
                self.halt.wait(cfg["probe_gap_s"])
        self.done["probe"] = n

    def _burst(self, cfg, until):
        workers = cfg["burst_workers"]
        go, counts = threading.Barrier(workers), [0] * workers

        def work(i):
            try:
                go.wait(2.0)
            except threading.BrokenBarrierError:
                pass
            while counts[i] < cfg["burst_each"] and not self.halt.is_set() and time.monotonic() < until:
                self.req("burst", STATUS)
                counts[i] += 1
        ts = [threading.Thread(target=work, args=(i,), daemon=True) for i in range(workers)]
        self.bursting.set()
        try:
            for t in ts:
                t.start()
            for t in ts:
                t.join()
        finally:
            self.bursting.clear()
        self.done["burst"] = sum(counts)

    def _drive(self, cfg, until):
        if not self.halt.wait(cfg["warm_s"]):
            self._probe(cfg, until)
            self._burst(cfg, until)
            self.halt.wait(max(0.0, until - time.monotonic()))

    def window(self, cfg, until, watch=None):
        """before, the pollers, probe then burst, hold to `until` (time.monotonic()), after. `watch`, if
        given, runs every ~0.1 s on the caller's thread (the call mode's phantom and S1 checks); if it
        raises, everything is stopped first."""
        self.planned = {"probe": cfg["probe_polls"], "burst": cfg["burst_workers"] * cfg["burst_each"]}
        self.req("before", STATUS)
        pollers = [threading.Thread(target=self._poll, args=(p, per), daemon=True)
                   for p, per, _ in polls_for(self.mode)]
        driver = threading.Thread(target=self._drive, args=(cfg, until), daemon=True)
        try:
            for t in pollers + [driver]:
                t.start()
            while driver.is_alive():
                if watch:
                    watch()
                driver.join(0.1)
        finally:
            self.halt.set()
            for t in pollers + [driver]:
                t.join(10.0)
        self.req("after", STATUS)

    def meta(self, rep, **extra):
        return dict(extra, k="run", run=self.run, mode=self.mode, rep=rep,
                    probe=[self.done.get("probe", 0), self.planned.get("probe", 0)],
                    burst=[self.done.get("burst", 0), self.planned.get("burst", 0)])


# ---------------------------------------------------------------- reading the log back
def read_log(lines):
    """The JSON objects in `lines`, in order, each with its 1-based line number as "_n". Bad lines are skipped."""
    out = []
    for n, line in enumerate(lines, 1):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if isinstance(d, dict):
            d["_n"] = n
            out.append(d)
    return out


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def per_run(recs):
    runs = collections.OrderedDict()
    for r in recs:
        if _int(r.get("run")) is None:
            continue
        d = runs.setdefault(r["run"], {"run": r["run"], "mode": r.get("mode"), "reqs": [], "status": [], "meta": None})
        k = r.get("k")
        if k == "req":
            d["reqs"].append(r)
        elif k == "status":
            d["status"].append(r)
        elif k == "run":
            d["meta"] = r
    return list(runs.values())


def _block(ms):
    return {"n": len(ms), "p50": nearest_rank(ms, 50), "p99": nearest_rank(ms, 99)}


def run_stats(d):
    reqs, st, meta = d["reqs"], d["status"], d["meta"] or {}
    served = [r for r in reqs if r.get("code") is not None and r["code"] != 503]
    polls = [r for r in reqs if r.get("label") == "poll"]
    free = [v for v in (_int(s.get("freeHeapInternal")) for s in st) if v is not None]

    def edge(label, key):
        return next((_int(s.get(key)) for s in st if s.get("label") == label), None)
    return {"run": d["run"], "mode": d["mode"], "rep": meta.get("rep"), "call": call_text(meta),
            "peak": peak_concurrency([(r["t"], r["t"] + r["ms"] / 1000.0) for r in served]),
            "peak_poll": peak_concurrency([(r["t"], r["t"] + r["ms"] / 1000.0) for r in polls
                                           if r in served]),
            "served": len(served), "refused": sum(1 for r in reqs if r.get("code") == 503),
            "refused_poll": sum(1 for r in polls if r.get("code") == 503),
            "errors": sum(1 for r in reqs if r.get("code") is None),
            "probe": _block([r["ms"] for r in reqs if r.get("label") == "probe" and r.get("code") == 200]),
            "burst": _block([r["ms"] for r in reqs if r.get("label") == "burst" and r.get("code") == 200]),
            "probe_done": (meta.get("probe") or [None, None]), "burst_done": (meta.get("burst") or [None, None]),
            "free_min": min(free) if free else None, "free_max": max(free) if free else None,
            "min_free": (edge("before", "minFreeHeapInternal"), edge("after", "minFreeHeapInternal")),
            "stack": (edge("before", "stackHwm_http_conn"), edge("after", "stackHwm_http_conn")),
            "uptime": (edge("before", "uptime"), edge("after", "uptime")),
            "refusals": (edge("before", "httpPerSourceRefusals"), edge("after", "httpPerSourceRefusals"))}


def judge_log(recs):
    """(fails, invalid) from the log alone. A slow or refused answer is a measurement, not a failure."""
    fails, invalid = [], []
    runs = per_run(recs)
    if not runs:
        return fails, ["no run was recorded"]
    last = None                                      # (run, uptime at its end)
    for d in runs:
        s, tag = run_stats(d), "run %s (%s)" % (d["run"], d["mode"])
        if d["meta"] is None:
            invalid.append("%s has no end record: the harness stopped inside it" % tag)
        u0, u1 = s["uptime"]
        if last is not None and u0 is not None and u0 < last[1]:
            fails.append("%s: uptime fell from %d s (end of run %s) to %d s at its start: the board rebooted between "
                         "runs, so a watermark read across them means nothing" % (tag, last[1], last[0], u0))
        if u1 is not None:
            last = (d["run"], u1)
        if u0 is not None and u1 is not None and u1 < u0:
            fails.append("%s: uptime fell from %d s to %d s: the board rebooted, so both watermarks restarted"
                         % (tag, u0, u1))
        if s["probe"]["n"] == 0:
            invalid.append("%s: no GET /api/status probe was answered 200" % tag)
        m = d["meta"] or {}
        if m.get("call_mode") == "ringing" and not m.get("answered"):
            kind, text = ringing_call(m)
            if kind != "valid":
                (fails if kind == "fail" else invalid).append("%s: ringing call: %s" % (tag, text))
        if d["mode"] in MODES:
            for path, _, _ in polls_for(d["mode"]):
                codes = collections.Counter(r.get("code") for r in d["reqs"]
                                            if r.get("label") == "poll" and r.get("path") == path)
                # only the per-source cap saying 503 is not the handler's fault; any other answer, an error or
                # no request at all means the real handler did not run
                if not codes[200] and (not codes or any(c != 503 for c in codes)):
                    invalid.append("%s: %s was never answered 200 (%s): the dashboard's real handler did not run"
                                   % (tag, path, ", ".join("%s x%d" % kv for kv in sorted(codes.items(), key=str))
                                      or "never asked"))
    return fails, invalid


def _spread(vals, fmt="%d"):
    vals = [v for v in vals if v is not None]
    if not vals:
        return "-"
    lo, hi = min(vals), max(vals)
    return fmt % lo if lo == hi else (fmt + ".." + fmt) % (lo, hi)


def _pct(b, planned):
    if not b["n"]:
        return "n=0/%s" % planned
    return "n=%d/%s p50=%.1f p99=%.1f%s" % (b["n"], planned, b["p50"], b["p99"],
                                           " (p99 = max, n<100)" if b["n"] < 100 else "")


def _tie(rows, key):
    """The smallest non-None value of key over `rows` (status records), earliest line on a tie."""
    best = None
    for r in rows:
        v = _int(r.get(key))
        if v is not None and (best is None or v < _int(best[key])):
            best = r
    return best


def render(recs, log_name="http-load.jsonl"):
    """The summary text: per run, the spread per mode, the stack high-water and the low-water with their source
    lines, and what the board does not emit."""
    runs = per_run(recs)
    stats = [run_stats(d) for d in runs]
    out = ["#947 HTTP server under load: %d run(s), nearest-rank percentiles, latency in ms, concurrency "
           "counted at this client" % len(runs)]
    for mode in MODES:
        mine = [s for s in stats if s["mode"] == mode]
        if not mine:
            continue
        out.append("mode %s: %d run(s)" % (mode, len(mine)))
        for s in mine:
            out.append("  run %s (repeat %s): peak all %d, polls %d | served %d, refused 503 %d (polls %d), errors %d "
                       "| probe %s | burst %s | freeHeapInternal %s..%s | minFreeHeapInternal %s -> %s "
                       "| stackHwm_http_conn %s -> %s"
                       % (s["run"], s["rep"], s["peak"], s["peak_poll"], s["served"], s["refused"],
                          s["refused_poll"], s["errors"],
                          _pct(s["probe"], s["probe_done"][1]), _pct(s["burst"], s["burst_done"][1]),
                          s["free_min"], s["free_max"], s["min_free"][0], s["min_free"][1],
                          s["stack"][0], s["stack"][1]) + (" | call " + s["call"] if s["call"] else ""))
        out.append("  spread over %d run(s): peak all %s, polls %s; probe p50 %s, p99 %s; burst p50 %s, p99 %s; "
                   "freeHeapInternal swing %s" % (
                       len(mine), _spread([s["peak"] for s in mine]), _spread([s["peak_poll"] for s in mine]),
                       _spread([s["probe"]["p50"] for s in mine], "%.1f"),
                       _spread([s["probe"]["p99"] for s in mine], "%.1f"),
                       _spread([s["burst"]["p50"] for s in mine], "%.1f"),
                       _spread([s["burst"]["p99"] for s in mine], "%.1f"),
                       _spread([None if s["free_min"] is None else s["free_max"] - s["free_min"] for s in mine])))
    st = [r for r in recs if r.get("k") == "status"]
    where = lambda r: "%s line %d (run %s, %s, %s read)" % (log_name, r["_n"], r.get("run"), r.get("mode"),
                                                             r.get("label"))
    hwm = _tie(st, "stackHwm_http_conn")
    if hwm is None:
        out.append("stack high-water: not read (stackHwm_http_conn was null or absent in every sample)")
    else:
        free = hwm["stackHwm_http_conn"]
        out.append("stack high-water: stackHwm_http_conn %d B free of %d B (%d B used), httpConnWorstRoute %s; "
                   "source %s" % (free, STACK_BYTES, STACK_BYTES - free,
                                  json.dumps(hwm.get("httpConnWorstRoute")), where(hwm)))
    low = _tie(st, "minFreeHeapInternal")
    if low is None:
        out.append("low-water internal free: not read (minFreeHeapInternal absent in every sample)")
    else:
        first = next(r for r in st if _int(r.get("minFreeHeapInternal")) is not None)
        out.append("low-water internal free: minFreeHeapInternal %d B; source %s; first read %d B, so the runs "
                   "%s" % (low["minFreeHeapInternal"], where(low), first["minFreeHeapInternal"],
                           "took it lower" if low["minFreeHeapInternal"] < first["minFreeHeapInternal"]
                           else "did not take it lower"))
    ups = [_int(r.get("uptime")) for r in st if _int(r.get("uptime")) is not None]
    if ups:
        out.append("uptime at the first read: %d s%s" % (ups[0], "" if ups[0] >= UPTIME_MIN_S else
                   " (under %d s: a reading right after boot is not evidence, #405; re-read after hours of use)"
                   % UPTIME_MIN_S))
    r0 = next((s["refusals"][0] for s in stats if s["refusals"][0] is not None), None)
    r1 = next((s["refusals"][1] for s in reversed(stats) if s["refusals"][1] is not None), None)
    out.append("503s: this client saw %d; the board's httpPerSourceRefusals moved %s (its global-cap refusals "
               "are not emitted)" % (sum(s["refused"] for s in stats),
                                     "by %d" % (r1 - r0) if r0 is not None and r1 is not None else "unreadable"))
    out.append("both watermarks are since boot and only fall: a run shows a low-water only if it went below "
               "every earlier run; the board serves %d connection(s) per source and refuses the rest with 503"
               % PER_SOURCE_CAP)
    out.append("not emitted by the firmware, so not reported: a peak or active-connection count, a per-request "
               "thread cost; a SIP reply time during the burst is not measured here")
    return "\n".join(out)

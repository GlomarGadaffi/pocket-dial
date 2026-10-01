#!/usr/bin/env python3
"""Scheduled load profiles for the #401 release harness (`sip_stress.py --profile`).

A profile is a small declarative table (PROFILES below): how many test UAs,
their REGISTER refresh, and one row per scenario with its hold time, its
interval and its first start. Changing the numbers needs no code change.

The table is turned into a concrete PLAN before anything is sent: a list of
bursts, each with a start time, the scenarios that start together, and the UAs
each one uses. Two rules shape it:

  * Idle gaps. A burst may only start `idle_gap_s` after the previous one ends,
    so soak_verdict.py's heap check has idle samples. A row marked
    "on_collision": "skip" (the 777 echo) drops a slot that falls inside a gap;
    a row marked "defer" starts at the first free moment instead.
  * Capacity. Scenarios that start at the same moment share one burst only if
    their UAs can be disjoint (an extension call's callee must not be busy on
    another call); otherwise the same skip/defer rule applies.

`--dry-run` prints the plan and sends nothing. A real run executes the plan,
writes a JSON report (per scenario: planned, attempted, ok, failed, response
codes, RTP counts) and exits 0 only if nothing failed and every scenario ran
its planned count (within 1).

Safety, all checked before the first packet and each with a unit test:
  * every INVITE target comes from an allowlist: this run's own test
    extensions, 777, 888 and the park orbits; nothing else can be dialled;
  * 911, 933 (anywhere in a number) and 112 are refused outright;
  * 555 (the anchored outside line), URIs and PSTN-shaped numbers are refused;
  * the owner's extensions (--owner-ext or PD_OWNER_EXTS) are refused both as
    targets and as test UAs: registering one would steal that phone's binding;
  * a real run needs a discussion #428 CHECK-OUT link and an expiry that
    covers the whole run (checked offline: nothing is fetched);
  * at run time an extension call is placed only to a test UA whose REGISTER
    got a 200 echoing its own binding, and a park only when /api/status shows
    no parked call (the orbit would otherwise hand us someone's call).

Usage (normally through sip_stress.py):
  python3 tests/load/sip_stress.py --profile rc1 --host <rig-ip> \\
      --exts 6101,6102,6103,6104 --owner-ext <owner extensions> \\
      --checkout-url <#428 comment URL> --checkout-expiry 2026-10-01T22:00Z \\
      [--duration 3600] [--report r.json] [--dry-run]
stdlib only.
"""
import argparse
import copy
import datetime
import hashlib
import heapq
import json
import os
import re
import signal
import sys
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import sip_agent  # noqa: E402

MAX_CALL_S = 170          # soak_verdict.py's no-stuck-leg limit is 180 s
PARK_TIMEOUT_S = 90       # POCKETDIAL_PARK_TIMEOUT_SEC: a park must be retrieved before it
EMERGENCY_SUBSTRINGS = ("911", "933")
EMERGENCY_EXACT = ("112",)
ANCHORED = ("555",)       # the anchored outside line: a real carrier
SERVICE = ("777", "888", "796", "999", "555") + tuple(str(z) for z in range(980, 990))
CHECKOUT_URL_RX = re.compile(
    r"^https://github\.com/GlomarGadaffi/pocket-dial/discussions/428#discussioncomment-[0-9]+$")
END_MARGIN_S = 120        # the CHECK-OUT must outlive the planned end by this much
KINDS = ("echo", "ext", "conf", "park")

PROFILES = {
    "rc1": {
        "about": "#401 rc.1 mix (discussion #451 row S2 a-e); no anchored or trunk calls",
        "duration_s": 3600,
        "quiesce_s": 210,           # after the last burst: registrations only (past the 180 s session timer)
        "idle_gap_s": 30,           # idle between bursts, for the heap verdict
        "setup_margin_s": 3,        # added to a burst's hold time when planning
        "register": {"ua_count": 4, "expires": 120, "refresh_s": 60, "stagger_s": 2},
        "orbits": [700, 709],       # the PBX's park orbits (POCKETDIAL_PARK_SLOTS 10)
        "scenarios": [
            {"name": "echo777", "kind": "echo", "target": "777", "calls": 2, "hold_s": 20,
             "first_s": 20, "every_s": 60, "on_collision": "skip"},
            {"name": "ext_call", "kind": "ext", "hold_s": 60,
             "first_s": 80, "every_s": 300, "on_collision": "defer"},
            {"name": "conf888", "kind": "conf", "target": "888", "legs": 3, "hold_s": 60,
             "first_s": 200, "every_s": 900, "on_collision": "defer"},
            {"name": "park_moh", "kind": "park", "orbit": "709", "parked_s": 20, "retrieved_s": 10,
             "first_s": 560, "every_s": 1200, "on_collision": "defer"},
        ],
    },
}


class Refused(Exception):
    """A safety or validity refusal: nothing was sent."""

    def __init__(self, problems):
        super().__init__("; ".join(problems))
        self.problems = list(problems)


# ---------------------------------------------------------------- table checks
def table_sha256(prof):
    return hashlib.sha256(json.dumps(prof, sort_keys=True).encode("utf-8")).hexdigest()


def ua_need(sc):
    return {"echo": sc.get("calls", 1), "ext": 2, "conf": sc.get("legs", 1), "park": 2}[sc["kind"]]


def busy_s(sc, margin):
    if sc["kind"] == "park":
        return sc["parked_s"] + sc["retrieved_s"] + margin
    return sc["hold_s"] + margin


def scenario_targets(sc):
    if sc["kind"] in ("echo", "conf"):
        return [str(sc["target"])]
    if sc["kind"] == "park":
        return [str(sc["orbit"])]
    return []


def orbit_numbers(prof):
    lo, hi = prof["orbits"]
    return {str(n) for n in range(int(lo), int(hi) + 1)}


def validate_profile(prof):
    problems = []
    reg = prof["register"]
    names = [sc.get("name") for sc in prof["scenarios"]]
    if len(set(names)) != len(names):
        problems.append("scenario names must be unique")
    if not 0 < reg["refresh_s"] < reg["expires"]:
        problems.append("register.refresh_s must be below register.expires")
    for sc in prof["scenarios"]:
        n = sc.get("name")
        if sc.get("kind") not in KINDS:
            problems.append("%s: kind must be one of %s" % (n, ", ".join(KINDS)))
            continue
        if sc.get("every_s", 0) <= 0 or sc.get("first_s", -1) < 0:
            problems.append("%s: every_s must be > 0 and first_s >= 0" % n)
        if sc.get("on_collision") not in ("skip", "defer"):
            problems.append("%s: on_collision must be skip or defer" % n)
        if sc["kind"] == "park":
            if not 0 < sc.get("parked_s", 0) < PARK_TIMEOUT_S - 10:
                problems.append("%s: parked_s must be under %d s (the park timeout is %d s)"
                                % (n, PARK_TIMEOUT_S - 10, PARK_TIMEOUT_S))
            if not 0 < sc.get("parked_s", 0) + sc.get("retrieved_s", 0) <= MAX_CALL_S:
                problems.append("%s: parked_s + retrieved_s must be 1..%d s" % (n, MAX_CALL_S))
        elif not 0 < sc.get("hold_s", 0) <= MAX_CALL_S:
            problems.append("%s: hold_s must be 1..%d s (the soak's stuck-leg limit is 180 s)"
                            % (n, MAX_CALL_S))
        if ua_need(sc) > reg["ua_count"]:
            problems.append("%s: needs %d UAs, the profile has %d" % (n, ua_need(sc), reg["ua_count"]))
    return problems


def number_problems(num, owner, role):
    num = str(num)
    out = []
    digits = re.sub(r"[^0-9]", "", num)
    if any(e in digits for e in EMERGENCY_SUBSTRINGS) or digits in EMERGENCY_EXACT:
        out.append("%s %s is an emergency number (911/933/112): never dialled by a load generator"
                   % (role, num))
    if num in ANCHORED:
        out.append("%s %s is the anchored outside line (a real carrier): refused" % (role, num))
    if not re.fullmatch(r"[0-9]{2,6}", num):
        out.append("%s %r is not a 2-6 digit local number: a URI or a PSTN-shaped number "
                   "could leave the PBX through the trunk" % (role, num))
    if num in owner:
        out.append("%s %s is one of the owner's phones: refused" % (role, num))
    return out


def safety_problems(prof, exts, owner):
    """Every reason this table + these extensions may not run, or []."""
    problems = []
    n = prof["register"]["ua_count"]
    if owner is None:
        problems.append("no owner-phone list: pass --owner-ext <the owner's extensions> "
                        "(or PD_OWNER_EXTS; 'none' asserts there are none) so they can be refused")
        owner = set()
    if len(exts) != n:
        problems.append("--exts must list exactly %d test extensions (got %d); there is no default, "
                        "because a default could be someone's phone" % (n, len(exts)))
    if len(set(exts)) != len(exts):
        problems.append("--exts has duplicates")
    orbits = orbit_numbers(prof)
    for e in exts:
        problems += number_problems(e, owner, "test extension")
        if e in SERVICE or e in orbits:
            problems.append("test extension %s is a PBX service number" % e)
    allow = set(exts) | {"777", "888"} | orbits
    for sc in prof["scenarios"]:
        for t in scenario_targets(sc):
            problems += number_problems(t, owner, "%s target" % sc.get("name"))
            if t not in allow:
                problems.append("%s target %s is not in the allowlist (this run's test extensions, "
                                "777, 888, orbits %s-%s)" % (sc.get("name"), t, *prof["orbits"]))
        if sc.get("kind") == "park" and str(sc.get("orbit")) not in orbits:
            problems.append("%s orbit %s is outside the park orbits" % (sc.get("name"), sc.get("orbit")))
    seen = []
    for p in problems:
        if p not in seen:
            seen.append(p)
    return seen


def parse_owner(arg, env):
    raw = arg if arg is not None else env
    if raw is None or not raw.strip():
        return None
    if raw.strip().lower() == "none":
        return set()
    return {x.strip() for x in raw.split(",") if x.strip()}


def parse_expiry(text):
    s = (text or "").strip()
    if s[-1:] in ("Z", "z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.timestamp()


def checkout_problems(url, expiry, now_wall, needed_s):
    problems = []
    if not url:
        problems.append("no CHECK-OUT: post one on discussion #428 and pass its comment link "
                        "as --checkout-url")
    elif not CHECKOUT_URL_RX.match(url):
        problems.append("--checkout-url is not a discussion #428 comment link")
    if not expiry:
        problems.append("no --checkout-expiry (ISO-8601 with a zone, e.g. 2026-10-01T22:00Z)")
    else:
        ts = parse_expiry(expiry)
        if ts is None:
            problems.append("--checkout-expiry %r is not an ISO-8601 time with a zone" % expiry)
        elif ts <= now_wall:
            problems.append("the CHECK-OUT expired at %s" % expiry)
        elif ts < now_wall + needed_s:
            problems.append("the CHECK-OUT expires at %s, before this run would end (+%d s from now)"
                            % (expiry, needed_s))
    return problems


# ---------------------------------------------------------------- the plan
def make_plan(prof, duration_s, quiesce_s):
    """The table -> concrete bursts and REGISTERs (see the module docstring)."""
    reg = prof["register"]
    n_ua = reg["ua_count"]
    gap = prof["idle_gap_s"]
    margin = prof["setup_margin_s"]
    scs = prof["scenarios"]
    heap = []
    for idx, sc in enumerate(scs):
        k = 0
        t = sc["first_s"]
        while t < duration_s:
            heapq.heappush(heap, (t, 0 if sc["on_collision"] == "defer" else 1, idx, k, t))
            k += 1
            t = sc["first_s"] + k * sc["every_s"]
    bursts, skipped, deferred, dropped = [], [], [], []
    blocked_until = float("-inf")
    cur = None
    while heap:
        t, pri, idx, k, due = heapq.heappop(heap)
        sc = scs[idx]
        need, busy = ua_need(sc), busy_s(sc, margin)
        if t + busy > duration_s:
            dropped.append({"scenario": sc["name"], "occurrence": k, "t": t,
                            "why": "would end after the load window"})
            continue
        if cur is not None and t == cur["t"] and len(cur["_free"]) >= need:
            pass
        elif t >= blocked_until and (cur is None or t != cur["t"]):
            rot = len(bursts) % n_ua
            cur = {"t": t, "end": t, "events": [],
                   "_free": [(rot + j) % n_ua for j in range(n_ua)]}
            bursts.append(cur)
        else:
            if sc["on_collision"] == "skip":
                skipped.append({"scenario": sc["name"], "occurrence": k, "t": t})
            else:
                deferred.append({"scenario": sc["name"], "occurrence": k, "due": due,
                                 "t": blocked_until})
                heapq.heappush(heap, (blocked_until, pri, idx, k, due))
            continue
        uas, cur["_free"] = cur["_free"][:need], cur["_free"][need:]
        cur["events"].append({"scenario": sc["name"], "kind": sc["kind"], "occurrence": k,
                              "due": due, "uas": uas})
        cur["end"] = max(cur["end"], t + busy)
        blocked_until = cur["end"] + gap
    for b in bursts:
        del b["_free"]
    registers = []
    for i in range(n_ua):
        t = i * reg["stagger_s"]
        while t < duration_s + quiesce_s:
            registers.append({"t": t, "ua": i})
            t += reg["refresh_s"]
    registers.sort(key=lambda r: (r["t"], r["ua"]))
    counts = {sc["name"]: 0 for sc in scs}
    for b in bursts:
        for ev in b["events"]:
            counts[ev["scenario"]] += 1
    busy_total = sum(b["end"] - b["t"] for b in bursts)
    return {"duration_s": duration_s, "quiesce_s": quiesce_s, "bursts": bursts,
            "skipped": skipped, "deferred": deferred, "dropped": dropped,
            "registers": registers, "counts": counts,
            "idle_fraction": round(1.0 - busy_total / duration_s, 3) if duration_s else 0.0}


def plan_problems(plan):
    missing = [n for n, c in plan["counts"].items() if c < 1]
    if missing:
        return ["a %d s load never runs %s: lengthen --duration or move first_s, an idle "
                "board must not pass" % (plan["duration_s"], ", ".join(missing))]
    return []


def format_plan(prof, plan, exts):
    def hms(t):
        return "+%d:%02d:%02d" % (t // 3600, (t % 3600) // 60, t % 60)
    out = []
    for b in plan["bursts"]:
        evs = ", ".join("%s#%d (%s)" % (ev["scenario"], ev["occurrence"],
                                         ",".join(exts[i] if i < len(exts) else "U%d" % i
                                                  for i in ev["uas"]))
                        for ev in b["events"])
        out.append("  %s  busy until %s  %s" % (hms(b["t"]), hms(b["end"]), evs))
    for s in plan["skipped"]:
        out.append("  skipped  %s#%d at %s (inside an idle gap or no free UA)"
                   % (s["scenario"], s["occurrence"], hms(s["t"])))
    for d in plan["deferred"]:
        out.append("  deferred %s#%d from %s to %s" % (d["scenario"], d["occurrence"],
                                                      hms(d["due"]), hms(d["t"])))
    for d in plan["dropped"]:
        out.append("  dropped  %s#%d at %s (%s)" % (d["scenario"], d["occurrence"],
                                                    hms(d["t"]), d["why"]))
    return out


# ---------------------------------------------------------------- clocks
class RealClock:
    is_fake = False

    def __init__(self):
        self.stop = threading.Event()

    def now(self):
        return time.monotonic()

    def wall(self):
        return time.time()

    def wait_until(self, t):
        while not self.stop.is_set():
            d = t - self.now()
            if d <= 0:
                return True
            self.stop.wait(min(d, 1.0))
        return False

    def hold(self, s):
        return not self.stop.wait(s)


class FakeClock:
    """Virtual time for tests: waits and holds return at once, SIP still runs for real."""
    is_fake = True

    def __init__(self, start_wall=1_800_000_000.0):
        self.t = 0.0
        self.base = start_wall
        self.stop = threading.Event()
        self._lock = threading.Lock()

    def now(self):
        return self.t

    def wall(self):
        return self.base + self.t

    def wait_until(self, t):
        if self.stop.is_set():
            return False
        with self._lock:
            self.t = max(self.t, t)
        return True

    def hold(self, s):
        return not self.stop.is_set()


# ---------------------------------------------------------------- the report
class Report:
    def __init__(self, meta, plan):
        self._lock = threading.Lock()
        self.data = dict(meta)
        self.data["plan_counts"] = dict(plan["counts"])
        self.data["scenarios"] = {n: {"planned": c, "attempted": 0, "ok": 0, "failed": 0,
                                      "codes": {}, "failures": [], "rtp_tx": 0, "rtp_rx": 0,
                                      "notes": {}}
                                  for n, c in plan["counts"].items()}
        self.data["registrations"] = {"planned": len(plan["registers"]), "attempted": 0,
                                      "ok": 0, "failed": 0, "codes": {}, "deregistered": 0}
        self.data["interrupted"] = False
        self.data["last_call_end_at"] = None

    def code(self, name, method, status):
        key = "%s/%s" % (method, status if status is not None else "timeout")
        with self._lock:
            c = self.data["scenarios"][name]["codes"]
            c[key] = c.get(key, 0) + 1

    def attempt(self, name):
        with self._lock:
            self.data["scenarios"][name]["attempted"] += 1

    def result(self, name, occurrence, t_rel, errors, end_wall):
        with self._lock:
            s = self.data["scenarios"][name]
            if errors:
                s["failed"] += 1
                s["failures"].append({"occurrence": occurrence, "t": t_rel, "errors": errors})
            else:
                s["ok"] += 1
            last = self.data["last_call_end_at"]
            self.data["last_call_end_at"] = end_wall if last is None else max(last, end_wall)

    def rtp(self, name, tx, rx):
        with self._lock:
            self.data["scenarios"][name]["rtp_tx"] += tx
            self.data["scenarios"][name]["rtp_rx"] += rx

    def note(self, name, key, value):
        with self._lock:
            notes = self.data["scenarios"][name]["notes"]
            notes[key] = notes.get(key, 0) + value

    def registration(self, status, registered):
        key = "REGISTER/%s" % (status if status is not None else "timeout")
        with self._lock:
            r = self.data["registrations"]
            r["attempted"] += 1
            r["codes"][key] = r["codes"].get(key, 0) + 1
            if status == 200 and registered:
                r["ok"] += 1
            else:
                r["failed"] += 1

    def finish(self):
        problems = []
        for name, s in self.data["scenarios"].items():
            if s["failed"]:
                problems.append("%s: %d of %d failed" % (name, s["failed"], s["attempted"]))
            if abs(s["attempted"] - s["planned"]) > 1:
                problems.append("%s: ran %d, planned %d" % (name, s["attempted"], s["planned"]))
        r = self.data["registrations"]
        if r["failed"]:
            problems.append("registrations: %d of %d failed" % (r["failed"], r["attempted"]))
        if self.data["interrupted"]:
            problems.append("interrupted before the plan finished")
        self.data["problems"] = problems
        self.data["pass"] = not problems
        return self.data["pass"]


# ---------------------------------------------------------------- scenarios
class Ctx:
    def __init__(self, prof, agents, clock, rep, status_fn):
        self.prof, self.agents, self.clock, self.rep, self.status_fn = prof, agents, clock, rep, status_fn
        self.sc = {sc["name"]: sc for sc in prof["scenarios"]}


def _parallel(fns):
    results = [None] * len(fns)

    def run(i, fn):
        try:
            results[i] = fn()
        except Exception as e:  # noqa: BLE001 -- recorded, never raised past the scheduler
            results[i] = "harness exception: %r" % (e,)
    threads = [threading.Thread(target=run, args=(i, fn), daemon=True) for i, fn in enumerate(fns)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    return results


def _hang_up(ctx, name, dlg):
    """BYE a dialog the far side has not ended. Returns an error or None."""
    if dlg.ended.is_set():
        return None
    st = dlg.bye()
    ctx.rep.code(name, "BYE", st)
    return None if st == 200 else "%s BYE -> %s" % (dlg.agent.ext, st or "no final response")


def _media_call(ctx, name, agent, target, hold_s):
    dlg = agent.invite(target)
    ctx.rep.code(name, "INVITE", dlg.final_status)
    if not dlg.ok:
        dlg.close()
        return "%s INVITE %s -> %s" % (agent.ext, target, dlg.final_status or "no final response")
    err = None
    try:
        ctx.clock.hold(hold_s)
        if dlg.ended.is_set():
            err = "%s->%s: the PBX hung up during the hold" % (agent.ext, target)
    finally:
        bye_err = _hang_up(ctx, name, dlg)
        dlg.close()
        ctx.rep.rtp(name, dlg.rtp_tx, dlg.rtp_rx)
    return err or bye_err


def run_media(ctx, sc, ev):
    uas = [ctx.agents[i] for i in ev["uas"]]
    errs = _parallel([lambda a=a: _media_call(ctx, sc["name"], a, sc["target"], sc["hold_s"])
                      for a in uas])
    return [e for e in errs if e]


def run_ext(ctx, sc, ev):
    name = sc["name"]
    caller, callee = ctx.agents[ev["uas"][0]], ctx.agents[ev["uas"][1]]
    for role, ua in (("callee", callee), ("caller", caller)):
        if not ua.registered:
            return ["%s %s is not registered by this run: call not placed (that extension "
                    "could ring another device)" % (role, ua.ext)]
    since = callee.incoming_count()
    dlg = caller.invite(callee.ext)
    ctx.rep.code(name, "INVITE", dlg.final_status)
    if not dlg.ok:
        dlg.close()
        return ["%s INVITE %s -> %s" % (caller.ext, callee.ext, dlg.final_status or "no final response")]
    errs = []
    inc = callee.wait_incoming(since, 5.0)
    try:
        if inc is None:
            errs.append("%s answered but the test UA %s never saw the INVITE: hung up at once"
                        % (callee.ext, callee.ext))
        else:
            if not inc.confirmed.wait(5.0):
                errs.append("callee %s never got the ACK" % callee.ext)
            ctx.clock.hold(sc["hold_s"])
            if dlg.ended.is_set():
                errs.append("the PBX hung up %s->%s during the hold" % (caller.ext, callee.ext))
    finally:
        e = _hang_up(ctx, name, dlg)
        if e:
            errs.append(e)
        if inc is not None and not inc.ended.wait(5.0):
            errs.append("callee %s never got the BYE" % callee.ext)
        dlg.close()
        ctx.rep.rtp(name, dlg.rtp_tx, dlg.rtp_rx)
        if inc is not None:
            inc.close()
            ctx.rep.rtp(name, inc.rtp_tx, inc.rtp_rx)
    return errs


def run_park(ctx, sc, ev):
    name, orbit = sc["name"], str(sc["orbit"])
    parker, retriever = ctx.agents[ev["uas"][0]], ctx.agents[ev["uas"][1]]
    st = ctx.status_fn() if ctx.status_fn else None
    parked = st.get("parkedCount") if isinstance(st, dict) else None
    if not isinstance(parked, int) or isinstance(parked, bool):
        return ["park refused: /api/status unavailable or without parkedCount (orbit %s could "
                "hold someone's call)" % orbit]
    if parked > 0:
        return ["park refused: the board already holds %d parked call(s)" % parked]
    dp = parker.invite(orbit)
    ctx.rep.code(name, "INVITE", dp.final_status)
    if not dp.ok:
        dp.close()
        return ["%s INVITE %s -> %s" % (parker.ext, orbit, dp.final_status or "no final response")]
    errs = []
    dr = None
    try:
        direction = dp.remote_media[2]
        if direction not in ("sendonly", "inactive"):
            errs.append("orbit %s answered %s: it was occupied (a retrieve, not a park); hung up"
                        % (orbit, direction))
            return errs
        ctx.rep.note(name, "moh_offered" if direction == "sendonly" else "silent_hold", 1)
        ctx.clock.hold(sc["parked_s"])
        ctx.rep.note(name, "moh_rx_packets", dp.media_counts()[1])
        dr = retriever.invite(orbit)
        ctx.rep.code(name, "INVITE", dr.final_status)
        if not dr.ok:
            errs.append("%s retrieve INVITE %s -> %s" % (retriever.ext, orbit,
                                                         dr.final_status or "no final response"))
            return errs
        if not dp.reinvited.wait(5.0):
            errs.append("parked %s was never re-INVITEd on retrieve" % parker.ext)
        ctx.clock.hold(sc["retrieved_s"])
        e = _hang_up(ctx, name, dr)
        if e:
            errs.append(e)
        if not dp.ended.wait(5.0):
            errs.append("parked %s never got the BYE after the retriever hung up" % parker.ext)
    finally:
        e = _hang_up(ctx, name, dp)
        if e and not errs:
            errs.append(e)
        for d in (dr, dp):
            if d is not None:
                d.close()
                ctx.rep.rtp(name, d.rtp_tx, d.rtp_rx)
    return errs


RUNNERS = {"echo": run_media, "conf": run_media, "ext": run_ext, "park": run_park}


def _run_event(ctx, ev, t_rel):
    sc = ctx.sc[ev["scenario"]]
    ctx.rep.attempt(sc["name"])
    try:
        errs = RUNNERS[sc["kind"]](ctx, sc, ev)
    except Exception as e:  # noqa: BLE001
        errs = ["harness exception: %r" % (e,)]
    ctx.rep.result(sc["name"], ev["occurrence"], t_rel, errs, ctx.clock.wall())


def _join(threads, timeout):
    deadline = time.monotonic() + timeout
    for th in threads:
        th.join(max(0.0, deadline - time.monotonic()))
    return [th for th in threads if th.is_alive()]


def execute(prof, plan, agents, clock, rep, status_fn, log=print):
    ctx = Ctx(prof, agents, clock, rep, status_fn)
    expires = prof["register"]["expires"]
    grace = max(busy_s(sc, prof["setup_margin_s"]) for sc in prof["scenarios"]) + 60
    actions = ([(r["t"], 0, "reg", r) for r in plan["registers"]] +
               [(b["t"], 1, "burst", b) for b in plan["bursts"]])
    actions.sort(key=lambda a: (a[0], a[1]))
    t0 = clock.now()
    rep.data["started_at"] = clock.wall()
    rep.data["load_end_at"] = rep.data["started_at"] + plan["duration_s"]
    rep.data["quiesce_check_at"] = rep.data["load_end_at"] + plan["quiesce_s"]
    workers = []
    try:
        for t, _, kind, item in actions:
            if not clock.wait_until(t0 + t):
                rep.data["interrupted"] = True
                break
            if kind == "reg":
                ua = agents[item["ua"]]
                rep.registration(ua.register(expires), ua.registered)
                continue
            for th in _join(workers, grace):
                rep.data.setdefault("overruns", []).append(th.name)
            workers = []
            for ev in item["events"]:
                th = threading.Thread(target=_run_event, args=(ctx, ev, t), daemon=True,
                                      name="%s#%d" % (ev["scenario"], ev["occurrence"]))
                th.start()
                workers.append(th)
        if not rep.data["interrupted"] and not clock.wait_until(t0 + plan["duration_s"] + plan["quiesce_s"]):
            rep.data["interrupted"] = True
    finally:
        for th in _join(workers, grace):
            rep.data.setdefault("overruns", []).append(th.name)
        for ua in agents:
            for dlg in ua.live_dialogs():
                if not dlg.ended.is_set() and dlg.ok:
                    dlg.bye()
                dlg.close()
        for ua in agents:
            if ua.register(0) == 200:
                rep.data["registrations"]["deregistered"] += 1
        rep.data["ended_at"] = clock.wall()
    return rep


# ---------------------------------------------------------------- CLI
def http_status(url, timeout=3.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            body = json.loads(r.read().decode("utf-8", "replace"))
            return body if isinstance(body, dict) else None
    except Exception:  # noqa: BLE001 -- unreachable is "no status", and park refuses on it
        return None


def build_parser():
    ap = argparse.ArgumentParser(prog="sip_stress.py --profile", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", required=True, choices=sorted(PROFILES))
    ap.add_argument("--host", required=True, help="the PBX under test (no default)")
    ap.add_argument("--port", type=int, default=5060)
    ap.add_argument("--status-url", default=None, help="default http://<host>/api/status")
    ap.add_argument("--exts", default="", help="the test UAs' extensions, comma-separated")
    ap.add_argument("--owner-ext", default=None,
                    help="the owner's extensions, refused as targets and as test UAs "
                         "(default $PD_OWNER_EXTS; 'none' asserts there are none)")
    ap.add_argument("--duration", type=int, default=None, help="load window in seconds")
    ap.add_argument("--quiesce-s", type=int, default=None,
                    help="after the load: registrations only, before de-registering")
    ap.add_argument("--report", default=None, help="write the JSON report here")
    ap.add_argument("--dry-run", action="store_true", help="print the plan; send nothing")
    ap.add_argument("--checkout-url", default=None, help="the discussion #428 CHECK-OUT comment link")
    ap.add_argument("--checkout-expiry", default=None, help="its expiry, ISO-8601 with a zone")
    ap.add_argument("--local-ip", default=None, help="bind address (default: the route to --host)")
    ap.add_argument("--no-rtp", action="store_true", help="signal only; send no RTP")
    return ap


def _install_signals(clock):
    old = {}

    def handler(signum, frame):
        clock.stop.set()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            old[sig] = signal.signal(sig, handler)
        except ValueError:
            pass              # not the main thread (a test driving main())
    return old


def _restore_signals(old):
    for sig, h in old.items():
        signal.signal(sig, h)


def main(argv=None, clock=None, agent_factory=None, status_fn=None, out=print):
    args = build_parser().parse_args(argv)
    prof = copy.deepcopy(PROFILES[args.profile])
    duration = args.duration if args.duration is not None else prof["duration_s"]
    quiesce = args.quiesce_s if args.quiesce_s is not None else prof["quiesce_s"]
    exts = [e.strip() for e in args.exts.split(",") if e.strip()]
    owner = parse_owner(args.owner_ext, os.environ.get("PD_OWNER_EXTS"))
    status_url = args.status_url or "http://%s/api/status" % args.host
    clock = clock or RealClock()

    problems = validate_profile(prof) + safety_problems(prof, exts, owner)
    plan = make_plan(prof, duration, quiesce) if not validate_profile(prof) else None
    if plan is not None:
        problems += plan_problems(plan)
    needed = duration + quiesce + END_MARGIN_S
    co_problems = checkout_problems(args.checkout_url, args.checkout_expiry, time.time(), needed)

    out("sip_stress.py --profile %s%s" % (args.profile, "  (DRY RUN: nothing is sent)" if args.dry_run else ""))
    out("  target    %s:%d   status %s" % (args.host, args.port, status_url))
    out("  test UAs  %s   owner phones refused: %s" % (" ".join(exts) or "<none>",
        "<no list>" if owner is None else len(owner)))
    out("  table     sha256 %s  (%s)" % (table_sha256(prof)[:16], prof["about"]))
    out("  CHECK-OUT %s until %s  [%s]" % (args.checkout_url or "<none>", args.checkout_expiry or "<none>",
        "ok" if not co_problems else "a real run refuses: " + "; ".join(co_problems)))
    out("  load      %d s, then %d s of registrations only, then de-register" % (duration, quiesce))
    if plan is not None:
        out("  plan      %d bursts, idle >= %d s between them (%.0f%% idle); %s; %d REGISTERs"
            % (len(plan["bursts"]), prof["idle_gap_s"], 100 * plan["idle_fraction"],
               ", ".join("%s x%d" % kv for kv in plan["counts"].items()), len(plan["registers"])))
        for line in format_plan(prof, plan, exts):
            out(line)
    if problems:
        for p in problems:
            out("REFUSED: " + p)
        return 2

    meta = {"tool": "tests/load/sip_stress.py --profile", "profile": args.profile,
            "about": prof["about"], "table_sha256": table_sha256(prof), "table": prof,
            "host": args.host, "port": args.port, "exts": exts,
            "duration_s": duration, "quiesce_s": quiesce, "dry_run": args.dry_run,
            "checkout": {"url": args.checkout_url, "expiry": args.checkout_expiry},
            "rtp": not args.no_rtp, "schedule": plan}
    if args.dry_run:
        if args.report:
            with open(args.report, "w", encoding="utf-8") as f:
                json.dump(dict(meta, **{"pass": None}), f, indent=1)
        return 0
    if co_problems:
        for p in co_problems:
            out("REFUSED: " + p)
        return 2

    rep = Report(meta, plan)
    pump = None if args.no_rtp else sip_agent.RtpPump()
    factory = agent_factory or (lambda ext: sip_agent.Agent(ext, args.host, args.port,
                                                            local_ip=args.local_ip, rtp_pump=pump))
    agents = []
    old = _install_signals(clock)
    try:
        agents = [factory(e) for e in exts]
        execute(prof, plan, agents, clock, rep,
                status_fn or (lambda: http_status(status_url)), log=out)
    finally:
        _restore_signals(old)
        for ua in agents:
            ua.close()
        if pump is not None:
            pump.stop()
    passed = rep.finish()
    for name, s in rep.data["scenarios"].items():
        out("  %-9s planned %3d  ran %3d  ok %3d  failed %3d  codes %s"
            % (name, s["planned"], s["attempted"], s["ok"], s["failed"],
               " ".join("%s:%d" % kv for kv in sorted(s["codes"].items()))))
    r = rep.data["registrations"]
    out("  REGISTER  planned %3d  sent %3d  ok %3d  failed %3d  de-registered %d"
        % (r["planned"], r["attempted"], r["ok"], r["failed"], r["deregistered"]))
    for p in rep.data["problems"]:
        out("FAIL: " + p)
    out("LOAD VERDICT: %s" % ("PASS" if passed else "FAIL"))
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(rep.data, f, indent=1)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

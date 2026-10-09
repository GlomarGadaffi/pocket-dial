#!/usr/bin/env python3
"""Self-test for the h947_http_load scenario (#947, for #410): tests/load/http_load.py and its glue in
tests/load/anchor_scenarios.py. Runs in CI:

    python3 -m unittest discover -s tests/tools -p 'test_http_load.py'

Everything is loopback and fakes: a small HTTP server with the board's per-source cap, and the anchor
tests' fake board (tests/tools/test_anchor_scenarios.py) with the dashboard's routes added. No board, no
phone, no 3CX, no hardware, no other network.
"""
import collections
import contextlib
import io
import json
import os
import re
import sys
import tempfile
import threading
import time
import types
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(HERE, "..", "load"))
import anchor_scenarios as an  # noqa: E402
import http_load as hl  # noqa: E402
import sip_stress  # noqa: E402
import test_anchor_scenarios as base  # noqa: E402  (its fakes; no TestCase is imported by name)

S = "h947_http_load"
FAR, FAR2 = base.FAR, base.FAR2


def cli(*extra, **kw):
    kw.setdefault("scenario", S)
    return base.cli(*extra, **kw)


def read(path):
    with open(os.path.join(REPO, path), encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------- nearest-rank percentile
class NearestRankTest(unittest.TestCase):
    def test_p50_and_p99_of_one_to_a_hundred(self):
        xs = list(range(100, 0, -1))                       # unsorted on purpose
        self.assertEqual((hl.nearest_rank(xs, 50), hl.nearest_rank(xs, 99)), (50, 99))
        self.assertEqual((hl.nearest_rank(xs, 1), hl.nearest_rank(xs, 100)), (1, 100))

    def test_the_textbook_five(self):
        xs = [15, 20, 35, 40, 50]                           # nearest-rank: P30 = 20, P40 = 20, P50 = 35
        self.assertEqual([hl.nearest_rank(xs, p) for p in (5, 30, 40, 50, 100)], [15, 20, 20, 35, 50])

    def test_p99_of_fewer_than_a_hundred_is_the_maximum(self):
        xs = [7, 3, 9, 1, 5, 8, 2, 10, 4, 6]
        self.assertEqual((hl.nearest_rank(xs, 99), hl.nearest_rank(xs, 50), hl.nearest_rank(xs, 90)), (10, 5, 9))

    def test_empty_and_single(self):
        self.assertIsNone(hl.nearest_rank([], 50))
        self.assertEqual({hl.nearest_rank([4.5], p) for p in (1, 50, 99, 100)}, {4.5})

    def test_it_is_not_the_interpolated_percentile_sip_stress_has(self):
        self.assertEqual(sip_stress.pct([10, 20], 50), 15.0)
        self.assertEqual(hl.nearest_rank([10, 20], 50), 10)


class PeakConcurrencyTest(unittest.TestCase):
    def test_fixed_spans(self):
        self.assertEqual(hl.peak_concurrency([(0, 2), (1, 3), (2, 4), (5, 6)]), 2)
        self.assertEqual(hl.peak_concurrency([(0, 10), (1, 9), (2, 8)]), 3)
        self.assertEqual(hl.peak_concurrency([]), 0)

    def test_a_span_ending_as_another_starts_does_not_overlap_it(self):
        self.assertEqual(hl.peak_concurrency([(0, 1), (1, 2), (2, 3)]), 1)


# ---------------------------------------------------------------- the plan and the run cap
class PlanAndCapTest(unittest.TestCase):
    def test_the_default_plan_is_three_repeats_of_each_mode_lightest_first(self):
        runs = hl.plan(hl.DEFAULTS)
        self.assertEqual(len(runs), 9)
        self.assertEqual(runs, [(m, r) for m in ("idle", "dashboard", "dashboard-call") for r in (1, 2, 3)])
        self.assertEqual((hl.DEFAULTS["repeats"], hl.DEFAULTS["run_cap"]), (3, 9))
        self.assertEqual(hl.plan(dict(hl.DEFAULTS, modes=("dashboard-call", "idle"), repeats=2)),
                         [("idle", 1), ("idle", 2), ("dashboard-call", 1), ("dashboard-call", 2)])

    def test_a_run_past_the_cap_is_refused(self):
        self.assertEqual(hl.run_cap_problems(9, 9), [])
        self.assertIn("12 runs", hl.run_cap_problems(12, 9)[0])
        self.assertIn("past --run-cap 9", hl.run_cap_problems(12, 9)[0])
        self.assertTrue(hl.run_cap_problems(10, 9))

    def test_the_cap_itself_is_bounded_and_a_stray_number_is_never_echoed(self):
        for cap in (0, -1, 31, 15550104242):
            problems = hl.run_cap_problems(1, cap)
            self.assertEqual(problems, ["--run-cap must be 1-30"], cap)
        self.assertEqual(hl.config_problems(dict(hl.DEFAULTS, run_cap=15550104242)), ["--run-cap must be 1-30"])

    def test_the_budget_stops_the_run_after_the_cap(self):
        budget = hl.RunBudget(9)
        for _ in range(9):
            budget.take()
        with self.assertRaises(hl.CapExceeded) as cm:
            budget.take()
        self.assertIn("run 10 is past --run-cap 9", str(cm.exception))
        self.assertEqual(budget.used, 9)

    def test_the_default_configuration_is_valid_and_each_knob_is_bounded(self):
        self.assertEqual(hl.config_problems(hl.DEFAULTS), [])
        for key, bad, needle in (("modes", ("idle", "bogus"), "--http-modes"), ("modes", (), "--http-modes"),
                                 ("modes", ("idle", "idle"), "--http-modes"), ("repeats", 0, "--repeats"),
                                 ("repeats", 4, "12 runs"), ("window_s", 0.5, "--window-s"),
                                 ("probe_polls", 0, "--probe-polls"), ("probe_polls", 1001, "--probe-polls"),
                                 ("probe_gap_s", 11, "--probe-gap-ms"), ("burst_workers", 9, "--burst-workers"),
                                 ("burst_workers", 0, "--burst-workers"), ("burst_each", 0, "--burst-each")):
            problems = hl.config_problems(dict(hl.DEFAULTS, **{key: bad}))
            self.assertTrue(any(needle in p for p in problems), (key, bad, problems))
        self.assertEqual(hl.config_problems(dict(hl.DEFAULTS, repeats=4, run_cap=12)), [])


# ---------------------------------------------------------------- the refusals, through main()
class CliRefusalTest(unittest.TestCase):
    def refused(self, argv, env, needle):
        rc, out = base.run_main(argv, env, http=base.NoNetwork())
        self.assertEqual(rc, an.REFUSED, out)
        self.assertIn("REFUSED", out)
        self.assertIn(needle, out)
        self.assertNotIn(FAR, out)
        return out

    def test_every_forbidden_far_end_is_refused_before_anything_is_sent(self):
        for num in ("911", "933", "113", "1001"):                       # desmo's list for #947
            out = self.refused(cli(), base.base_env(PD_ANCHOR_FAR_END=num),
                               "owner extension" if num == "1001" else "emergency or never-dial")
            self.assertIn("nothing was sent", out, num)
            rc, out = base.run_main(cli("--dry-run"), base.base_env(PD_ANCHOR_FAR_END=num), http=base.NoNetwork())
            self.assertEqual(rc, an.REFUSED, "refused in a dry run too: " + num)
        for num in ("9911", "112", "999", "1002", "1003", "15559110000", "+19335551234"):
            self.refused(cli(), base.base_env(PD_ANCHOR_FAR_END=num),
                         "owner extension" if num in ("1002", "1003") else "emergency or never-dial")
        for num in ("6101", "6104", "555", "777", "985"):
            self.refused(cli(), base.base_env(PD_ANCHOR_FAR_END=num), "this PBX owns")

    def test_every_forbidden_far_end_is_refused_on_the_second_line_too(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "far")
            for forbidden in ("911", "1001"):
                with open(path, "w", encoding="utf-8") as f:
                    f.write("%s\n%s\n" % (FAR, forbidden))
                os.chmod(path, 0o600)
                rc, out = base.run_main(cli(), base.base_env(PD_ANCHOR_FAR_END=None, PD_ANCHOR_FAR_END_FILE=path),
                                        http=base.NoNetwork())
                self.assertEqual(rc, an.REFUSED, out)
                self.assertNotIn(FAR, out)

    def test_a_valid_far_end_is_accepted(self):
        for far in (FAR, FAR2, "+" + FAR):
            rc, out = base.run_main(cli("--dry-run"), base.base_env(PD_ANCHOR_FAR_END=far), http=base.NoNetwork())
            self.assertEqual(rc, 0, out)
            self.assertNotIn(far.lstrip("+"), out)

    def test_the_dry_run_prints_the_plan_and_the_ring_banner_only_when_a_call_is_planned(self):
        rc, out = base.run_main(cli("--dry-run"), base.base_env(), http=base.NoNetwork())
        self.assertEqual(rc, 0, out)
        self.assertIn("plan      9 run(s), cap 9: idle x3, dashboard x3, dashboard-call x3", out)
        self.assertIn("3 ring(s), one held 24 s each", out)
        self.assertIn("RING-REQUIRED", out)
        self.assertIn("(Part of #947)", out)
        rc, out = base.run_main(cli("--dry-run", "--http-modes", "idle,dashboard"), base.base_env(),
                                http=base.NoNetwork())
        self.assertEqual(rc, 0, out)
        self.assertIn("0 ring(s)", out)
        self.assertIn("calls     0", out)
        self.assertNotIn("RING-REQUIRED", out)

    def test_runs_beyond_the_cap_are_refused_and_a_raised_cap_is_accepted(self):
        out = self.refused(cli("--repeats", "4"), base.base_env(), "12 runs (modes x repeats) is past --run-cap 9")
        self.assertIn("nothing was sent", out)
        self.refused(cli("--run-cap", "8"), base.base_env(), "9 runs (modes x repeats) is past --run-cap 8")
        self.refused(cli("--http-modes", "idle,dashboard,dashboard-call", "--repeats", "3", "--run-cap", "5"),
                     base.base_env(), "past --run-cap 5")
        rc, out = base.run_main(cli("--dry-run", "--repeats", "4", "--run-cap", "12"), base.base_env(),
                                http=base.NoNetwork())
        self.assertEqual(rc, 0, out)
        self.assertIn("plan      12 run(s), cap 12", out)

    def test_the_cap_is_bounded_and_a_far_end_pasted_into_it_is_not_echoed(self):
        for cap in ("0", "31"):
            self.refused(cli("--run-cap", cap), base.base_env(), "--run-cap must be 1-30")
        other = "15559998888"
        out = self.refused(cli("--run-cap", other), base.base_env(), "--run-cap must be 1-30")
        self.assertNotIn(other, out)
        out = self.refused(cli("--probe-polls", other), base.base_env(), "--probe-polls must be 1-1000")
        self.assertNotIn(other, out)
        out = self.refused(cli("--run-cap", FAR), base.base_env(), "holds a secret")       # the real far end itself
        self.assertNotIn(FAR, out)

    def test_the_other_knobs_are_refused_when_out_of_range(self):
        self.refused(cli("--http-modes", "idle,bogus"), base.base_env(), "--http-modes")
        self.refused(cli("--burst-workers", "9"), base.base_env(), "--burst-workers must be 1-8")
        self.refused(cli("--window-s", "0"), base.base_env(), "--window-s")
        self.refused(cli("--repeats", "0"), base.base_env(), "--repeats")

    def test_the_numeric_flags_are_not_taken_for_a_far_end(self):
        rc, out = base.run_main(cli("--dry-run", "--probe-polls", "200", "--window-s", "120", "--burst-each", "100"),
                                base.base_env(), http=base.NoNetwork())
        self.assertEqual(rc, 0, out)
        self.assertIn("probe 200 x GET /api/status", out)

    def test_it_carries_the_refusals_every_anchor_scenario_has(self):
        self.refused(cli(checkout=None), base.base_env(), "no CHECK-OUT")
        self.refused(cli(approval=an.APPROVALS[0] + "x"), base.base_env(), "not a recorded approval")
        self.refused(cli(host="192.168.12.110"), base.base_env(), "not an approved rig")
        self.refused(cli("--far-end", FAR), base.base_env(), "never goes on an argv")
        self.refused(cli(), base.base_env(PD_ANCHOR_FAR_END=None), "no far end")
        self.refused(cli(), base.base_env(), "no --expect-version")

    def test_the_ring_cap_is_ten_calls(self):
        self.refused(cli("--http-modes", "dashboard-call", "--repeats", "11", "--run-cap", "30"), base.base_env(),
                     "calls must be 0-10")
        rc, out = base.run_main(cli("--dry-run", "--http-modes", "dashboard-call", "--repeats", "10",
                                    "--run-cap", "30"), base.base_env(), http=base.NoNetwork())
        self.assertEqual(rc, 0, out)

    def test_the_scenario_is_registered_as_specified(self):
        sc = an.SCENARIOS[S]
        self.assertEqual((sc["issues"], sc["path_counter"], sc["call_cap_s"], sc["hold_s"], sc["max_calls"]),
                         (("#947", "#410"), "initiated", 30, 24.0, 10))
        self.assertEqual(sc["uas"], {"caller": "6101", "detector": "6104"})
        self.assertTrue(sc["no_status_logger"] and sc["ring_required"])
        self.assertEqual(an.scenario_problems(sc), [])
        self.assertTrue(any("hold_s leaves no room" in p for p in an.scenario_problems(dict(sc, hold_s=29.0))))
        self.assertEqual(an.MAX_CALL_S, 30, "the d451 approval's per-call bound is not raised here")

    def test_sip_stress_delegates_the_scenario(self):
        with mock.patch.dict(os.environ, base.base_env(), clear=False):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = sip_stress.main(cli("--dry-run"))
        self.assertEqual(rc, 0, buf.getvalue())
        self.assertIn(S, buf.getvalue())


class HaltOnStopTest(unittest.TestCase):
    def test_a_signal_ends_the_window_and_nothing_else_does(self):
        load = hl.RunLoad(lambda *a: None, hl.Sink(), 1, "idle")
        an.h947_halt_on_stop(types.SimpleNamespace(stopped=lambda: False), load)
        self.assertFalse(load.halt.is_set())
        an.h947_halt_on_stop(types.SimpleNamespace(stopped=lambda: True), load)
        self.assertTrue(load.halt.is_set())


class CheckpointRetryTest(unittest.TestCase):
    """A 503 from the per-source cap reads to checkpoint() as a lapsed pin; only one that persists is one."""

    @staticmethod
    def run_failing(times, verdict="INVALID"):
        calls = []

        def checkpoint():
            calls.append(1)
            if len(calls) <= times:
                raise an.run_soak.Abort(verdict, "the S1 pin lapsed: GET /api/did-mapping failed")
        return types.SimpleNamespace(checkpoint=checkpoint, stop=threading.Event()), calls

    def test_a_blip_is_tried_again_and_a_lapse_that_persists_is_not(self):
        run, calls = self.run_failing(2)
        an.h947_checkpoint(run)
        self.assertEqual(len(calls), 3)
        run, calls = self.run_failing(3)
        with self.assertRaises(an.run_soak.Abort) as cm:
            an.h947_checkpoint(run)
        self.assertEqual((cm.exception.verdict, len(calls)), ("INVALID", 3))

    def test_a_fail_is_never_tried_again(self):
        run, calls = self.run_failing(1, verdict="FAIL")
        with self.assertRaises(an.run_soak.Abort):
            an.h947_checkpoint(run)
        self.assertEqual(len(calls), 1)

    def test_a_signal_stops_the_retries(self):
        run, calls = self.run_failing(3)
        run.stop.set()
        with self.assertRaises(an.run_soak.Abort):
            an.h947_checkpoint(run)
        self.assertEqual(len(calls), 1)


class RingGateTest(unittest.TestCase):
    """The last check before the one INVITE, in case anything upstream of main()'s refusals is bypassed."""

    @staticmethod
    def run_with(*far):
        return types.SimpleNamespace(far_ends=tuple(far))

    def test_a_forbidden_far_end_is_refused_at_the_ring(self):
        for num in ("911", "933", "113", "1001", "9911", "112"):
            with self.assertRaises(an.run_soak.Abort) as cm:
                an.h947_ring_gate(self.run_with(num))
            self.assertEqual(cm.exception.verdict, "INVALID")
            self.assertIn("refusing to ring", cm.exception.reason)
        with self.assertRaises(an.run_soak.Abort):
            an.h947_ring_gate(self.run_with(FAR, "911"))
        an.h947_ring_gate(self.run_with(FAR))
        an.h947_ring_gate(self.run_with(FAR, FAR2))

    def test_a_call_run_with_a_forbidden_far_end_never_sends_an_invite(self):
        caller = mock.Mock()
        caller.invite.side_effect = AssertionError("an INVITE was sent to a forbidden number")
        run = types.SimpleNamespace(far_ends=("911",), far_end="911")
        with self.assertRaises(an.run_soak.Abort):
            an.h947_call(run, an.SCENARIOS[S], mock.Mock(), caller, hl.DEFAULTS)
        caller.invite.assert_not_called()


# ---------------------------------------------------------------- the log and the summary
def _req(run, mode, label, path, t, ms, code=200):
    return {"k": "req", "run": run, "mode": mode, "label": label, "path": path, "t": t, "ms": ms, "code": code,
            "bytes": 100, "err": None}


def _stat(run, mode, label, t, **kw):
    d = {"k": "status", "run": run, "mode": mode, "label": label, "t": t, "uptime": 7200,
         "freeHeapInternal": 50000, "minFreeHeapInternal": 39483, "largestFreeBlockInternal": 26612,
         "stackHwm_http_conn": 1552, "httpConnWorstRoute": "GET /api/status", "httpPerSourceRefusals": 4}
    d.update(kw)
    return d


def excerpt():
    """26 lines: two runs, one line that is not JSON (it still counts for the line numbers)."""
    r1, r2 = (1, "idle"), (2, "dashboard-call")
    rows = [
        _req(*r1, "before", "/api/status", 0.0, 10.0), _stat(*r1, "before", 0.0),
        _req(*r1, "probe", "/api/status", 1.0, 10.0), _stat(*r1, "probe", 1.0, freeHeapInternal=49000),
        _req(*r1, "probe", "/api/status", 2.0, 20.0), _stat(*r1, "probe", 2.0, freeHeapInternal=51000),
        _req(*r1, "probe", "/api/status", 3.0, 30.0), _stat(*r1, "probe", 3.0),
        _req(*r1, "burst", "/api/status", 4.0, 40.0),
        _req(*r1, "poll", "/api/status", 4.0, 50.0, 503),                  # the dashboard's own poll, refused
        _req(*r1, "burst", "/api/status", 4.01, 60.0),
        _req(*r1, "after", "/api/status", 5.0, 10.0),
        _stat(*r1, "after", 5.0, uptime=7205, freeHeapInternal=50200, httpPerSourceRefusals=5),
        {"k": "run", "run": 1, "mode": "idle", "rep": 1, "probe": [3, 3], "burst": [3, 3]},
        "this line is not json",
        _req(*r2, "before", "/api/status", 0.0, 20.0),
        _stat(*r2, "before", 0.0, uptime=7300, freeHeapInternal=48000, httpPerSourceRefusals=5),
        _req(*r2, "poll", "/api/cdr", 0.5, 30.0),
        _req(*r2, "probe", "/api/status", 1.0, 100.0),
        _stat(*r2, "probe", 1.0, freeHeapInternal=47000, stackHwm_http_conn=1400, httpConnWorstRoute="GET /api/trace"),
        _req(*r2, "probe", "/api/status", 2.0, 200.0),
        _stat(*r2, "probe", 2.0, freeHeapInternal=46500, minFreeHeapInternal=38000, stackHwm_http_conn=1400,
              httpConnWorstRoute="GET /api/trace"),
        _req(*r2, "safety", "checkpoint", 2.5, 5.0),
        _req(*r2, "after", "/api/status", 3.0, 20.0),
        _stat(*r2, "after", 3.0, uptime=7303, freeHeapInternal=48000, minFreeHeapInternal=38000,
              stackHwm_http_conn=1400, httpConnWorstRoute="GET /api/trace", httpPerSourceRefusals=7),
        {"k": "run", "run": 2, "mode": "dashboard-call", "rep": 1, "probe": [2, 3], "burst": [0, 3], "call": 1},
    ]
    return [r if isinstance(r, str) else json.dumps(r, sort_keys=True) for r in rows]


EXPECTED_SUMMARY = "\n".join([
    "#947 HTTP server under load: 2 run(s), nearest-rank percentiles, latency in ms, concurrency counted at this client",
    "mode idle: 1 run(s)",
    "  run 1 (repeat 1): peak all 2, polls 0 | served 7, refused 503 1 (polls 1), errors 0"
    " | probe n=3/3 p50=20.0 p99=30.0 (p99 = max, n<100)"
    " | burst n=2/3 p50=40.0 p99=60.0 (p99 = max, n<100) | freeHeapInternal 49000..51000"
    " | minFreeHeapInternal 39483 -> 39483 | stackHwm_http_conn 1552 -> 1552",
    "  spread over 1 run(s): peak all 2, polls 0; probe p50 20.0, p99 30.0; burst p50 40.0, p99 60.0; freeHeapInternal swing 2000",
    "mode dashboard-call: 1 run(s)",
    "  run 2 (repeat 1): peak all 1, polls 1 | served 6, refused 503 0 (polls 0), errors 0"
    " | probe n=2/3 p50=100.0 p99=200.0"
    " (p99 = max, n<100) | burst n=0/3 | freeHeapInternal 46500..48000"
    " | minFreeHeapInternal 39483 -> 38000 | stackHwm_http_conn 1552 -> 1400",
    "  spread over 1 run(s): peak all 1, polls 1; probe p50 100.0, p99 200.0; burst p50 -, p99 -; freeHeapInternal swing 1500",
    "stack high-water: stackHwm_http_conn 1400 B free of 4096 B (2696 B used), httpConnWorstRoute \"GET /api/trace\";"
    " source http-load.jsonl line 20 (run 2, dashboard-call, probe read)",
    "low-water internal free: minFreeHeapInternal 38000 B; source http-load.jsonl line 22 (run 2, dashboard-call,"
    " probe read); first read 39483 B, so the runs took it lower",
    "uptime at the first read: 7200 s",
    "503s: this client saw 1; the board's httpPerSourceRefusals moved by 3 (its global-cap refusals are not emitted)",
    "both watermarks are since boot and only fall: a run shows a low-water only if it went below every earlier run;"
    " the board serves 3 connection(s) per source and refuses the rest with 503",
    "not emitted by the firmware, so not reported: a peak or active-connection count, a per-request thread cost;"
    " a SIP reply time during the burst is not measured here",
])


class SummaryTest(unittest.TestCase):
    def test_the_fixed_excerpt_reads_back_with_its_line_numbers(self):
        lines = excerpt()
        self.assertEqual(len(lines), 26)
        recs = hl.read_log(lines)
        self.assertEqual(len(recs), 25, "the line that is not JSON is skipped")
        self.assertEqual([r["_n"] for r in recs][13:16], [14, 16, 17], "but it still takes its line number")
        self.assertEqual(recs[18]["stackHwm_http_conn"], 1400)
        self.assertEqual(recs[18]["_n"], 20)

    def test_the_summary_of_the_fixed_excerpt(self):
        self.assertEqual(hl.render(hl.read_log(excerpt())), EXPECTED_SUMMARY)

    def test_the_per_run_numbers_by_hand(self):
        s = {d["run"]: hl.run_stats(d) for d in hl.per_run(hl.read_log(excerpt()))}
        self.assertEqual((s[1]["peak"], s[1]["peak_poll"], s[1]["served"], s[1]["refused"], s[1]["refused_poll"]),
                         (2, 0, 7, 1, 1))
        self.assertEqual((s[2]["peak"], s[2]["peak_poll"], s[2]["refused_poll"]), (1, 1, 0))
        self.assertEqual(s[1]["probe"], {"n": 3, "p50": 20.0, "p99": 30.0})
        self.assertEqual(s[1]["burst"], {"n": 2, "p50": 40.0, "p99": 60.0})
        self.assertEqual((s[2]["probe"]["p99"], s[2]["burst"]["n"]), (200.0, 0))
        self.assertEqual((s[2]["min_free"], s[2]["stack"], s[2]["refusals"]), ((39483, 38000), (1552, 1400), (5, 7)))

    def test_a_reading_right_after_boot_is_called_what_it_is(self):
        lines = [l.replace('"uptime": 7200', '"uptime": 120') for l in excerpt()]
        text = hl.render(hl.read_log(lines))
        self.assertIn("uptime at the first read: 120 s (under 3600 s: a reading right after boot is not evidence, "
                      "#405; re-read after hours of use)", text)

    def test_a_null_stack_reading_is_reported_as_not_read(self):
        lines = [re.sub(r'"stackHwm_http_conn": \d+', '"stackHwm_http_conn": null', l) for l in excerpt()]
        text = hl.render(hl.read_log(lines))
        self.assertIn("stack high-water: not read (stackHwm_http_conn was null or absent in every sample)", text)

    def test_the_stack_line_is_the_earliest_of_equal_minimums(self):
        text = hl.render(hl.read_log(excerpt()))
        self.assertIn("source http-load.jsonl line 20 (run 2", text)        # lines 22 and 25 hold 1400 too


class PeakSplitTest(unittest.TestCase):
    def test_the_dashboards_own_traffic_is_counted_apart_from_the_harnesss(self):
        rows = [_req(1, "dashboard", "poll", "/api/status", 0.0, 2000.0),
                _req(1, "dashboard", "poll", "/api/cdr", 1.0, 2000.0),
                _req(1, "dashboard", "probe", "/api/status", 0.5, 2000.0),
                _req(1, "dashboard", "burst", "/api/status", 1.5, 100.0, 503),
                _req(1, "dashboard", "poll", "/api/moh", 5.0, 100.0)]
        s = hl.run_stats(hl.per_run(hl.read_log([json.dumps(r) for r in rows]))[0])
        self.assertEqual((s["peak_poll"], s["peak"]), (2, 3))     # polls (0,2) (1,3); with the probe (0.5,2.5): 3
        self.assertEqual((s["refused"], s["refused_poll"]), (1, 0))


def full_run(run, mode, **kw):
    """A complete, healthy run of `mode`: every poll path answered 200, probes, and an end record. The board's
    uptime moves on from run to run, as it does on a board that stays up."""
    up = 7200 + 100 * run
    rows = [_req(run, mode, "before", "/api/status", 0.0, 10.0), _stat(run, mode, "before", 0.0, uptime=up)]
    rows += [_req(run, mode, "poll", path, 0.1, 10.0) for path, _, _ in hl.polls_for(mode)]
    rows += [_req(run, mode, "probe", "/api/status", 1.0 + i, 10.0 + i) for i in range(3)]
    rows += [_req(run, mode, "after", "/api/status", 9.0, 10.0), _stat(run, mode, "after", 9.0, uptime=up + 9)]
    rows.append({"k": "run", "run": run, "mode": mode, "rep": 1, "probe": [3, 3], "burst": [0, 0]})
    return [json.dumps(r, sort_keys=True) for r in rows]


class JudgeLogTest(unittest.TestCase):
    def judge(self, lines):
        return hl.judge_log(hl.read_log(lines))

    def test_healthy_runs_of_every_mode_are_clean(self):
        lines = full_run(1, "idle") + full_run(2, "dashboard") + full_run(3, "dashboard-call")
        self.assertEqual(self.judge(lines), ([], []))

    def test_a_reboot_inside_a_run_is_a_fail(self):
        lines = [l.replace('"uptime": 7309', '"uptime": 12') for l in full_run(1, "idle")]
        fails, invalid = self.judge(lines)
        self.assertEqual(invalid, [])
        self.assertEqual(len(fails), 1)
        self.assertIn("uptime fell from 7300 s to 12 s", fails[0])

    def test_a_reboot_between_two_runs_is_a_fail_too(self):
        run2 = [l.replace('"uptime": 7400', '"uptime": 30').replace('"uptime": 7409', '"uptime": 39')
                for l in full_run(2, "dashboard")]
        fails, invalid = self.judge(full_run(1, "idle") + run2)
        self.assertEqual(invalid, [])
        self.assertEqual(len(fails), 1)
        self.assertIn("run 2 (dashboard): uptime fell from 7309 s (end of run 1) to 30 s at its start", fails[0])
        self.assertIn("rebooted between runs", fails[0])

    def test_no_answered_probe_and_no_end_record_are_invalid(self):
        lines = [l for l in full_run(1, "idle") if '"label": "probe"' not in l]
        self.assertTrue(any("no GET /api/status probe was answered 200" in p for p in self.judge(lines)[1]))
        lines = full_run(1, "idle")[:-1]
        self.assertTrue(any("no end record" in p for p in self.judge(lines)[1]))
        self.assertEqual(self.judge([]), ([], ["no run was recorded"]))

    def test_a_dashboard_path_that_never_answered_200_did_not_run_its_handler(self):
        lines = [l.replace('"code": 200', '"code": 403') if '"/api/trace"' in l else l
                 for l in full_run(1, "dashboard")]
        invalid = self.judge(lines)[1]
        self.assertEqual(len(invalid), 1)
        self.assertIn("/api/trace was never answered 200 (403 x1)", invalid[0])

    def test_a_path_only_the_per_source_cap_refused_is_not_a_dead_handler(self):
        lines = [l.replace('"code": 200', '"code": 503') if '"/api/trace"' in l else l
                 for l in full_run(1, "dashboard")]
        self.assertEqual(self.judge(lines), ([], []))
        lines = [l.replace('"code": 200', '"code": 401') if '"/api/trace"' in l else l
                 for l in full_run(1, "dashboard")]
        self.assertIn("/api/trace was never answered 200 (401 x1)", self.judge(lines)[1][0])
        lines = [l for l in full_run(1, "dashboard") if '"/api/trace"' not in l]
        self.assertIn("/api/trace was never answered 200 (never asked)", self.judge(lines)[1][0])

    def test_idle_needs_only_the_always_on_polls(self):
        self.assertEqual([p for p, _, _ in hl.polls_for("idle")],
                         ["/api/status", "/api/cdr", "/api/admin/status", "/api/ota/status"])
        self.assertEqual([p for p, _, _ in hl.polls_for("dashboard")], [p for p, _, _ in hl.POLLS])
        lines = [l for l in full_run(1, "idle") if '"/api/moh"' not in l and '"/api/trace"' not in l]
        self.assertEqual(self.judge(lines), ([], []))


# ---------------------------------------------------------------- the generator, on a server with the board's cap
class _Server(ThreadingHTTPServer):
    request_queue_size = 64                                 # a burst must not overflow the SYN backlog


class CapServer:
    """GET only. /api/status holds each request `hold` s and answers 503 beyond `cap` in flight (the board does
    that per source); the gated paths answer 401 without the session cookie. Every request is logged."""

    GATED = ("/api/cdr", "/api/trace", "/api/moh")

    def __init__(self, cap=3, hold=0.05):
        self.cap, self.hold, self.active, self.peak, self.refused = cap, hold, 0, 0, 0
        self.log, self.lock = [], threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"                   # closes after each response, as the board's does

            def reply(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                cookie = "pd_session=" in self.headers.get("Cookie", "")
                with outer.lock:
                    outer.log.append((self.path, cookie))
                if self.path == "/api/status":
                    with outer.lock:
                        busy = outer.active >= outer.cap
                        if busy:
                            outer.refused += 1
                        else:
                            outer.active += 1
                            outer.peak = max(outer.peak, outer.active)
                    if busy:
                        return self.reply(503, {"error": "busy"})
                    try:
                        time.sleep(outer.hold)
                    finally:
                        with outer.lock:
                            outer.active -= 1
                    return self.reply(200, {"uptime": 7200, "freeHeapInternal": 50000, "minFreeHeapInternal": 39483,
                                            "stackHwm_http_conn": 1552, "httpConnWorstRoute": "GET /api/status"})
                if self.path in CapServer.GATED and not cookie:
                    return self.reply(401, {"error": "authentication required"})
                return self.reply(200, {})

            def log_message(self, *a):
                pass

        self.httpd = _Server(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def paths(self):
        return collections.Counter(p for p, _ in list(self.log))


class RunLoadTest(unittest.TestCase):
    def setUp(self):
        self.srv = CapServer()
        self.addCleanup(self.srv.stop)

    def window(self, mode, seconds, watch=None, **over):
        cfg = dict(hl.DEFAULTS, warm_s=0.05, probe_polls=5, burst_workers=6, burst_each=4)
        cfg.update(over)
        sink = hl.Sink()
        load = self.load = hl.RunLoad(hl.getter("127.0.0.1", self.srv.port), sink, 1, mode, cookie="0123abcd")
        load.window(cfg, time.monotonic() + seconds, watch)
        sink.add(load.meta(1))
        return hl.read_log(sink.lines)

    def test_a_run_logs_every_request_and_reads_the_status_fields(self):
        recs = self.window("idle", 1.5)
        reqs = [r for r in recs if r["k"] == "req"]
        by_label = collections.Counter(r["label"] for r in reqs)
        self.assertEqual((by_label["before"], by_label["after"], by_label["probe"]), (1, 1, 5))
        self.assertEqual(by_label["burst"], 24)
        stats = [r for r in recs if r["k"] == "status"]
        self.assertEqual({s["label"] for s in stats} >= {"before", "after", "probe"}, True)
        self.assertEqual(stats[0]["stackHwm_http_conn"], 1552)
        self.assertEqual(recs[-1]["probe"], [5, 5])
        self.assertEqual(recs[-1]["burst"], [24, 24])
        self.assertEqual(sum(1 for r in reqs if r["label"] == "probe" and r["code"] == 200), 5)
        self.assertTrue(all(r["ms"] >= self.srv.hold * 1000 - 5 for r in reqs if r["label"] == "probe"))

    def test_a_burst_wider_than_the_cap_is_refused_and_every_refusal_is_counted(self):
        recs = self.window("idle", 1.5)
        refused = [r for r in recs if r["k"] == "req" and r["code"] == 503]
        self.assertGreaterEqual(len(refused), 1, "6 clients against a cap of 3 must see 503s")
        self.assertEqual(len(refused), self.srv.refused, "the client counted exactly the 503s the server sent")
        self.assertTrue(all(r["label"] in ("burst", "poll") for r in refused))
        s = hl.run_stats(hl.per_run(recs)[0])
        self.assertEqual(s["refused"], self.srv.refused)
        self.assertGreaterEqual(s["peak"], 2)
        self.assertLessEqual(self.srv.peak, 3)

    def test_the_pollers_send_the_session_and_the_probe_and_burst_do_not(self):
        self.window("dashboard", 1.5)
        status_with, status_without = (sum(1 for p, c in list(self.srv.log) if p == "/api/status" and c == want)
                                       for want in (True, False))
        self.assertEqual(status_with, 1, "only the dashboard's own status poll carries the cookie")
        self.assertEqual(status_without, 1 + 1 + 5 + 24, "before, after, 5 probes, 24 burst requests")
        for path in ("/api/cdr", "/api/trace", "/api/moh"):
            self.assertTrue(all(c for p, c in list(self.srv.log) if p == path), path)

    def test_idle_polls_the_always_on_four_and_the_dashboard_all_six(self):
        self.window("idle", 0.4)
        seen = self.srv.paths()
        self.assertEqual({p for p in seen if p != "/api/status"}, {"/api/cdr", "/api/admin/status", "/api/ota/status"})
        self.srv.log.clear()
        self.window("dashboard", 0.4)
        self.assertEqual(set(self.srv.paths()), {p for p, _, _ in hl.POLLS})

    def test_the_poll_rates_are_the_dashboards(self):
        self.window("dashboard", 2.3, probe_polls=1, burst_workers=1, burst_each=1)
        polls = collections.Counter(p for p, c in list(self.srv.log) if c)
        # t = 0, then every period: status 0, 2 s; trace 0, 1.5 s; the rest once
        self.assertEqual((polls["/api/status"], polls["/api/trace"]), (2, 2))
        self.assertEqual((polls["/api/cdr"], polls["/api/admin/status"], polls["/api/ota/status"],
                          polls["/api/moh"]), (1, 1, 1, 1))

    def test_bursting_is_set_for_the_burst_and_only_then(self):
        seen = []
        self.window("idle", 1.5, watch=lambda: seen.append(self.load.bursting.is_set()))
        self.assertIn(True, seen, "the caller's watch can see the burst is on")
        self.assertIn(False, seen)
        self.assertFalse(self.load.bursting.is_set())
        self.assertEqual(self.load.done["burst"], 24)

    def test_a_watch_that_raises_stops_every_thread_and_the_error_comes_out(self):
        ticks = []

        def watch():
            ticks.append(time.monotonic())
            if len(ticks) > 3:
                raise RuntimeError("phantom")
        with self.assertRaises(RuntimeError):
            self.window("dashboard", 5.0, watch=watch)
        n = len(self.srv.log)
        time.sleep(0.4)
        self.assertEqual(len(self.srv.log), n, "no request after the window was torn down")


# ---------------------------------------------------------------- the whole scenario, on the anchor tests' fake board
class LoadBoard(base.FakeProbeBoard):
    """FakeProbeBoard (an answered anchor call, the BYE, the drop lines) plus the dashboard's routes and the
    memory fields /api/status carries on main."""

    def __init__(self):
        super().__init__("h947")
        self.deny_trace, self.reboot_on_trace, self.reads = False, False, 0

    def _call_h947(self, c):
        self.initiated(c)
        if self.knobs.get("refuse"):
            self.refuse(c, 503)
            return self.drop(c)                          # the board drops the leg it opened
        self.answer(c)

    def public_status(self):
        st = super().public_status()
        self.reads += 1
        st.update(freeHeapInternal=50000 - 100 * (self.reads % 7), minFreeHeapInternal=39483,
                  largestFreeBlockInternal=26612, stackHwm_http_conn=1552, httpConnWorstRoute="GET /api/status",
                  httpPerSourceRefusals=0, httpReadDeadlineDrops=0, httpStatusRefusals=0)
        return st

    def http_get(self, path):
        if path == "/api/trace":
            if self.reboot_on_trace:
                self.uptime_base = 100
            return (403, {"error": "owner privilege required"}) if self.deny_trace else (200, [])
        if path == "/api/cdr":
            return (200, [])
        if path in ("/api/admin/status", "/api/ota/status"):
            return (200, {})
        return super().http_get(path)


class ScenarioRunTest(unittest.TestCase):
    assert_no_secret_anywhere = base.RunTest.assert_no_secret_anywhere
    FAST = {"hold_s": 3.0, "gap_s": 0.1, "settle_s": 0.5}
    SMALL = ("--window-s", "1.2", "--probe-polls", "6", "--burst-workers", "2", "--burst-each", "3", "--repeats", "1")

    def setUp(self):
        self.board = LoadBoard().start()
        self.http_port = self.board.serve_http()
        self.addCleanup(self.board.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        warm = mock.patch.dict(hl.DEFAULTS, warm_s=0.1)
        warm.start()
        self.addCleanup(warm.stop)

    def go(self, *extra, overrides=None, env=None):
        def no_logger(argv, out_path):
            raise AssertionError("the scenario started a status logger: its polls would be load on the thing measured")
        argv = cli("--port", str(self.board.port), "--http-port", str(self.http_port), "--local-ip", "127.0.0.1",
                   "--syslog-port", "0", "--set-syslog", "--pin-check-s", "0.05", "--out", self.tmp.name,
                   "--expect-version", base.PROBE_VERSION, *self.SMALL, *extra)
        rc, out = base.run_main(argv, env or base.base_env(), start_logger=no_logger,
                                overrides=dict(self.FAST, **(overrides or {})), run_defaults=base.FAST_RUN)
        dirs = [d for d in os.listdir(self.tmp.name) if os.path.isdir(os.path.join(self.tmp.name, d))]
        self.assertEqual(len(dirs), 1, out)
        self.res = os.path.join(self.tmp.name, dirs[0])
        with open(os.path.join(self.res, "manifest.json"), encoding="utf-8") as f:
            self.manifest = json.load(f)
        return rc, out

    def log(self):
        with open(os.path.join(self.res, "http-load.jsonl"), encoding="utf-8") as f:
            return hl.read_log(f.read().splitlines())

    def poll_paths(self, run):
        return {r["path"] for r in self.log() if r["k"] == "req" and r["run"] == run and r["label"] == "poll"}

    def test_idle_and_dashboard_pass_without_a_call(self):
        rc, out = self.go("--http-modes", "idle,dashboard")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.manifest["verdict"], "PASS")
        self.assertEqual(self.board.invite_users, [], "no ring without dashboard-call")
        self.assertNotIn("RING-REQUIRED", out)
        self.assertEqual(self.poll_paths(1), {"/api/status", "/api/cdr", "/api/admin/status", "/api/ota/status"})
        self.assertEqual(self.poll_paths(2), {p for p, _, _ in hl.POLLS})
        self.assertEqual([m["mode"] for m in self.log() if m["k"] == "run"], ["idle", "dashboard"])
        for name in ("http-load.jsonl", "http-summary.txt"):
            self.assertTrue(os.path.exists(os.path.join(self.res, name)), name)
        self.assertFalse(os.path.exists(os.path.join(self.res, "status.jsonl")))
        with open(os.path.join(self.res, "http-summary.txt"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("mode idle: 1 run(s)", text)
        self.assertIn("mode dashboard: 1 run(s)", text)
        self.assertRegex(text, r"stack high-water: stackHwm_http_conn 1552 B free of 4096 B \(2544 B used\), "
                               r"httpConnWorstRoute \"GET /api/status\"; source http-load.jsonl line \d+ ")
        self.assertEqual(len(self.manifest["summary"]["runs"]), 2)
        self.assertEqual(self.manifest["params"]["no_status_logger"], True)
        self.assert_no_secret_anywhere(out)

    def test_a_held_call_is_one_invite_one_bye_and_a_window_inside_it(self):
        rc, out = self.go("--http-modes", "dashboard-call")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.board.invite_users, [FAR], "exactly one ring")
        self.assertIn("RING-REQUIRED", out)
        with open(os.path.join(self.res, "calls.json"), encoding="utf-8") as f:
            calls = json.load(f)
        self.assertEqual(len(calls), 1)
        self.assertEqual((calls[0]["final"], calls[0]["hangup_bye"], calls[0]["call"]), (200, 200, 1))
        self.assertFalse(calls[0].get("ended_early"))
        self.assertLessEqual(calls[0]["duration_s"], an.MAX_CALL_S)
        self.assertEqual(self.manifest["log_counters"]["initiated"], 1)
        self.assertEqual(self.manifest["log_counters"]["dropped"], 1)
        recs = self.log()
        self.assertGreaterEqual(sum(1 for r in recs if r["k"] == "req" and r["label"] == "safety"), 1,
                                "the S1 checkpoints made during the call are counted as load")
        self.assertEqual(self.poll_paths(1), {p for p, _, _ in hl.POLLS})
        meta = [r for r in recs if r["k"] == "run"][0]
        self.assertEqual((meta["call"], meta["answered"]), (1, True))
        self.assertEqual(self.board.bindings, {}, "both test UAs de-registered")
        self.assert_no_secret_anywhere(out)

    def test_no_s1_checkpoint_is_made_while_the_burst_holds_the_slots(self):
        seen, loads = [], []
        checkpoint, window = an.AnchorRun.checkpoint, hl.RunLoad.window

        def spy(run_self):
            seen.append(bool(loads and loads[-1].bursting.is_set()))
            return checkpoint(run_self)

        def stash(load_self, *a, **kw):
            loads.append(load_self)
            return window(load_self, *a, **kw)
        with mock.patch.object(an.AnchorRun, "checkpoint", spy), mock.patch.object(hl.RunLoad, "window", stash):
            rc, out = self.go("--http-modes", "dashboard-call", "--burst-workers", "3", "--burst-each", "40")
        self.assertEqual(rc, 0, out)
        self.assertGreater(len(seen), 3, "the checkpoints went on all through the call")
        self.assertNotIn(True, seen, "one was made during the burst")
        self.assertEqual(loads[-1].done["burst"], 120, "and the burst did run")

    def test_the_run_loop_stops_at_the_cap_even_if_the_plan_is_longer(self):
        real = hl.RunBudget
        with mock.patch.object(hl, "RunBudget", lambda cap: real(1)):
            rc, out = self.go("--http-modes", "idle,dashboard")
        self.assertEqual(rc, an.EXIT["INVALID"], out)
        self.assertIn("run 2 is past --run-cap 1", out)
        self.assertEqual({m["run"] for m in self.log()}, {1}, "nothing ran past the cap")
        self.assertEqual(self.board.invite_users, [])

    def test_a_call_the_far_end_does_not_answer_is_invalid(self):
        self.board.knobs["refuse"] = True
        rc, out = self.go("--http-modes", "dashboard-call")
        self.assertEqual(rc, an.EXIT["INVALID"], out)
        self.assertIn("the far end did not answer (final 503)", out)

    def test_a_reboot_inside_a_run_is_a_fail(self):
        self.board.reboot_on_trace = True
        rc, out = self.go("--http-modes", "dashboard")
        self.assertEqual(rc, an.EXIT["FAIL"], out)
        self.assertIn("the board rebooted, so both watermarks restarted", out)

    def test_a_poll_the_board_refuses_means_the_handler_never_ran(self):
        self.board.deny_trace = True
        rc, out = self.go("--http-modes", "dashboard")
        self.assertEqual(rc, an.EXIT["INVALID"], out)
        self.assertIn("/api/trace was never answered 200 (403 x", out)


# ---------------------------------------------------------------- the claims the harness makes about the firmware
class DriftTest(unittest.TestCase):
    """Constants and tables the harness copies from the firmware are pinned to their source, so a change there
    fails here instead of quietly misreporting."""

    def test_the_poll_table_is_index_html_hs(self):
        html = read("src/Helpers/index_html.h")
        interval = {"/api/status": "setInterval(fetchStatus,%d)", "/api/cdr": "setInterval(fetchCdr,%d)",
                    "/api/admin/status": "setInterval(fetchAdminStatus,%d)",
                    "/api/ota/status": "fetchOtaStatus();},%d)", "/api/trace": "setInterval(pollTrace,%d)",
                    "/api/moh": "fetchMohStatus();},%d)"}
        self.assertEqual(sorted(interval), sorted(p for p, _, _ in hl.POLLS))
        for path, period, _ in hl.POLLS:
            self.assertIn(interval[path] % int(period * 1000), html, path)
            self.assertIn('fetch("%s"' % path, html, path)
        self.assertIn('$("pbx-modal").classList.contains("show"))fetchMohStatus()', html)    # moh: panel open only
        self.assertEqual([p for p, _, always in hl.POLLS if not always], ["/api/trace", "/api/moh"])

    def test_the_stack_and_per_source_constants_are_the_firmwares(self):
        hpp = read("src/Helpers/HttpServer.hpp")
        self.assertEqual(int(re.search(r"kHttpConnStackBytes\s*=\s*(\d+)", hpp).group(1)), hl.STACK_BYTES)
        total = int(re.search(r"kMaxConcurrentConnections\s*=\s*(\d+)", hpp).group(1))
        self.assertIn("kMaxConnectionsPerSource = kMaxConcurrentConnections - 1", hpp)
        self.assertEqual(total - 1, hl.PER_SOURCE_CAP)

    def test_every_field_it_reads_is_one_sendApiStatus_writes(self):
        cpp = read("src/Helpers/HttpServer.cpp")
        for field in hl.FIELDS:
            self.assertIn(field, cpp, field)

    def test_the_numbers_it_says_the_board_does_not_emit_are_not_in_the_status_json(self):
        cpp = read("src/Helpers/HttpServer.cpp")
        body = cpp[cpp.index("void HttpServer::sendApiStatus"):]
        body = body[:body.index("\n}\n")]
        for absent in ("activeConnections", "peakConnections", "busyRefusals", "peakConcurrent"):
            self.assertNotIn(absent, body, absent)


if __name__ == "__main__":
    unittest.main()

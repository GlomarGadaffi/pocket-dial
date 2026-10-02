#!/usr/bin/env python3
"""Self-test for tools/soak/soak_verdict.py (#401). Runs in CI:

    python3 -m unittest discover -s tests/tools -p 'test_soak_verdict.py'

Each case builds a synthetic one-hour 1 Hz log (durations scaled down from the
real 4 h), breaks exactly one thing, and asserts that exactly that check fails.
A clean run must pass every check, so a check that fires on healthy data is
caught too. No board, no build.
"""

import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools", "soak"))
import soak_verdict as sv  # noqa: E402

T0 = 1_800_000_000


def cfg():
    c = sv.default_config()
    c.min_duration_s = 3000
    c.warmup_s = 300
    c.min_idle_samples = 50
    return c


def status(uptime, sessions=None, heap=120000, min_heap=60000, block=40000, hwm=1500,
           reason="POWERON", coredump=None):
    return {
        "uptime": uptime,
        "resetReason": reason,
        "freeHeapInternal": heap,
        "minFreeHeapInternal": min_heap,
        "largestFreeBlockInternal": block,
        "sessions": sessions or [],
        "parkedCalls": [],
        "clientCount": 4,
        "recvErrors": 0,
        "stackHwm_sip_server_task": hwm,
        "stackHwm_http_conn": None,     # a task that never ran reports null
        "coredump": coredump or {"present": False, "size": 0},
    }


def call(i, start):
    return [{"caller": "201", "callee": "777", "state": "CONNECTED",
             "duration": "%02d:%02d" % divmod(i - start, 60)}]


def clean_run(seconds=3600, every=120, length=30):
    """A 30 s call every 2 min, stopping 2 min before the end."""
    out = []
    for i in range(seconds):
        start = i - (i % every)
        busy = (i % every) < length and i < seconds - 120
        out.append((float(T0 + i), status(100 + i, sessions=call(i, start) if busy else None)))
    return out


def failed(samples, bad=0):
    return {name for name, ok, _ in sv.evaluate(samples, bad, cfg()) if not ok}


class SoakVerdictTest(unittest.TestCase):
    def test_a_clean_run_passes_every_check(self):
        checks = sv.evaluate(clean_run(), 0, cfg())
        self.assertEqual({n for n, ok, _ in checks if not ok}, set(), checks)
        self.assertTrue(sv.verdict(checks))

    def test_a_reboot_fails_no_reboot(self):
        s = clean_run()
        for i in range(1800, len(s)):
            t, st = s[i]
            st["uptime"] = 5 + (i - 1800)
        self.assertEqual(failed(s), {"no-reboot"})

    def test_a_changed_reset_reason_fails_no_reboot(self):
        s = clean_run()
        s[-1][1]["resetReason"] = "PANIC"
        self.assertEqual(failed(s), {"no-reboot"})

    def test_an_idle_heap_leak_fails_heap_stable(self):
        s = clean_run()
        for i, (t, st) in enumerate(s):
            st["freeHeapInternal"] = 120000 - 2 * i     # 7.2 KB/h
        self.assertEqual(failed(s), {"heap-stable"})

    def test_a_heap_dip_during_calls_is_not_a_leak(self):
        s = clean_run()
        for t, st in s:
            if st["sessions"]:
                st["freeHeapInternal"] = 90000          # calls cost memory; idle recovers
        self.assertEqual(failed(s), set())

    def test_a_low_minimum_fails_heap_floor(self):
        s = clean_run()
        s[-1][1]["minFreeHeapInternal"] = 9000
        self.assertEqual(failed(s), {"heap-floor"})

    def test_fragmentation_fails_on_a_small_idle_block(self):
        s = clean_run()
        s[2000][1]["largestFreeBlockInternal"] = 4096
        self.assertTrue(not s[2000][1]["sessions"])
        self.assertEqual(failed(s), {"fragmentation"})

    def test_a_session_that_never_ends_fails_no_stuck_leg(self):
        s = clean_run()
        for i in range(1000, 1500):
            s[i][1]["sessions"] = call(i, 1000)          # 499 s old by the end
        self.assertEqual(failed(s), {"no-stuck-leg"})

    def test_a_call_still_up_at_the_end_fails_quiet_tail(self):
        s = clean_run()
        for i in range(len(s) - 30, len(s)):
            s[i][1]["sessions"] = call(i, len(s) - 30)
        self.assertEqual(failed(s), {"quiet-tail"})

    def test_failed_polls_fail_sampling(self):
        self.assertEqual(failed(clean_run(), bad=100), {"sampling"})

    def test_a_long_gap_fails_sampling(self):
        s = clean_run()
        del s[2000:2060]
        self.assertEqual(failed(s), {"sampling"})

    def test_a_new_coredump_fails(self):
        s = clean_run()
        for i in range(2000, len(s)):
            s[i][1]["coredump"] = {"present": True, "size": 47264}
        self.assertEqual(failed(s), {"no-new-coredump"})

    def test_an_old_coredump_that_does_not_change_passes(self):
        s = clean_run()
        for t, st in s:
            st["coredump"] = {"present": True, "size": 47264}
        self.assertEqual(failed(s), set())

    def test_a_board_without_a_coredump_partition_fails_unless_accepted(self):
        # #531: supported:false means no crash could ever leave a core, so a
        # "no new coredump" pass would prove nothing.
        s = clean_run()
        for t, st in s:
            st["coredump"] = {"supported": False, "present": False, "size": 0}
        self.assertEqual(failed(s), {"no-new-coredump"})
        c = cfg()
        c.allow_no_coredump = True
        self.assertEqual({n for n, ok, _ in sv.evaluate(s, 0, c) if not ok}, set())

    def test_supported_true_is_judged_as_before(self):
        s = clean_run()
        for t, st in s:
            st["coredump"] = {"supported": True, "present": False, "size": 0}
        self.assertEqual(failed(s), set())
        for i in range(2000, len(s)):
            s[i][1]["coredump"] = {"supported": True, "present": True, "size": 47264}
        self.assertEqual(failed(s), {"no-new-coredump"})

    def test_a_stack_below_the_floor_fails(self):
        s = clean_run()
        s[1234][1]["stackHwm_sip_server_task"] = 400
        self.assertEqual(failed(s), {"stack-margin"})

    def test_too_short_a_run_fails_duration(self):
        self.assertEqual(failed(clean_run(seconds=2000)), {"duration"})

    def test_the_identity_free_shape_is_judged_the_same(self):
        # #539: an unauthenticated poll gets sessionCount/oldestSessionSec and an
        # empty sessions array. Busy/idle and stuck-leg must still work.
        s = clean_run()
        for t, st in s:
            live = st["sessions"]
            st["sessionCount"] = len(live)
            st["oldestSessionSec"] = sv._duration_s(live[0]["duration"]) if live else 0
            st["sessions"] = []
        self.assertEqual(failed(s), set())
        for i in range(1000, 1500):
            s[i][1]["sessionCount"] = 1
            s[i][1]["oldestSessionSec"] = i - 1000
        self.assertEqual(failed(s), {"no-stuck-leg"})

    def test_load_reads_logger_lines_and_counts_failed_polls(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "log.jsonl")
            with open(path, "w", encoding="utf-8") as f:
                f.write(json.dumps({"t": T0 + 1, "s": status(11)}) + "\n")
                f.write(json.dumps({"t": T0, "s": status(10)}) + "\n")
                f.write('{"t":%d,"s":null}\n' % (T0 + 2))
                f.write('{"t":%d,"s":null,"code":503}\n' % (T0 + 3))
                # An older logger wrote a refusal body as if it were a sample
                # (#537 review): it has no uptime, so it is a failed poll.
                f.write(json.dumps({"t": T0 + 4, "s": {"error": "busy",
                                    "message": "too many concurrent connections"}}) + "\n")
                f.write("not json\n")
                f.write("\n")
            samples, bad = sv.load(path)
        self.assertEqual(len(samples), 2)
        self.assertEqual(bad, 4)
        self.assertEqual([st["uptime"] for _, st in samples], [10, 11], "sorted by t")


# ---------------------------------------------------------------- #401 item 0.4
def results(samples, bad=0, **kw):
    return sv.assess(samples, bad, cfg(), **kw)


def failing(res):
    return {c["name"] for c in res if c["judged"] and not c["ok"]}


def by_name(res):
    return {c["name"]: c for c in res}


def idle_run(seconds=3600):
    return clean_run(seconds=seconds, every=120, length=0)


def quiesce_run(regs_at_quiesce=4, leaked_session=False):
    """60 s pre-roll (the post-boot baseline), calls until +3000 s, registrations
    held until +3300 s, then de-registered."""
    out = []
    for i in range(3600):
        start = i - ((i - 60) % 120)
        busy = 60 <= i < 3000 and ((i - 60) % 120) < 30
        st = status(100 + i, sessions=call(i, start) if busy else None)
        st["clientCount"] = 4 if i < 3000 else (regs_at_quiesce if i < 3300 else 0)
        if leaked_session and 3280 <= i < 3295:
            st["sessions"] = call(i, 3280)
        out.append((float(T0 + i), st))
    return out


def report(**kw):
    r = {"profile": "rc1", "pass": True, "dry_run": False, "exts": ["6101", "6102", "6103", "6104"],
         "load_end_at": T0 + 3000, "last_call_end_at": T0 + 2990, "quiesce_check_at": T0 + 3290,
         "registrations": {"planned": 256, "attempted": 256, "ok": 256, "failed": 0},
         "scenarios": {"echo777": {"planned": 37, "attempted": 37, "ok": 37, "failed": 0},
                       "ext_call": {"planned": 12, "attempted": 12, "ok": 12, "failed": 0}}}
    r.update(kw)
    return r


class VerdictHardeningTest(unittest.TestCase):
    def test_the_verdict_is_pass_fail_or_invalid(self):
        self.assertEqual(sv.overall(results(clean_run())), "PASS")
        self.assertEqual(sv.overall(results(clean_run(seconds=2000))), "INVALID", "too short to judge")
        s = clean_run()
        del s[2000:2060]
        self.assertEqual(sv.overall(results(s)), "INVALID", "a 60 s poll gap")
        self.assertEqual(sv.overall(results(clean_run(), bad=100)), "INVALID", "failed polls")
        r = clean_run()
        for i in range(1800, len(r)):
            r[i][1]["uptime"] = 5 + (i - 1800)
        self.assertEqual(sv.overall(results(r)), "FAIL")
        short = clean_run(seconds=2000)
        for i in range(1000, len(short)):
            short[i][1]["uptime"] = 5 + (i - 1000)
        self.assertEqual(sv.overall(results(short)), "FAIL", "a reboot outranks a short run")

    def test_every_judged_numeric_check_reports_its_margin(self):
        res = by_name(results(clean_run()))
        for name in ("duration", "sampling", "no-stuck-leg", "heap-stable", "heap-floor",
                     "fragmentation", "stack-margin", "recv-errors", "load-delivered"):
            self.assertIsNotNone(res[name]["margin"], name)
            self.assertIsNotNone(res[name]["limit"], name)
        self.assertEqual(res["heap-floor"]["margin"], 60000 - 16384)
        self.assertEqual(res["stack-margin"]["margin"], 1500 - 512)
        self.assertEqual(res["no-stuck-leg"]["margin"], 180 - 29)

    def test_the_heap_trend_carries_a_confidence_interval(self):
        s = clean_run()
        for i, (t, st) in enumerate(s):
            st["freeHeapInternal"] = 120000 - 2 * i + (i % 7) * 40      # 7.2 KB/h and some noise
        _, pts = sv.heap_trend(s, cfg())
        slope, lo, hi = (x * 3600 for x in sv._slope_ci(pts, 1.96))
        self.assertLess(lo, slope)
        self.assertLess(slope, hi)
        self.assertLess(hi, 0, "a confident leak")
        self.assertIn("95% CI", by_name(results(s))["heap-stable"]["detail"])

    def test_missing_data_fails(self):
        s = clean_run()
        for i in range(500, 510):
            del s[i][1]["recvErrors"]
        self.assertEqual(failing(results(s)), {"data-complete"})
        s = clean_run()
        del s[1500][1]["freeHeapInternal"]
        self.assertEqual(failing(results(s)), {"data-complete"})
        self.assertIn("freeHeapInternal (1)", by_name(results(s))["data-complete"]["detail"])

    def test_an_idle_board_does_not_pass(self):
        self.assertEqual(failing(results(idle_run())), {"load-delivered"})

    def test_a_load_below_schedule_or_with_failures_fails(self):
        s = quiesce_run()
        self.assertEqual(failing(results(s, load_report=report())), set())
        short = report(scenarios={"ext_call": {"planned": 12, "attempted": 9, "ok": 9, "failed": 0}})
        self.assertEqual(failing(results(s, load_report=short)), {"load-delivered"})
        bad = report(scenarios={"ext_call": {"planned": 12, "attempted": 12, "ok": 10, "failed": 2}})
        self.assertEqual(failing(results(s, load_report=bad)), {"load-delivered"})
        res = results(s, load_report=report(dry_run=True))
        self.assertEqual(sv.overall(res), "INVALID")

    def test_a_report_without_any_call_on_this_board_fails(self):
        self.assertIn("load-delivered", failing(results(idle_run(), load_report=report())))

    def test_stack_drop_vs_the_previous_release(self):
        self.assertFalse(by_name(results(clean_run()))["stack-drop"]["judged"], "no baseline, not judged")
        prev = {"stackLows": {"stackHwm_sip_server_task": 1700}}       # was 1700 free, now 1500
        self.assertEqual(failing(results(clean_run(), baseline=prev)), {"stack-drop"})
        prev = {"stackLows": {"stackHwm_sip_server_task": 1600}}       # 100 B: within 128
        self.assertEqual(failing(results(clean_run(), baseline=prev)), set())

    def test_recv_errors_must_not_move(self):
        s = clean_run()
        for i in range(2000, len(s)):
            s[i][1]["recvErrors"] = 1
        self.assertEqual(failing(results(s)), {"recv-errors"})

    def test_a_503_fails(self):
        self.assertEqual(failing(results(clean_run(), codes={503: 2})), {"http-503"})
        self.assertEqual(failing(results(clean_run(), codes={0: 3})), set(), "a timeout is not a 503")

    def test_pool_exhausted_syslog_lines_fail(self):
        lines = ["boot ok\n", "888 conference: message pool exhausted, leg unwound\n"]
        self.assertEqual(failing(results(clean_run(), syslog_lines=lines)), {"pool-exhausted"})
        self.assertEqual(failing(results(clean_run(), syslog_lines=["440 media: session pool full, rejected 6101"])),
                         {"pool-exhausted"})
        self.assertEqual(failing(results(clean_run(), syslog_lines=["anchor restart: reclaiming socket pool"])),
                         set())

    def test_the_idle_quiesce_gate(self):
        res = by_name(results(quiesce_run(), load_report=report()))
        self.assertTrue(res["idle-quiesce"]["ok"], res["idle-quiesce"]["detail"])
        self.assertIn("firmware gaps", res["idle-quiesce"]["detail"])
        self.assertEqual(failing(results(quiesce_run(regs_at_quiesce=3), load_report=report())),
                         {"idle-quiesce"}, "registrations must be exactly 4")
        self.assertEqual(failing(results(quiesce_run(leaked_session=True), load_report=report())),
                         {"idle-quiesce"}, "a session still up after 200 s")
        early = report(last_call_end_at=T0 + 3200)          # only 90 s before the quiesce sample
        self.assertEqual(sv.overall(results(quiesce_run(), load_report=early)), "INVALID")
        self.assertFalse(by_name(results(quiesce_run()))["idle-quiesce"]["judged"])


class FixtureLogTest(unittest.TestCase):
    """Done-when: each fixture log, through the CLI, trips exactly its criterion."""

    def run_cli(self, samples, extra=()):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "log.jsonl")
            with open(path, "w", encoding="utf-8") as f:
                for t, st in samples:
                    f.write(json.dumps({"t": t, "s": st}) + "\n")
            import contextlib
            import io
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = sv.main([path, "--min-hours", str(3000 / 3600), "--warmup-s", "300", "--json", *extra])
        out = json.loads(buf.getvalue())
        return rc, {c["name"] for c in out["checks"] if c["judged"] and not c["ok"]}, out

    def test_each_fixture_trips_exactly_its_criterion(self):
        reboot = clean_run()
        for i in range(1800, len(reboot)):
            reboot[i][1]["uptime"] = 5 + (i - 1800)
        leak = clean_run()
        for i, (t, st) in enumerate(leak):
            st["freeHeapInternal"] = 120000 - 2 * i
        stale = clean_run()
        for i in range(1000, 1500):
            stale[i][1]["sessions"] = call(i, 1000)
        gaps = clean_run()
        del gaps[2000:2060]
        cases = [("reboot", reboot, {"no-reboot"}, 1), ("leak", leak, {"heap-stable"}, 1),
                 ("stale session", stale, {"no-stuck-leg"}, 1), ("gaps", gaps, {"sampling"}, 3),
                 ("short run", clean_run(seconds=2000), {"duration"}, 3),
                 ("idle board", idle_run(), {"load-delivered"}, 1)]
        for name, samples, want, code in cases:
            with self.subTest(name):
                rc, bad, out = self.run_cli(samples)
                self.assertEqual(bad, want)
                self.assertEqual(rc, code)
                self.assertEqual(out["verdict"], {1: "FAIL", 3: "INVALID"}[code])
        rc, bad, out = self.run_cli(clean_run())
        self.assertEqual((rc, bad, out["verdict"]), (0, set(), "PASS"))
        self.assertEqual(len(out["firmwareGaps"]), 3)
        self.assertEqual(out["stackLows"], {"stackHwm_sip_server_task": 1500})

    def test_an_unreadable_input_is_invalid(self):
        with tempfile.TemporaryDirectory() as d:
            import contextlib
            import io
            with contextlib.redirect_stdout(io.StringIO()):
                rc = sv.main([os.path.join(d, "missing.jsonl")])
        self.assertEqual(rc, 3)


if __name__ == "__main__":
    unittest.main()

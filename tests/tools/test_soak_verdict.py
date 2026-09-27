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
                f.write("not json\n")
                f.write("\n")
            samples, bad = sv.load(path)
        self.assertEqual(len(samples), 2)
        self.assertEqual(bad, 2)
        self.assertEqual([st["uptime"] for _, st in samples], [10, 11], "sorted by t")


if __name__ == "__main__":
    unittest.main()

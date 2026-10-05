#!/usr/bin/env python3
"""Self-test for the #401 load profile (tests/load/sip_stress.py --profile). Runs in CI:

    python3 -m unittest discover -s tests/tools -p 'test_load_profile.py'

Everything runs against tests/load/fake_pbx.py on 127.0.0.1 with a fake clock,
so a 600 s profile takes about a second. No board, no build, no other network.
"""
import contextlib
import copy
import datetime
import io
import json
import os
import signal
import socket
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "load"))
import load_profile as lp  # noqa: E402
import sip_agent  # noqa: E402
import sip_stress  # noqa: E402
from fake_pbx import FakePbx  # noqa: E402

EXTS = ["6101", "6102", "6103", "6104"]
OWNER = "4242,4243"          # fictional owner extensions
CHECKOUT = "https://github.com/GlomarGadaffi/pocket-dial/discussions/428#discussioncomment-1"


def expiry(seconds_from_now):
    t = datetime.datetime.fromtimestamp(time.time() + seconds_from_now, datetime.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def args(port, *extra, duration=600, checkout=True, exts=EXTS, owner=OWNER):
    a = ["--profile", "rc1", "--host", "127.0.0.1", "--port", str(port), "--local-ip", "127.0.0.1",
         "--exts", ",".join(exts), "--duration", str(duration), "--no-rtp"]
    if owner is not None:
        a += ["--owner-ext", owner]
    if checkout:
        a += ["--checkout-url", CHECKOUT, "--checkout-expiry", expiry(7200)]
    return a + list(extra)


def run(argv, **kw):
    lines = []
    rc = lp.main(argv, out=lines.append, **kw)
    return rc, "\n".join(lines)


def rc1():
    return copy.deepcopy(lp.PROFILES["rc1"])


def burst_gaps(plan):
    b = plan["bursts"]
    return [nxt["t"] - prev["end"] for prev, nxt in zip(b, b[1:])]


class SampledClock(lp.FakeClock):
    """A fake clock that records how many UAs the (fake) board has registered.

    Every wait_until() first takes an entry (fake time, clientCount) and records its
    target; snap() adds the final one. registered_at(T) is the last entry with time <= T:
    the board's count AFTER everything the harness did at fake instant T. That is the worst
    case for a status poll stamped the same second as a de-REGISTER, and the soak logger
    produces it: tools/soak/status_logger.sh stamps whole seconds (date -u +%s) BEFORE a
    curl that may take 2 s, so a poll up to about a second after quiesce_check_at is still
    stamped t <= quiesce_check_at, which is what soak_verdict.py's idle-quiesce gate keeps.
    stop_at: set the stop event (a SIGTERM) when a wait reaches that fake time.
    """

    def __init__(self, pbx, stop_at=None):
        super().__init__()
        self.pbx, self.stop_at = pbx, stop_at
        self.states, self.targets = [], []

    def snap(self):
        self.states.append((self.t, self.pbx.status()["clientCount"]))

    def wait_until(self, t):
        self.snap()
        self.targets.append(t)
        if self.stop_at is not None and t >= self.stop_at:
            self.stop.set()
        return super().wait_until(t)

    def registered_at(self, instant):
        return [n for s, n in self.states if s <= instant][-1]


@mock.patch.dict(os.environ, {"PD_OWNER_EXTS": ""})
class PlanTest(unittest.TestCase):
    def check_shape(self, plan, duration):
        self.assertTrue(all(g >= 30 for g in burst_gaps(plan)), burst_gaps(plan))
        self.assertTrue(all(b["end"] <= duration for b in plan["bursts"]))
        for b in plan["bursts"]:
            used = [u for ev in b["events"] for u in ev["uas"]]
            self.assertEqual(len(used), len(set(used)), "a UA is in two calls of one burst: %r" % b)

    def test_ten_minutes_runs_every_scenario_once_or_more_with_idle_gaps(self):
        plan = lp.make_plan(rc1(), 600, 210)
        self.assertEqual(plan["counts"], {"echo777": 6, "ext_call": 2, "conf888": 1, "park_moh": 1})
        self.check_shape(plan, 600)
        self.assertEqual(len(plan["registers"]), 4 * 14, "4 UAs, every 60 s, until load + quiesce")
        self.assertEqual(lp.plan_problems(plan), [])

    def test_one_hour_keeps_the_cadence(self):
        plan = lp.make_plan(rc1(), 3600, 210)
        c = plan["counts"]
        self.assertEqual((c["ext_call"], c["conf888"], c["park_moh"]), (12, 4, 3))
        skipped = sum(1 for s in plan["skipped"] if s["scenario"] == "echo777")
        self.assertEqual(c["echo777"] + skipped, 60, "every 777 slot is either run or skipped")
        self.assertEqual(plan["dropped"], [])
        self.assertGreater(plan["idle_fraction"], 0.5, "the heap verdict needs idle samples")
        self.check_shape(plan, 3600)

    def test_five_hour_soak_uses_the_same_table(self):
        plan = lp.make_plan(rc1(), 18000, 210)
        c = plan["counts"]
        self.assertEqual((c["ext_call"], c["conf888"], c["park_moh"]), (60, 20, 15))
        self.check_shape(plan, 18000)

    def test_too_short_a_load_is_refused(self):
        rc, out = run(args(5060, duration=120))
        self.assertEqual(rc, 2)
        self.assertIn("never runs", out)

    def test_a_collision_defers_the_longer_row_and_skips_the_echo(self):
        prof = rc1()
        prof["scenarios"][2]["first_s"] = 20       # conf888 (3 UAs) ...
        prof["scenarios"][3]["first_s"] = 20       # ... and park (2 UAs) with the first 777
        plan = lp.make_plan(prof, 600, 210)
        # conf takes 3 of the 4 UAs for [20, 83]; park waits for the 30 s gap.
        self.assertIn({"scenario": "park_moh", "occurrence": 0, "due": 20, "t": 113},
                      plan["deferred"])
        self.assertIn(20, [s["t"] for s in plan["skipped"] if s["scenario"] == "echo777"])
        self.check_shape(plan, 600)

    def test_the_numbers_live_in_the_table(self):
        prof = rc1()
        prof["scenarios"][1]["every_s"] = 150     # extension calls twice as often
        plan = lp.make_plan(prof, 3600, 210)
        dropped = sum(1 for d in plan["dropped"] if d["scenario"] == "ext_call")
        self.assertEqual(plan["counts"]["ext_call"] + dropped, 24, "24 slots, each run or dropped")
        self.assertGreaterEqual(plan["counts"]["ext_call"], 23)
        self.check_shape(plan, 3600)

    def test_limits_from_the_firmware_are_enforced(self):
        prof = rc1()
        prof["scenarios"][3]["parked_s"] = 85      # past the 90 s park timeout
        prof["scenarios"][1]["hold_s"] = 200       # past the 180 s stuck-leg limit
        problems = " ".join(lp.validate_profile(prof))
        self.assertIn("park timeout", problems)
        self.assertIn("stuck-leg", problems)


@mock.patch.dict(os.environ, {"PD_OWNER_EXTS": ""})
class SafetyTest(unittest.TestCase):
    def problems(self, prof=None, exts=EXTS, owner=frozenset({"4242", "4243"})):
        return " | ".join(lp.safety_problems(prof or rc1(), list(exts), owner))

    def test_the_default_table_is_clean(self):
        self.assertEqual(self.problems(), "")

    def test_911_and_933_targets_are_refused(self):
        for target in ("911", "933", "9911"):
            prof = rc1()
            prof["scenarios"][0]["target"] = target
            self.assertIn("emergency number", self.problems(prof), target)

    def test_an_emergency_digit_run_in_a_test_extension_is_refused(self):
        self.assertIn("emergency number", self.problems(exts=["6101", "6102", "6103", "1933"]))

    def test_the_anchored_line_is_refused(self):
        prof = rc1()
        prof["scenarios"][2]["target"] = "555"
        p = self.problems(prof)
        self.assertIn("anchored outside line", p)
        self.assertIn("not in the allowlist", p)

    def test_trunk_shaped_and_uri_targets_are_refused(self):
        for target in ("0000000000", "sip:888@example.invalid"):
            prof = rc1()
            prof["scenarios"][2]["target"] = target
            self.assertIn("not a 2-6 digit local number", self.problems(prof), target)

    def test_owner_phones_are_refused_as_targets_and_as_test_uas(self):
        self.assertIn("owner's phones", self.problems(exts=["6101", "6102", "6103", "4242"]))
        prof = rc1()
        prof["scenarios"][0]["target"] = "4243"
        p = self.problems(prof)
        self.assertIn("owner's phones", p)
        self.assertIn("not in the allowlist", p)

    def test_a_missing_owner_list_is_refused_and_none_is_explicit(self):
        self.assertIn("no owner-phone list", " ".join(lp.safety_problems(rc1(), EXTS, None)))
        self.assertEqual(lp.parse_owner("none", None), set())
        self.assertEqual(lp.parse_owner(None, "4242, 4243"), {"4242", "4243"})
        self.assertIsNone(lp.parse_owner(None, ""))

    def test_test_extensions_must_be_given_unique_and_not_service_numbers(self):
        self.assertIn("exactly 4", self.problems(exts=[]))
        self.assertIn("duplicates", self.problems(exts=["6101", "6101", "6102", "6103"]))
        self.assertIn("service number", self.problems(exts=["6101", "6102", "6103", "777"]))
        self.assertIn("service number", self.problems(exts=["6101", "6102", "6103", "705"]))

    def test_a_refused_run_sends_nothing(self):
        pbx = FakePbx().start()
        try:
            rc, out = run(args(pbx.port, exts=["6101", "6102", "6103", "9110"]),
                          clock=lp.FakeClock(), status_fn=pbx.status)
            self.assertEqual(rc, 2)
            self.assertIn("REFUSED", out)
            time.sleep(0.3)
            self.assertEqual(pbx.packets, 0)
        finally:
            pbx.stop()

    def test_the_owner_list_can_come_from_the_environment(self):
        with mock.patch.dict(os.environ, {"PD_OWNER_EXTS": "6104"}):
            rc, out = run(args(5060, owner=None, checkout=False) + ["--dry-run"])
        self.assertEqual(rc, 2)
        self.assertIn("owner's phones", out)


@mock.patch.dict(os.environ, {"PD_OWNER_EXTS": ""})
class CheckoutTest(unittest.TestCase):
    def test_a_valid_checkout_passes(self):
        self.assertEqual(lp.checkout_problems(CHECKOUT, expiry(3600), time.time(), 1000), [])

    def test_a_missing_checkout_refuses_and_sends_nothing(self):
        pbx = FakePbx().start()
        try:
            rc, out = run(args(pbx.port, checkout=False), clock=lp.FakeClock(), status_fn=pbx.status)
            self.assertEqual(rc, 2)
            self.assertIn("no CHECK-OUT", out)
            time.sleep(0.3)
            self.assertEqual(pbx.packets, 0)
        finally:
            pbx.stop()

    def test_bad_links_and_expiries_are_refused(self):
        now = time.time()
        cases = [
            ("https://github.com/GlomarGadaffi/pocket-dial/discussions/294#discussioncomment-1",
             expiry(3600), "not a discussion #428"),
            (CHECKOUT, expiry(-60), "expired"),
            (CHECKOUT, expiry(600), "before this run would end"),
            (CHECKOUT, "2026-10-01T22:00", "with a zone"),
            (CHECKOUT, None, "no --checkout-expiry"),
        ]
        for url, exp, want in cases:
            self.assertIn(want, " ".join(lp.checkout_problems(url, exp, now, 1000)), (url, exp))

    def test_the_checkout_must_outlive_the_dereg_grace_too(self):
        # The planned end is load + quiesce + the held-registered grace; END_MARGIN_S is slack
        # PAST it. An expiry that clears the old end + margin by 10 s but not the grace is refused.
        quiesce = lp.PROFILES["rc1"]["quiesce_s"]
        short = expiry(600 + quiesce + lp.END_MARGIN_S + 10)
        rc, out = run(args(5060, "--dry-run", "--checkout-url", CHECKOUT, "--checkout-expiry", short,
                           checkout=False))
        self.assertEqual(rc, 0, out)
        self.assertIn("before this run would end", out)
        rc, out = run(args(5060, "--dry-run", "--checkout-url", CHECKOUT,
                           "--checkout-expiry", expiry(7200), checkout=False))
        self.assertEqual(rc, 0, out)
        self.assertIn("[ok]", out)
        self.assertRegex(out, r"then \d+ s of registrations only, then \d+ s held registered, "
                              r"then de-register", "the plan print names the grace")

    def test_dry_run_needs_no_checkout_and_sends_nothing(self):
        pbx = FakePbx().start()
        try:
            with tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "plan.json")
                rc, out = run(args(pbx.port, "--dry-run", "--report", path, checkout=False))
                with open(path, encoding="utf-8") as f:
                    rep = json.load(f)
            self.assertEqual(rc, 0, out)
            self.assertIn("a real run refuses", out)
            self.assertIn("+0:00:20", out)
            self.assertTrue(rep["dry_run"])
            self.assertEqual(rep["schedule"]["counts"]["park_moh"], 1)
            time.sleep(0.3)
            self.assertEqual(pbx.packets, 0)
        finally:
            pbx.stop()


@mock.patch.dict(os.environ, {"PD_OWNER_EXTS": ""})
class RunTest(unittest.TestCase):
    def setUp(self):
        self.pbx = FakePbx().start()
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "r.json")

    def tearDown(self):
        self.pbx.stop()
        self.tmp.cleanup()

    def go(self, *extra, clock=None, status_fn="pbx", duration=600):
        sf = self.pbx.status if status_fn == "pbx" else status_fn
        rc, out = run(args(self.pbx.port, "--report", self.path, *extra, duration=duration),
                      clock=clock or lp.FakeClock(), status_fn=sf)
        with open(self.path, encoding="utf-8") as f:
            return rc, out, json.load(f)

    def test_done_when_a_600_s_rc1_run_passes_against_the_fake_pbx(self):
        rc, out, rep = self.go()
        self.assertEqual(rc, 0, out)
        self.assertTrue(rep["pass"])
        for name, s in rep["scenarios"].items():
            self.assertGreaterEqual(s["attempted"], 1, name)
            self.assertEqual(s["failed"], 0, (name, s["failures"]))
            self.assertLessEqual(abs(s["attempted"] - s["planned"]), 1, name)
            self.assertEqual(s["ok"], s["attempted"], name)
        self.assertEqual(rep["scenarios"]["echo777"]["codes"], {"INVITE/200": 12, "BYE/200": 12})
        self.assertEqual(rep["scenarios"]["park_moh"]["notes"].get("moh_offered"), 1)
        regs = rep["registrations"]
        self.assertEqual((regs["failed"], regs["ok"], regs["deregistered"]), (0, regs["planned"], 4))
        self.assertEqual(self.pbx.bindings, {}, "every test UA de-registered at the end")
        self.assertEqual(self.pbx.sessions, {}, "no leg left up")
        self.assertIn("LOAD VERDICT: PASS", out)

    def test_every_invite_on_the_wire_was_in_the_allowlist(self):
        rc, out, rep = self.go()
        allow = set(EXTS) | {"777", "888"} | {str(n) for n in range(700, 710)}
        self.assertEqual(rc, 0, out)
        self.assertTrue(self.pbx.invite_users)
        self.assertLessEqual(set(self.pbx.invite_users), allow, self.pbx.invite_users)

    def test_refused_extension_calls_fail_the_run(self):
        self.pbx.reject_ext = 486
        rc, out, rep = self.go()
        self.assertEqual(rc, 1)
        s = rep["scenarios"]["ext_call"]
        self.assertEqual(s["failed"], s["planned"])
        self.assertEqual(s["codes"].get("INVITE/486"), s["planned"])
        self.assertIn("LOAD VERDICT: FAIL", out)

    def test_an_unregistered_callee_is_never_called(self):
        self.pbx.register_status["6102"] = 403
        rc, out, rep = self.go()
        self.assertEqual(rc, 1)
        self.assertNotIn("6102", self.pbx.invite_users)
        errors = json.dumps(rep["scenarios"]["ext_call"]["failures"])
        self.assertIn("6102 is not registered by this run", errors)
        self.assertGreater(rep["registrations"]["failed"], 0)

    def test_park_is_refused_while_the_board_holds_a_parked_call(self):
        self.pbx.parked_count_override = 1
        rc, out, rep = self.go()
        self.assertEqual(rc, 1)
        self.assertNotIn("709", self.pbx.invite_users)
        self.assertIn("already holds 1 parked", json.dumps(rep["scenarios"]["park_moh"]["failures"]))

    def test_park_is_refused_without_a_status_source(self):
        rc, out, rep = self.go(status_fn=lambda: None)
        self.assertEqual(rc, 1)
        self.assertNotIn("709", self.pbx.invite_users)

    def test_a_stop_mid_run_hangs_up_and_deregisters(self):
        class StopAt(lp.FakeClock):
            def wait_until(self, t):
                if t >= 300:
                    self.stop.set()
                return super().wait_until(t)
        rc, out, rep = self.go(clock=StopAt())
        self.assertEqual(rc, 1)
        self.assertTrue(rep["interrupted"])
        self.assertEqual(rep["registrations"]["deregistered"], 4)
        self.assertEqual(self.pbx.bindings, {})
        self.assertEqual(self.pbx.sessions, {})

    def test_the_test_uas_are_still_registered_at_quiesce_check_at(self):
        # The 1 h Elite run's only FAIL: the UAs de-registered at +3901 s, the quiesce sample
        # (+3900 s) saw registrations 0 (want exactly 4). Every sample stamped <= quiesce_check_at
        # must see them: a second before it, at it, and up to a second after it.
        clock = SampledClock(self.pbx)
        rc, out, rep = self.go(clock=clock)
        clock.snap()
        q = rep["quiesce_check_at"] - clock.base
        self.assertEqual(rc, 0, out)
        self.assertEqual(q, 600 + lp.PROFILES["rc1"]["quiesce_s"], "quiesce_check_at is unchanged")
        for dt in (-1, 0, 0.9):
            n = clock.registered_at(q + dt)
            self.assertEqual(n, len(EXTS),
                             "the board counted %d registrations at quiesce_check_at %+.1f s (want %d): "
                             "the final de-REGISTER came too soon" % (n, dt, len(EXTS)))
        self.assertEqual(rep["registrations"]["deregistered"], len(EXTS))
        self.assertEqual(self.pbx.bindings, {}, "and they are all gone at the end")

    def test_an_interrupted_run_deregisters_at_once_and_never_waits_out_the_grace(self):
        q = 600 + lp.PROFILES["rc1"]["quiesce_s"]
        # mid-run; in the quiesce wait; in the held-registered wait after it (the plan and the
        # quiesce sample are done by then, so that stop is not an interruption of the plan)
        for stop_at, interrupted, last_wait in ((300, True, q), (q, True, q), (q + 1, False, None)):
            with self.subTest(stop_at=stop_at):
                clock = SampledClock(self.pbx, stop_at=stop_at)
                rc, out, rep = self.go(clock=clock)
                self.assertEqual(rep["interrupted"], interrupted)
                self.assertLessEqual(clock.t, q, "the clock never sat through the grace")
                if last_wait is not None:       # a stop before the grace wait must not even start one
                    self.assertLessEqual(max(clock.targets), last_wait, clock.targets[-3:])
                self.assertEqual(rep["registrations"]["deregistered"], len(EXTS))
                self.assertEqual(self.pbx.bindings, {})
                self.assertEqual(self.pbx.sessions, {})

    @unittest.skipUnless(hasattr(signal, "SIGTERM") and os.name == "posix", "POSIX signals")
    def test_sigterm_mid_run_still_cleans_up(self):
        class TermAt(lp.FakeClock):
            def wait_until(self, t):
                if t >= 300 and not self.stop.is_set():
                    os.kill(os.getpid(), signal.SIGTERM)
                    time.sleep(0.05)
                return super().wait_until(t)
        before = signal.getsignal(signal.SIGTERM)
        rc, out, rep = self.go(clock=TermAt())
        self.assertEqual(rc, 1)
        self.assertTrue(rep["interrupted"])
        self.assertEqual(self.pbx.bindings, {})
        self.assertIs(signal.getsignal(signal.SIGTERM), before, "the handler is restored")

    def test_sip_stress_delegates_the_profile_and_keeps_its_exit_code(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = sip_stress.main(args(self.pbx.port, "--dry-run", checkout=False))
        self.assertEqual(rc, 0)
        self.assertIn("DRY RUN", buf.getvalue())


class AgentTest(unittest.TestCase):
    def test_parse_compact_and_folded_headers(self):
        m = sip_agent.SipMsg.parse(
            b"SIP/2.0 200 OK\r\nv: SIP/2.0/UDP 127.0.0.1:5;branch=z9hG4bKx\r\ni: abc\r\n"
            b"t: <sip:6101@h>;tag=t1\r\nCSeq: 7\r\n INVITE\r\nl: 4\r\n\r\nbodyEXTRA")
        self.assertEqual((m.status, m.method, m.call_id(), m.body), (200, "INVITE", "abc", "body"))
        self.assertEqual(sip_agent.tag_of(m.get("to")), "t1")

    def test_rtp_pump_sends_and_counts(self):
        a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        a.bind(("127.0.0.1", 0))
        b.bind(("127.0.0.1", 0))
        pump = sip_agent.RtpPump()
        try:
            sa = pump.add(a, b.getsockname(), True)
            sb = pump.add(b, None, False)
            time.sleep(0.3)
            tx, _ = pump.remove(sa)
            _, rx = pump.remove(sb)
        finally:
            pump.stop()
            a.close()
            b.close()
        self.assertGreater(tx, 3)
        self.assertGreater(rx, 3)


if __name__ == "__main__":
    unittest.main()

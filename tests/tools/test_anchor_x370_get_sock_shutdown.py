#!/usr/bin/env python3
"""Host tests for the x370_get_sock_shutdown scenario (tests/load/anchor_scenarios.py, #370, #350).

The scenario arms the bench probe's get_sock_shutdown fault (docs/BENCH_PROBE.md) beside get_status=404 and
get_max_attempts=8, places one short ring, and reads the board's own log: the fault shuts down the socket the
rx task just published, the header read finds no response, and the loop rebuilds its GET handle and pays a fresh
handshake. It reuses the x370_pressure_rebuild judge, witness and path, counts the witness only from the shutdown
on, and wants the `applied` line to show rc=0. These pin what decides a verdict without a board: the
registration, the never-dial gate, the order of arm / (hold) / call / (release) against a stub run, the witness
and verdict arithmetic on sample logs, the counters' regexes against the firmware's own line, and the docs. The
end-to-end run against a fake board is X370SockShutdownTest in test_anchor_scenarios.py.

No stub: each test looks up the symbol it needs and fails by assertion when it is not there yet.

    python3 -m unittest discover -s tests/tools -p 'test_anchor_x370_get_sock_shutdown.py'
"""
import inspect
import os
import re
import sys
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "load"))
sys.path.insert(0, HERE)
import anchor_scenarios as an  # noqa: E402
import test_anchor_x370_pressure_rebuild as sib  # noqa: E402

REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
CLIENT = os.path.join(REPO, "src", "SIP", "TelephonyAnchorClient.cpp")
SCENARIOS = os.path.join(REPO, "tests", "load", "anchor_scenarios.py")
BENCH_DOC = os.path.join(REPO, "docs", "BENCH_PROBE.md")
HARNESS_DOC = os.path.join(REPO, "docs", "TEST_HARNESS.md")

NAME = "x370_get_sock_shutdown"
FAR = sib.FAR                    # a fictional far end, as the siblings use
FAR2 = "15550107373"             # another fictional one
FAULTS = ("get_sock_shutdown", "get_status", "get_max_attempts")
BALLAST = {"ballast_bytes": 16384, "ballast_deadman_s": 35}      # a test config, not a registered scenario
APPLIED_TEXT = "BENCHFAULT get_sock_shutdown applied: shutdown(SHUT_RDWR) on the published GET socket, rc=%d"
FIRED = "W (1) BenchProbe: BENCHFAULT get_sock_shutdown fired"
fail, ready, NO_REBUILD, GIVEUP3 = sib.fail, sib.ready, sib.NO_REBUILD, sib.GIVEUP3
INITIATED = "I (1) TelephonyAnchor: Successfully initiated call to <x> (own leg 41)"
RX_STARTED = "I (1) TelephonyAnchor: Rx stream task started for participant 41"
DROPPED = "I (1) TelephonyAnchor: Successfully dropped participant 41"


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def applied(rc=0):
    return "W (1) TelephonyAnchor: " + APPLIED_TEXT % rc


def need(*names):
    """The symbols of anchor_scenarios.py this test rests on: an assertion failure, not an exception, if absent."""
    missing = [n for n in names if not hasattr(an, n)]
    if missing:
        raise AssertionError("tests/load/anchor_scenarios.py has no %s yet" % ", ".join(missing))
    return [getattr(an, n) for n in names]


def scenario():
    if NAME not in an.SCENARIOS:
        raise AssertionError("%s is not in SCENARIOS yet" % NAME)
    return an.SCENARIOS[NAME]


def witness(lines):
    """x370s_witness over [(t, line)], t = 1.0, 2.0, ... in order."""
    (fn,) = need("x370s_witness")
    return fn([(float(i + 1), ln) for i, ln in enumerate(lines)])


class RegistrationTest(unittest.TestCase):
    def test_it_is_a_one_call_probe_scenario_with_the_three_faults_pre_registered(self):
        sc = scenario()
        self.assertEqual((sc["probe"], tuple(sc["faults"]), sc["calls"], sc["max_calls"]), (True, FAULTS, 1, 1))
        self.assertEqual(sc["uas"], {"caller": "6101", "detector": "6104"})
        self.assertTrue(sc["ring_required"])
        self.assertEqual(sc["part_of"], "#370")
        self.assertEqual(tuple(sc["issues"]), ("#370", "#350"))
        self.assertEqual(an.scenario_problems(sc), [])

    def test_every_fault_it_arms_is_one_the_probe_has(self):
        self.assertTrue(set(scenario()["faults"]) <= set(an.PROBE_FAULTS))

    def test_the_path_counter_is_the_applied_line_not_the_failure_line(self):
        sc = scenario()
        self.assertEqual(sc["path_counter"], "get_sock_shutdown_applied")
        self.assertIn(sc["path_counter"], an.LOG_COUNTERS)

    def test_the_get_values_keep_the_loop_in_its_not_ready_retries_for_a_short_call(self):
        sc = scenario()
        self.assertEqual((sc["get_status"], sc["get_max_attempts"]), (404, 8))
        self.assertLessEqual(an.get_giveup_worst_s(sc["get_max_attempts"]), sc["call_cap_s"] - an.HANGUP_MARGIN_S)

    def test_it_has_no_ballast_so_nothing_squeezes_the_board_or_orphans_a_leg(self):
        sc = scenario()
        self.assertNotIn("ballast_bytes", sc)
        self.assertNotIn("ballast_deadman_s", sc)
        self.assertTrue(sc["sock_shutdown"])
        self.assertTrue(sc["no_status_logger"])

    def test_the_about_text_says_it_is_necessary_but_weaker_evidence_for_350(self):
        about = scenario()["about"]
        for needle in ("#350", "weaker", "necessary", "no ballast"):
            self.assertIn(needle, about)

    def test_it_is_wrapped_so_the_probe_is_finished_after_it(self):
        sc = scenario()
        self.assertEqual(sc["run"].__name__, "x370s_run")
        r = mock.Mock()

        def boom(run, sc_):
            raise RuntimeError("boom")
        with self.assertRaises(RuntimeError):
            an.probe_run(boom)(r, sc)
        r.probe_finish.assert_called_once_with()

    def test_one_ring_is_the_cap_and_thirty_seconds_the_call_cap(self):
        sc = scenario()
        self.assertTrue(any("calls must be 1-1" in p for p in an.scenario_problems(dict(sc, calls=2))))
        self.assertTrue(any("call_cap_s" in p for p in an.scenario_problems(dict(sc, call_cap_s=31))))

    def test_a_cancel_wait_past_the_invite_bound_is_refused_with_no_ballast_too(self):
        sc = dict(scenario(), call_fire_wait_s=15.0)
        self.assertTrue(any("INVITE bound" in p for p in an.scenario_problems(sc)))

    def test_a_get_budget_past_the_call_cap_is_refused(self):
        self.assertTrue(any("past the" in p for p in an.scenario_problems(dict(scenario(), get_max_attempts=40))))

    def test_a_fault_it_did_not_pre_register_is_refused_and_a_foreign_one_is_not_a_probe_fault(self):
        problems = an.scenario_problems(dict(scenario(), faults=FAULTS + ("ws_drop",)))
        self.assertTrue(any("ws_drop is not a bench probe fault" in p for p in problems), problems)

    def test_the_ballast_branch_takes_a_target_above_the_floor_and_checks_it_like_x370(self):
        sc = dict(scenario(), **BALLAST)
        self.assertEqual(an.scenario_problems(sc), [])
        self.assertTrue(any("floor" in p for p in an.scenario_problems(dict(sc, ballast_bytes=4096))))
        self.assertTrue(any("before the call can end" in p for p in an.scenario_problems(dict(sc, ballast_deadman_s=5))))
        self.assertTrue(any("1-600" in p for p in an.scenario_problems(dict(sc, ballast_deadman_s=601))))

    def test_the_sibling_scenario_is_unchanged(self):
        sibling = an.SCENARIOS["x370_pressure_rebuild"]
        self.assertEqual(tuple(sibling["faults"]), ("get_status", "get_max_attempts"))
        self.assertEqual((sibling["ballast_bytes"], sibling["ballast_deadman_s"]), (8192, 35))
        self.assertNotIn("sock_shutdown", sibling)
        self.assertEqual(sibling["path_counter"], "get_transport_fail")
        self.assertEqual(an.scenario_problems(sibling), [])
        self.assertTrue(any("floor" in p for p in an.scenario_problems(dict(sibling, ballast_bytes=4096))))
        self.assertTrue(any("INVITE bound" in p for p in
                            an.scenario_problems(dict(sibling, call_fire_wait_s=15.0, ballast_deadman_s=60))))

    def test_no_phone_number_is_hard_coded_in_the_scenario_or_its_functions(self):
        sc = scenario()
        for key, value in sc.items():
            if isinstance(value, str):
                self.assertIsNone(re.search(r"\+?\d{7,}", value), key)
        for fn in need("x370s_run", "x370s_witness", "x370s_path"):
            self.assertIsNone(re.search(r"\d{7,}", inspect.getsource(fn)), fn.__name__)


class GateTest(unittest.TestCase):
    def test_the_run_refuses_before_it_arms_holds_or_dials(self):
        (fn,) = need("x370s_run")
        for ends in (("911",), ("933",), ("113",), ("1001",), (FAR, "911")):
            for sc in (scenario(), dict(scenario(), **BALLAST)):
                with self.subTest(ends=ends, ballast="ballast_bytes" in sc):
                    caller = mock.Mock()
                    run = mock.Mock(far_ends=ends, far_end=ends[0], agents={"caller": caller})
                    with self.assertRaises(an.run_soak.Abort) as cm:
                        fn(run, sc)
                    self.assertEqual(cm.exception.verdict, "INVALID")
                    self.assertIn("before any arm, ballast or call", cm.exception.reason)
                    self.assertNotIn(ends[0], cm.exception.reason, "a refusal never echoes the number")
                    caller.invite.assert_not_called()
                    run.arm.assert_not_called()
                    run.hold_ballast.assert_not_called()

    def test_the_far_end_comes_from_the_run_and_the_call_goes_to_it(self):
        s = StubRun(self, ends=(FAR,))
        s.go()
        self.assertEqual(s.caller.invite.call_args.args, (FAR,))
        s2 = StubRun(self, ends=(FAR2,))
        s2.go()
        self.assertEqual(s2.caller.invite.call_args.args, (FAR2,))


class StubRun(sib.StubRun):
    """The sibling's stub run (every board-facing call recorded in `order`), driving x370s_run."""

    def go(self, sc=None):
        (fn,) = need("x370s_run")
        return fn(self.run, sc if sc is not None else scenario())


class SequencingTest(unittest.TestCase):
    def test_without_a_ballast_the_order_is_gate_three_arms_call_then_the_status_read(self):
        s = StubRun(self)
        s.go()
        self.assertEqual(s.order, ["checkpoint", "arm:get_sock_shutdown=None", "arm:get_status=404",
                                   "arm:get_max_attempts=8", "invite", "finish", "status", "after_call"])
        s.run.hold_ballast.assert_not_called()
        s.run.probe.release_ballast.assert_not_called()

    def test_the_new_fault_is_armed_before_the_invite_makecall_claims_the_leg_at_its_start(self):
        s = StubRun(self)
        s.go()
        self.assertLess(s.order.index("arm:get_sock_shutdown=None"), s.order.index("invite"))

    def test_with_a_ballast_every_arm_precedes_the_hold_and_the_hold_precedes_the_call(self):
        s = StubRun(self)
        s.go(dict(scenario(), **BALLAST))
        self.assertEqual(s.order, ["checkpoint", "arm:get_sock_shutdown=None", "arm:get_status=404",
                                   "arm:get_max_attempts=8", "hold", "invite", "finish", "release", "status",
                                   "after_call"])
        held = s.order[s.order.index("hold") + 1:s.order.index("release")]
        self.assertEqual(held, ["invite", "finish"], "nothing but the call between the hold and the release")

    def test_with_a_ballast_it_is_released_when_the_call_raises(self):
        s = StubRun(self, invite_raises=RuntimeError("the UA blew up mid-call"))
        with self.assertRaises(RuntimeError):
            s.go(dict(scenario(), **BALLAST))
        self.assertEqual(s.order[-2:], ["invite", "release"])
        self.assertNotIn("status", s.order)

    def test_with_a_ballast_it_is_released_when_a_fault_arm_is_refused(self):
        s = StubRun(self, arm_raises=an.run_soak.Abort("INVALID", "arming get_sock_shutdown: 409"))
        with self.assertRaises(an.run_soak.Abort):
            s.go(dict(scenario(), **BALLAST))
        self.assertEqual(s.order[-2:], ["arm:get_sock_shutdown=None", "release"])
        self.assertNotIn("hold", s.order)
        s.caller.invite.assert_not_called()

    def test_without_a_ballast_a_refused_arm_stops_before_the_call_and_releases_nothing(self):
        s = StubRun(self, arm_raises=an.run_soak.Abort("INVALID", "arming get_sock_shutdown: 409"))
        with self.assertRaises(an.run_soak.Abort):
            s.go()
        self.assertEqual(s.order, ["checkpoint", "arm:get_sock_shutdown=None"])
        s.caller.invite.assert_not_called()
        self.assertEqual(s.run.calls, [])

    def test_without_a_ballast_a_call_that_raises_propagates_and_releases_nothing(self):
        s = StubRun(self, invite_raises=RuntimeError("the UA blew up mid-call"))
        with self.assertRaises(RuntimeError):
            s.go()
        self.assertEqual(s.order[-1], "invite")
        self.assertNotIn("release", s.order)

    def test_one_call_one_invite_with_a_cancel_bounded_by_the_wait(self):
        s = StubRun(self)
        s.go()
        self.assertEqual(s.caller.invite.call_count, 1)
        kw = s.caller.invite.call_args.kwargs
        self.assertEqual(kw["cancel_when_timeout_s"], scenario()["call_fire_wait_s"])
        self.assertTrue(callable(kw["cancel_when"]))

    def test_the_post_call_status_is_judged_for_a_reboot(self):
        s = StubRun(self, status={"uptime": 5, "resetReason": "PANIC"})
        s.go()
        problems = s.run.calls[0]["alive_problems"]
        self.assertEqual(len(problems), 2)
        self.assertTrue(all("rebooted" in p for p in problems), problems)

    def test_the_call_record_is_kept_first_so_an_abort_keeps_it(self):
        s = StubRun(self, invite_raises=RuntimeError("boom"))
        with self.assertRaises(RuntimeError):
            s.go()
        self.assertEqual(len(s.run.calls), 1)


class WitnessTest(unittest.TestCase):
    def test_a_shutdown_then_a_failure_then_the_next_attempt_answered_is_a_rebuild_with_a_fresh_handshake(self):
        w = witness([FIRED, applied(0), fail(1), ready(2), ready(3)])
        self.assertEqual((w["applied"], w["rcs"], w["attempts"], w["rebuilt"], w["answered"]), (1, [0], 1, 1, 1))
        (path,) = need("x370s_path")
        self.assertEqual(path(w), ("rebuilt, the fresh handshake was answered", ""))

    def test_no_applied_line_is_invalid_even_with_a_failure_and_a_next_attempt(self):
        w = witness([FIRED, fail(1), ready(2)])
        self.assertEqual(w["applied"], 0)
        outcome, why = need("x370s_path")[0](w)
        self.assertIsNone(outcome)
        self.assertIn("0 'applied' lines", why)

    def test_an_rc_of_minus_one_means_no_shutdown_happened_so_a_failure_after_it_proves_nothing(self):
        w = witness([FIRED, applied(-1), fail(1), ready(2)])
        self.assertEqual(w["rcs"], [-1])
        outcome, why = need("x370s_path")[0](w)
        self.assertIsNone(outcome)
        self.assertIn("rc=-1", why)
        self.assertIn("no shutdown happened", why)

    def test_a_shutdown_with_no_failure_after_it_is_invalid_the_read_still_got_an_answer(self):
        w = witness([FIRED, applied(0), ready(1), ready(2)])
        outcome, why = need("x370s_path")[0](w)
        self.assertIsNone(outcome)
        self.assertIn("no transport failure followed", why)

    def test_a_failure_before_the_shutdown_is_not_the_faults_and_is_not_counted(self):
        w = witness([fail(1, how="open"), applied(0), ready(2), ready(3)])
        self.assertEqual(w["attempts"], 0)
        self.assertIsNone(need("x370s_path")[0](w)[0])

    def test_only_the_failure_after_the_shutdown_is_counted_when_one_came_before(self):
        w = witness([fail(1, how="open"), ready(2), applied(0), fail(3), ready(4)])
        self.assertEqual((w["attempts"], w["rebuilt"], w["answered"]), (1, 1, 1))

    def test_two_applied_lines_are_invalid_for_a_one_shot_fault(self):
        w = witness([applied(0), fail(1), ready(2), applied(0), fail(3), ready(4)])
        self.assertEqual(w["applied"], 2)
        outcome, why = need("x370s_path")[0](w)
        self.assertIsNone(outcome)
        self.assertIn("2 'applied' lines", why)

    def test_the_x370_arithmetic_still_decides_the_rest(self):
        path = need("x370s_path")[0]
        self.assertEqual(path(witness([applied(0), fail(1), fail(2, how="open")]))[0],
                         "rebuilt, the open after it failed again")
        outcome, why = path(witness([applied(0), fail(1)]))
        self.assertIsNone(outcome)
        self.assertIn("no next attempt after one and no 'could not rebuild' line", why)
        outcome, why = path(witness([applied(0), fail(1), NO_REBUILD]))
        self.assertIsNone(outcome)
        self.assertIn("the log cannot tell which", why)
        w = witness([applied(0), fail(1), ready(2), fail(3), fail(4), GIVEUP3])
        self.assertEqual((w["rebuilt"], w["giveups"]), (2, 1), "three in a row rebuild twice, the third gives up")
        self.assertEqual(path(w)[0], "rebuilt, the fresh handshake was answered")

    def test_attempts_of_another_budget_do_not_pair(self):
        self.assertEqual(witness([applied(0), fail(1, n=8), ready(2, n=12)])["rebuilt"], 0)


class CounterTest(unittest.TestCase):
    def test_the_applied_line_has_its_own_counter_and_counts_nothing_else(self):
        counts = an.count_lines([applied(0)])
        self.assertEqual({k: v for k, v in counts.items() if v}, {"get_sock_shutdown_applied": 1})

    def test_the_fired_line_counts_for_the_generic_and_the_named_counter_only(self):
        counts = an.count_lines([FIRED])
        self.assertEqual({k: v for k, v in counts.items() if v}, {"bench_fired": 1, "bench_get_sock_shutdown": 1})

    def test_the_rc_is_group_one_so_the_judge_can_read_it(self):
        rx = an._RX.get("get_sock_shutdown_applied")
        self.assertIsNotNone(rx, "no get_sock_shutdown_applied counter yet")
        self.assertEqual([rx.search(applied(rc)).group(1) for rc in (0, -1)], ["0", "-1"])

    def test_the_regex_is_the_line_the_firmware_prints(self):
        m = re.search(r'"(BENCHFAULT get_sock_shutdown applied[^"]*)"', read(CLIENT))
        self.assertIsNotNone(m, "the firmware line is not in TelephonyAnchorClient.cpp")
        for rc in (0, -1):
            counts = an.count_lines(["W (1) TelephonyAnchor: " + m.group(1) % rc])
            self.assertEqual(counts.get("get_sock_shutdown_applied"), 1, rc)


def judge_run(lines, final=487, cancel_status=200, alive_problems=(), sessions=None):
    """A run whose syslog is `lines` and whose one call ended as given: -> (run, call record)."""
    ents = [(float(i + 1), ln) for i, ln in enumerate(lines)]
    c = {"call": 1, "t_start": 0.0, "final": final, "cancel_status": cancel_status,
         "alive_problems": list(alive_problems),
         "sessions": sessions or {"baseline": 0, "after": 0, "test_ua_sessions": 0}}
    run = mock.Mock()
    run.calls = [c]
    run.agents = {"caller": types.SimpleNamespace(ext="6101"), "detector": types.SimpleNamespace(ext="6104")}
    run.syslog.entries.side_effect = lambda since=None, until=None: ents
    run.manifest = {"notes": [], "probe": {}}
    run.probe_before = run.probe_after = None
    run.pcap_count.return_value = 0
    return run, c


GOOD = [INITIATED, RX_STARTED, FIRED, applied(0), fail(1), ready(2), ready(3), DROPPED]


class JudgeTest(unittest.TestCase):
    def judge(self, lines, sc=None, **kw):
        run, c = judge_run(lines, **kw)
        fails, invalid, summary = an.x370_judge(run, sc if sc is not None else scenario(), lines)
        return fails, invalid, summary, run

    def test_a_clean_run_passes_with_the_rebuild_outcome_and_the_rc_in_the_summary(self):
        fails, invalid, summary, _ = self.judge(GOOD)
        self.assertEqual((fails, invalid), ([], []))
        self.assertEqual(summary["outcome"], "rebuilt, the fresh handshake was answered")
        self.assertEqual((summary["witness"]["applied"], summary["witness"]["rcs"]), (1, [0]))

    def test_an_rc_of_minus_one_is_invalid_never_pass_and_never_a_fail(self):
        fails, invalid, summary, _ = self.judge([INITIATED, RX_STARTED, FIRED, applied(-1), fail(1), ready(2), DROPPED])
        self.assertEqual(fails, [])
        self.assertTrue(any("rc=-1" in p for p in invalid), invalid)
        self.assertIsNone(summary["outcome"])

    def test_no_applied_line_is_invalid(self):
        fails, invalid, _, _ = self.judge([INITIATED, RX_STARTED, FIRED, fail(1), ready(2), DROPPED])
        self.assertEqual(fails, [])
        self.assertTrue(any("0 'applied' lines" in p for p in invalid), invalid)

    def test_a_shutdown_with_no_failure_after_it_is_invalid(self):
        fails, invalid, _, _ = self.judge([INITIATED, RX_STARTED, FIRED, applied(0), ready(1), ready(2), DROPPED])
        self.assertEqual(fails, [])
        self.assertTrue(any("no transport failure followed" in p for p in invalid), invalid)

    def test_a_failure_with_no_next_attempt_is_invalid(self):
        fails, invalid, _, _ = self.judge([INITIATED, RX_STARTED, FIRED, applied(0), fail(1), DROPPED])
        self.assertEqual(fails, [])
        self.assertTrue(any("no next attempt" in p for p in invalid), invalid)

    def test_a_panic_line_fails(self):
        fails, _, _, _ = self.judge(GOOD + ["E (1) boot: Guru Meditation Error: Core 1 panic'ed (LoadProhibited)"])
        self.assertTrue(any("a panic line reached the syslog" in p for p in fails), fails)

    def test_a_second_rx_task_on_the_leg_fails(self):
        fails, _, _, _ = self.judge(GOOD + [RX_STARTED])
        self.assertTrue(any("two rx tasks on one leg" in p for p in fails), fails)

    def test_a_possible_orphan_fails_and_is_noted(self):
        line = ("W (1) TelephonyAnchor: makeCall: request reached 3CX but no response and no reconcilable leg "
                "after 3 attempts — a call may be ORPHANED on 3CX (#349/#328)")
        fails, _, _, run = self.judge(GOOD + [line])
        self.assertTrue(any("possible ORPHAN" in p for p in fails), fails)
        self.assertTrue(any("ORPHAN WARNING" in n for n in run.manifest["notes"]))

    def test_a_cancel_not_answered_200_fails(self):
        fails, _, _, _ = self.judge(GOOD, cancel_status=481)
        self.assertTrue(any("CANCEL was answered 481, not 200" in p for p in fails), fails)

    def test_a_board_that_rebooted_fails(self):
        fails, _, _, _ = self.judge(GOOD, alive_problems=["uptime went 100 -> 5: the board rebooted"])
        self.assertTrue(any("rebooted" in p for p in fails), fails)

    def test_a_call_that_never_rang_is_invalid_and_says_nothing_of_a_ballast_when_none_is_held(self):
        fails, invalid, _, _ = self.judge([FIRED, applied(0), fail(1), ready(2)])
        self.assertEqual(fails, [])
        text = " ".join(invalid)
        self.assertIn("0 anchored legs started during the call, not 1", text)
        self.assertNotIn("ballast", text)

    def test_with_a_ballast_the_never_rang_reason_still_names_the_pressure(self):
        _, invalid, _, _ = self.judge([FIRED, applied(0), fail(1), ready(2)], sc=dict(scenario(), **BALLAST))
        self.assertIn("ballast", " ".join(invalid))

    def test_the_sibling_scenario_still_uses_its_own_witness_not_the_shutdown_one(self):
        lines = [INITIATED, RX_STARTED, fail(1), ready(2), DROPPED]       # no applied line: the ballast's own shape
        fails, invalid, summary, _ = self.judge(lines, sc=an.SCENARIOS["x370_pressure_rebuild"])
        self.assertEqual((fails, invalid), ([], []))
        self.assertEqual(summary["outcome"], "rebuilt, the fresh handshake was answered")
        self.assertNotIn("applied", summary["witness"])


class DocsTest(unittest.TestCase):
    def test_the_harness_doc_has_a_scenario_row_and_the_two_counter_rows(self):
        doc = read(HARNESS_DOC)
        self.assertRegex(doc, r"\|\s*`x370_get_sock_shutdown`\s*\|\s*#370, #350\s*\|")
        for counter in ("bench_get_sock_shutdown", "get_sock_shutdown_applied"):
            self.assertRegex(doc, r"\|\s*`%s`\s*\|" % counter)

    def test_the_row_says_weaker_evidence_for_350_and_that_rc_zero_is_part_of_the_pass(self):
        row = next((ln for ln in read(HARNESS_DOC).splitlines() if "`x370_get_sock_shutdown`" in ln
                    and ln.lstrip().startswith("|")), "")
        for needle in ("rc=0", "weaker", "#350"):
            self.assertIn(needle, row)

    def test_the_bench_doc_names_the_scenario_and_no_longer_says_none_arms_the_fault(self):
        doc = read(BENCH_DOC)
        self.assertIn("`x370_get_sock_shutdown`", doc)
        self.assertIsNone(re.search(r"no scenario\s+arms", doc), "a stale claim, corrected where it was made")

    def test_the_harness_source_no_longer_says_none_arms_the_fault(self):
        self.assertIsNone(re.search(r"no scenario\s+(?:#\s*)?arms", read(SCENARIOS)),
                          "tests/load/anchor_scenarios.py still says no scenario arms get_sock_shutdown")


if __name__ == "__main__":
    unittest.main()

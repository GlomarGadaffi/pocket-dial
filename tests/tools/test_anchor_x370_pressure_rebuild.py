#!/usr/bin/env python3
"""Host tests for the x370_pressure_rebuild scenario (tests/load/anchor_scenarios.py, #370).

The scenario holds a DRAM ballast at the bench probe's 8192 B floor across one ring, so the rx
task's rebuild of the GET handle (TelephonyAnchorClient.cpp, recreateGetClient) and the TLS
handshake after it run under pressure. These pin what decides a verdict without a board: the
never-dial gate, the witness arithmetic on the board's log, the order of arm / hold / call /
release against a stub run, the probe client's retry rules, and that the lines the witness
counts are the ones the firmware logs. The end-to-end run against a fake board is X370Test in
test_anchor_scenarios.py.

    python3 -m unittest discover -s tests/tools -p 'test_anchor_x370_pressure_rebuild.py'
"""
import os
import re
import sys
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "load"))
import anchor_scenarios as an  # noqa: E402

REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
CLIENT = os.path.join(REPO, "src", "SIP", "TelephonyAnchorClient.cpp")
LOGIC = os.path.join(REPO, "src", "SIP", "BenchProbeLogic.hpp")
SC = an.SCENARIOS["x370_pressure_rebuild"]
FAR = "15550104242"            # a fictional far end
EM_DASH = "—"


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def fail(k, n=8, how="transport"):
    if how == "open":
        return "W (1) TelephonyAnchor: GET stream open failed (ESP_ERR_HTTP_CONNECT), attempt %d/%d" % (k, n)
    return "W (1) TelephonyAnchor: GET stream transport failure (no HTTP response, status=-1), attempt %d/%d" % (k, n)


def ready(k, n=8, code=404):
    return "W (1) TelephonyAnchor: GET stream not ready (HTTP %d), attempt %d/%d" % (code, k, n)


GIVEUP3 = ("W (1) TelephonyAnchor: GET stream: 3 consecutive transport failures %s giving up rather than "
           "reopening a dead connection 5 more times" % EM_DASH)
NO_REBUILD = "W (1) TelephonyAnchor: GET stream: could not rebuild client after transport failure %s giving up" % EM_DASH


def witness(lines, cancel_t=None, times=None):
    """x370_witness over [(t, line)]; times defaults to 1.0, 2.0, ... in order."""
    ents = [(times[i] if times else float(i + 1), ln) for i, ln in enumerate(lines)]
    return an.x370_witness(ents, cancel_t)


class GateTest(unittest.TestCase):
    def test_the_never_dial_list_is_911_933_113_1001(self):
        self.assertEqual(an.X370_NEVER_DIAL, ("911", "933", "113", "1001"))

    def test_each_forbidden_number_is_refused_and_never_echoed(self):
        for n in ("911", "933", "113", "1001", "+911"):
            with self.subTest(n=n):
                problems = an.x370_destination_problems(n)
                self.assertTrue(any("x370 never-dial list" in p for p in problems), problems)
                self.assertNotIn(n.lstrip("+"), " ".join(problems))

    def test_an_emergency_far_end_in_any_form_is_refused(self):
        for n in ("9911", "+19335550100", "15559110000", "112", "999", "9933"):
            with self.subTest(n=n):
                self.assertTrue(an.x370_destination_problems(n), n)

    def test_a_valid_far_end_is_accepted(self):
        self.assertEqual(an.x370_destination_problems(FAR), [])
        self.assertEqual(an.x370_destination_problems("+" + FAR), [])

    def test_the_run_refuses_before_it_arms_holds_or_dials(self):
        for ends in (("911",), ("933",), ("113",), ("1001",), (FAR, "911")):
            with self.subTest(ends=ends):
                caller = mock.Mock()
                run = mock.Mock(far_ends=ends, far_end=ends[0], agents={"caller": caller})
                with self.assertRaises(an.run_soak.Abort) as cm:
                    an.x370_run(run, SC)
                self.assertEqual(cm.exception.verdict, "INVALID")
                self.assertIn("before any arm, ballast or call", cm.exception.reason)
                caller.invite.assert_not_called()
                run.arm.assert_not_called()
                run.hold_ballast.assert_not_called()
                run.probe.hold_ballast.assert_not_called()
                run.probe.release_ballast.assert_not_called()

    def test_the_ballast_hold_itself_refuses_a_never_dial_far_end(self):
        # AnchorRun.arm() covers faults only: the ballast has its own check (docs/BENCH_PROBE.md, rule 5)
        for far in ("911", "933", "9911", "112"):
            with self.subTest(far=far):
                me = types.SimpleNamespace(sc=SC, far_ends=(far,), probe=mock.Mock(), manifest={"probe": {}},
                                           say=lambda *a: None)
                with self.assertRaises(an.run_soak.Abort) as cm:
                    an.AnchorRun.hold_ballast(me)
                self.assertIn("never-dial", cm.exception.reason)
                me.probe.hold_ballast.assert_not_called()

    def test_a_ballast_the_scenario_did_not_pre_register_is_refused(self):
        me = types.SimpleNamespace(sc=dict(SC, ballast_bytes=0), far_ends=(FAR,), probe=mock.Mock(),
                                   manifest={"probe": {}}, say=lambda *a: None)
        with self.assertRaises(an.run_soak.Abort):
            an.AnchorRun.hold_ballast(me)
        me.probe.hold_ballast.assert_not_called()


class WitnessTest(unittest.TestCase):
    def test_no_failure_line_is_invalid_and_says_the_ballast_did_not_bite(self):
        w = witness([ready(1), ready(2), ready(3)])
        self.assertEqual(w, {"attempts": 0, "rebuilt": 0, "answered": 0, "failed": 0, "giveups": 0})
        outcome, why = an.x370_path(w)
        self.assertIsNone(outcome)
        self.assertIn("0 'transport failure' or 'open failed' lines", why)

    def test_a_failure_then_the_next_attempt_answered_is_a_rebuild_with_a_fresh_handshake(self):
        w = witness([fail(1), ready(2), ready(3)])
        self.assertEqual((w["attempts"], w["rebuilt"], w["answered"]), (1, 1, 1))
        self.assertEqual(an.x370_path(w), ("rebuilt, the fresh handshake was answered", ""))

    def test_a_failure_then_a_second_failure_is_a_rebuild_whose_open_failed_again(self):
        w = witness([fail(1), fail(2, how="open")])
        self.assertEqual((w["attempts"], w["rebuilt"], w["answered"]), (2, 1, 0))
        self.assertEqual(an.x370_path(w)[0], "rebuilt, the open after it failed again")

    def test_three_in_a_row_rebuilds_twice_and_the_third_gives_up_unrebuilt(self):
        w = witness([fail(1), fail(2), fail(3), GIVEUP3])
        self.assertEqual(w, {"attempts": 3, "rebuilt": 2, "answered": 0, "failed": 0, "giveups": 1})
        self.assertEqual(an.x370_path(w)[0], "rebuilt, the open after it failed again")

    def test_a_failure_alone_is_not_a_rebuild_witness(self):
        # the failure line is logged before recreateGetClient() runs: it proves the attempt, not that it worked
        w = witness([fail(1)])
        self.assertEqual((w["attempts"], w["rebuilt"], w["failed"]), (1, 0, 0))
        outcome, why = an.x370_path(w)
        self.assertIsNone(outcome)
        self.assertIn("no next attempt after one and no 'could not rebuild' line", why)

    def test_the_rebuild_giveup_line_is_the_failed_outcome(self):
        w = witness([fail(1), NO_REBUILD])
        self.assertEqual((w["attempts"], w["rebuilt"], w["failed"]), (1, 0, 1))
        self.assertEqual(an.x370_path(w)[0], "rebuild failed, the board gave up cleanly")

    def test_a_could_not_rebuild_after_the_cancel_is_the_teardown_not_the_path(self):
        # recreateGetClient() also returns false when stop was requested, and logs the same line
        lines = [fail(1), NO_REBUILD]
        self.assertEqual(witness(lines, cancel_t=1.5)["failed"], 0)         # the line came at t=2.0, after it
        self.assertEqual(witness(lines, cancel_t=2.5)["failed"], 1)
        self.assertIsNone(an.x370_path(witness(lines, cancel_t=1.5))[0])

    def test_the_last_attempt_has_no_next_attempt(self):
        w = witness([fail(8, n=8)])
        self.assertEqual(w["rebuilt"], 0)

    def test_attempts_of_another_budget_do_not_pair(self):
        self.assertEqual(witness([fail(1, n=8), ready(2, n=12)])["rebuilt"], 0)

    def test_the_rebuild_giveup_line_is_not_a_transport_failure_line(self):
        w = witness([NO_REBUILD, GIVEUP3])
        self.assertEqual((w["attempts"], w["giveups"]), (0, 1))

    def test_a_forced_refusal_of_any_status_is_an_answer(self):
        self.assertEqual(witness([fail(1), ready(2, code=403)])["answered"], 1)

    def test_the_path_counter_is_the_failure_line_and_not_the_x4_window(self):
        self.assertEqual(SC["path_counter"], "get_transport_fail")
        self.assertEqual(an.count_lines([fail(1), fail(2, how="open"), ready(3)])["get_transport_fail"], 2)
        self.assertEqual(an.count_lines([NO_REBUILD, GIVEUP3])["get_transport_fail"], 0)


class WiredToTheFirmwareTest(unittest.TestCase):
    """The witness counts what the firmware prints and rests on how the loop is built: pin both."""

    def setUp(self):
        self.src = read(CLIENT)
        self.logic = read(LOGIC)
        a = self.src.index("for (; attempt < kMaxAttempts && keepRunning(); ++attempt)")
        self.loop = self.src[a:self.src.index("if (!opened)", a)]

    def test_the_attempt_lines_are_the_ones_the_scenario_counts(self):
        fmt = {"transport": '"GET stream transport failure (no HTTP response, status=%d), attempt %d/%d"',
               "open": '"GET stream open failed (%s), attempt %d/%d"',
               "ready": '"GET stream not ready (HTTP %d), attempt %d/%d"'}
        for name, literal in fmt.items():
            with self.subTest(line=name):
                self.assertEqual(self.src.count(literal), 1, literal)
        self.assertEqual(self.src.count("%d consecutive transport failures"), 1)
        self.assertEqual(self.src.count("GET stream: could not rebuild client after transport failure"), 1)
        for line in (fail(3), fail(3, how="open"), ready(3)):
            self.assertTrue(an._RX["get_transport_fail"].search(line) or an._RX["get_answered"].search(line), line)

    def test_every_iteration_logs_one_attempt_line_and_none_skips_to_the_next(self):
        # attempt k+1 after a failure at k means recreateGetClient() returned true only while nothing else
        # leaves an iteration without a line or continues past one
        self.assertEqual(self.loop.count("attempt + 1, kMaxAttempts"), 3)
        self.assertNotIn("continue;", self.loop)

    def test_the_rebuild_follows_the_failure_line_unless_it_is_the_third_in_a_row(self):
        i_fail = self.loop.index("if (transportFailed)")
        i_third = self.loop.index("++transportFailures >= kMaxTransportFailures")
        i_recreate = self.loop.index("if (!recreateGetClient())")
        self.assertLess(i_fail, i_third)
        self.assertLess(i_third, i_recreate)
        self.assertRegex(self.src, r"constexpr int\s+kMaxTransportFailures\s*=\s*3;")
        self.assertEqual(self.src.count("recreateGetClient()"), 1, "one call; the lambda is a variable")

    def test_a_rebuild_that_worked_logs_nothing_of_its_own(self):
        # the premise of the derivation: when it changes (a success line is added), the witness gets a direct line
        after = self.loop[self.loop.index("if (!recreateGetClient())"):]
        block = after[:after.index("if (keepRunning())")]
        self.assertEqual(block.count("ESP_LOG"), 1, "only the failure line (the give-up)")
        self.assertIn("could not rebuild client", block)

    def test_a_forced_status_only_rewrites_a_parsed_answer(self):
        # why no fault drives the rebuild: a transport failure (status <= 0) stays real
        self.assertRegex(self.logic, r"if \(forcedStatus == 0 \|\| realStatus <= 0\) return \{realStatus, false\};")
        self.assertIn("telephony::httpResponseParsed(status)", self.loop)

    def test_the_ballast_floor_is_the_probes(self):
        m = re.search(r"kBallastMinTarget\s*=\s*(\d+)\s*\*\s*(\d+)", self.logic)
        self.assertEqual(int(m.group(1)) * int(m.group(2)), an.BALLAST_FLOOR)
        self.assertEqual(SC["ballast_bytes"], an.BALLAST_FLOOR)
        self.assertIn("static_cast<size_t>(t) < kBallastMinTarget", self.logic)

    def test_the_get_fault_ranges_match_the_scenarios_values(self):
        self.assertRegex(self.logic, r"r\.value < 400 \|\| r\.value > 599")
        self.assertRegex(self.logic, r"r\.value < 1 \|\| r\.value > kGetMaxAttempts")
        self.assertTrue(400 <= SC["get_status"] <= 599)
        self.assertTrue(1 <= SC["get_max_attempts"] <= an.GET_MAX_ATTEMPTS)

    def test_release_never_answers_409(self):
        http = read(os.path.join(REPO, "src", "Helpers", "HttpServer.cpp"))
        self.assertRegex(http, r'ballast == "release"\)\s*bp::releaseBallast\(\);')
        self.assertIn("void releaseBallast();", read(os.path.join(REPO, "src", "SIP", "BenchProbe.hpp")))
        self.assertRegex(read(os.path.join(REPO, "src", "SIP", "BenchProbe.cpp")),
                         r"void releaseLocked\(Why why\)\s*\{\s*if \(!s_held\) return;")


class StubRun:
    """A run whose every board-facing call is recorded, in order, in `order`."""

    def __init__(self, test, ends=(FAR,), invite_raises=None, hold_raises=None, arm_raises=None,
                 release_raises=None, status=None):
        self.order = []
        run = mock.Mock(far_ends=ends, far_end=ends[0])
        self.run, self.caller = run, mock.Mock()
        run.agents = {"caller": self.caller}
        run.baseline = {"uptime": 100, "resetReason": "POWERON"}
        run.calls = []
        run.session_count.return_value = 0
        run.stop.wait.return_value = False
        o = self.order

        def arm(name, value=None):
            o.append("arm:%s=%s" % (name, value))
            if arm_raises:
                raise arm_raises
        run.arm.side_effect = arm

        def hold():
            o.append("hold")
            if hold_raises:
                raise hold_raises
        run.hold_ballast.side_effect = hold

        def release():
            o.append("release")
            if release_raises:
                raise release_raises
            return True
        run.probe.release_ballast.side_effect = release

        def http_status():
            o.append("status")
            return {"uptime": 150, "resetReason": "POWERON"} if status is None else status
        run.http.status.side_effect = http_status
        run.checkpoint.side_effect = lambda: o.append("checkpoint")

        def invite(*a, **kw):
            o.append("invite")
            if invite_raises:
                raise invite_raises
            return types.SimpleNamespace(call_id="c1", final_status=487, cancel_status=200, cancel_sent_at=1.0,
                                         cancel_when_expired=False, responses=[(0, 180)])
        self.caller.invite.side_effect = invite
        patches = [mock.patch.object(an, "finish_call", lambda *a: o.append("finish")),
                   mock.patch.object(an, "after_call", lambda *a: o.append("after_call"))]
        for p in patches:
            p.start()
            test.addCleanup(p.stop)

    def go(self, sc=SC):
        return an.x370_run(self.run, sc)


class SequencingTest(unittest.TestCase):
    def test_the_order_is_gate_arms_hold_call_release_then_the_status_reads(self):
        s = StubRun(self)
        s.go()
        self.assertEqual(s.order, ["checkpoint", "arm:get_status=404", "arm:get_max_attempts=8", "hold", "invite",
                                   "finish", "release", "status", "after_call"])

    def test_nothing_but_the_call_sits_between_the_hold_and_the_release(self):
        # the board may not answer HTTP while the ballast is held: no checkpoint, no status, no pcap pull
        s = StubRun(self)
        s.go()
        held = s.order[s.order.index("hold") + 1:s.order.index("release")]
        self.assertEqual(held, ["invite", "finish"])

    def test_the_ballast_is_released_when_the_call_raises(self):
        s = StubRun(self, invite_raises=RuntimeError("the UA blew up mid-call"))
        with self.assertRaises(RuntimeError):
            s.go()
        self.assertEqual(s.order[-2:], ["invite", "release"])
        self.assertNotIn("status", s.order)

    def test_the_ballast_is_released_when_the_hold_gets_no_answer(self):
        # the POST may have been applied before the reply was lost: the release goes anyway, the call never starts
        s = StubRun(self, hold_raises=an.run_soak.Abort("INVALID", "holding the ballast: no answer"))
        with self.assertRaises(an.run_soak.Abort):
            s.go()
        self.assertEqual(s.order[-2:], ["hold", "release"])
        s.caller.invite.assert_not_called()
        self.assertEqual(s.run.calls, [])

    def test_the_ballast_is_released_when_a_fault_arm_is_refused(self):
        s = StubRun(self, arm_raises=an.run_soak.Abort("INVALID", "arming get_status: 409"))
        with self.assertRaises(an.run_soak.Abort):
            s.go()
        self.assertEqual(s.order[-2:], ["arm:get_status=404", "release"])
        self.assertNotIn("hold", s.order)
        s.caller.invite.assert_not_called()

    def test_a_release_that_raises_does_not_hide_the_calls_own_error(self):
        s = StubRun(self, invite_raises=RuntimeError("the call"), release_raises=OSError("login failed"))
        with self.assertRaises(RuntimeError) as cm:
            s.go()
        self.assertEqual(str(cm.exception), "the call")
        self.assertIn("release", s.order)

    def test_a_release_that_raises_is_said_and_the_run_goes_on_to_probe_finish(self):
        s = StubRun(self, release_raises=OSError("login failed"))
        s.go()
        said = " ".join(str(c.args[0]) for c in s.run.say.call_args_list)
        self.assertIn("ballast release raised", said)
        self.assertIn("probe_finish tries again", said)

    def test_a_release_without_a_200_is_said(self):
        s = StubRun(self)
        s.run.probe.release_ballast.side_effect = lambda: False
        s.go()
        self.assertIn("no 200", " ".join(str(c.args[0]) for c in s.run.say.call_args_list))

    def test_one_call_one_invite_with_a_bounded_cancel(self):
        s = StubRun(self)
        s.go()
        self.assertEqual(s.caller.invite.call_count, 1)
        kw = s.caller.invite.call_args.kwargs
        self.assertEqual(kw["cancel_when_timeout_s"], SC["call_fire_wait_s"])
        self.assertTrue(callable(kw["cancel_when"]))
        self.assertEqual(s.caller.invite.call_args.args, (FAR,))

    def test_the_post_release_status_is_judged_for_a_reboot(self):
        s = StubRun(self, status={"uptime": 5, "resetReason": "PANIC"})
        s.go()
        problems = s.run.calls[0]["alive_problems"]
        self.assertEqual(len(problems), 2)
        self.assertTrue(all("rebooted" in p for p in problems), problems)

    def test_a_board_that_never_answers_after_the_release_is_a_hang(self):
        s = StubRun(self)
        s.run.http.status.side_effect = lambda: None
        s.go(dict(SC, recover_wait_s=0))
        self.assertIn("did not answer", s.run.calls[0]["alive_problems"][0])


class CancelWhenTest(unittest.TestCase):
    def run_with(self, entries, phantoms=()):
        return mock.Mock(syslog=mock.Mock(entries=lambda since: entries), phantoms=lambda: list(phantoms))

    def test_it_waits_until_the_first_transport_failure_then_adds_the_delay(self):
        none_yet = self.run_with([(1.0, ready(1))])
        self.assertIsNone(an.x370_cancel_when(none_yet, 2.0)(0.0))
        fired = self.run_with([(1.0, ready(1)), (3.0, fail(2)), (4.0, fail(3))])
        self.assertEqual(an.x370_cancel_when(fired, 2.0)(0.0), 5.0)

    def test_a_phantom_inbound_cancels_at_once(self):
        run = self.run_with([], phantoms=[("detector", "6104", "x")])
        with mock.patch.object(an.time, "monotonic", return_value=42.0):
            self.assertEqual(an.x370_cancel_when(run, 2.0)(0.0), 42.0)


class AliveTest(unittest.TestCase):
    BASE = {"uptime": 100, "resetReason": "POWERON"}

    def test_a_board_that_answers_with_a_later_uptime_is_up(self):
        self.assertEqual(an.x370_alive_problems(self.BASE, {"uptime": 130, "resetReason": "POWERON"}), [])

    def test_no_answer_is_a_hang(self):
        self.assertIn("did not answer", an.x370_alive_problems(self.BASE, None)[0])

    def test_an_uptime_that_went_back_is_a_reboot(self):
        self.assertIn("rebooted", an.x370_alive_problems(self.BASE, {"uptime": 3, "resetReason": "POWERON"})[0])

    def test_a_changed_reset_reason_is_a_reboot(self):
        out = an.x370_alive_problems(self.BASE, {"uptime": 130, "resetReason": "PANIC"})
        self.assertEqual(len(out), 1)
        self.assertIn("PANIC", out[0])

    def test_recover_polls_until_the_board_answers(self):
        answers = iter([None, None, {"uptime": 7}])
        run = mock.Mock()
        run.http.status.side_effect = lambda: next(answers)
        run.stop.wait.return_value = False
        self.assertEqual(an.x370_recover(run, dict(SC, recover_wait_s=60)), {"uptime": 7})
        self.assertEqual(run.http.status.call_count, 3)

    def test_recover_gives_up_at_the_bound(self):
        run = mock.Mock()
        run.http.status.return_value = None
        run.stop.wait.return_value = False
        self.assertIsNone(an.x370_recover(run, dict(SC, recover_wait_s=0)))


class StubHttp:
    """BoardHttp.request_json for the probe client: scripted (status, body) answers, every request kept."""

    def __init__(self, *answers):
        self.answers, self.requests = list(answers), []

    def request_json(self, method, path, fields=None):
        self.requests.append((method, path, fields))
        return self.answers.pop(0) if self.answers else (200, COUNTERS)


COUNTERS = {"image": an.PROBE_IMAGE, "faults": {}, "ballast": {"held": False}, "freeInternal": 8200}
HELD = dict(COUNTERS, ballast={"held": True, "bytes": 90000, "blocks": 30})


class ProbeClientTest(unittest.TestCase):
    def client(self, *answers, tries=3):
        h = StubHttp(*answers)
        return an.BenchProbe(h, tries=tries, pause_s=0), h

    def test_hold_posts_the_floor_and_the_dead_man_and_wants_it_held(self):
        p, h = self.client((200, HELD))
        body = p.hold_ballast(8192, 35)
        self.assertEqual(h.requests, [("POST", an.BENCH_PATH, {"ballast": "8192", "deadman": "35"})])
        self.assertTrue(body["ballast"]["held"])

    def test_a_200_that_does_not_show_it_held_is_invalid(self):
        p, _ = self.client((200, COUNTERS))
        with self.assertRaises(an.run_soak.Abort) as cm:
            p.hold_ballast(8192, 35)
        self.assertEqual(cm.exception.verdict, "INVALID")
        self.assertIn("do not show it held", cm.exception.reason)

    def test_a_409_on_the_hold_is_invalid_and_never_retried(self):
        p, h = self.client((409, {"error": "ballast already held"}))
        with self.assertRaises(an.run_soak.Abort) as cm:
            p.hold_ballast(8192, 35)
        self.assertIn("409", cm.exception.reason)
        self.assertEqual(len(h.requests), 1)

    def test_a_hold_with_no_answer_is_not_repeated(self):
        # the first POST may have been applied: a second would be a 409, or a second ballast
        p, h = self.client((None, None))
        with self.assertRaises(an.run_soak.Abort) as cm:
            p.hold_ballast(8192, 35)
        self.assertIn("no answer", cm.exception.reason)
        self.assertEqual(len(h.requests), 1)

    def test_release_is_repeated_while_the_board_gives_no_answer(self):
        p, h = self.client((None, None), (None, None), (200, COUNTERS))
        self.assertTrue(p.release_ballast())
        self.assertEqual([r[2] for r in h.requests], [{"ballast": "release"}] * 3)

    def test_release_gives_up_after_its_tries_and_says_false(self):
        p, h = self.client((None, None), (None, None), (None, None))
        self.assertFalse(p.release_ballast())
        self.assertEqual(len(h.requests), 3)

    def test_a_503_busy_release_is_repeated(self):
        p, h = self.client((503, {"error": "counters busy"}), (200, COUNTERS))
        self.assertTrue(p.release_ballast())
        self.assertEqual(len(h.requests), 2)

    def test_a_refused_release_is_not_repeated(self):
        for st in (403, 404):
            with self.subTest(st=st):
                p, h = self.client((st, {"error": "x"}))
                self.assertFalse(p.release_ballast())
                self.assertEqual(len(h.requests), 1)

    def test_release_with_nothing_held_is_a_plain_200(self):
        p, h = self.client((200, COUNTERS))
        self.assertTrue(p.release_ballast())
        self.assertEqual(len(h.requests), 1)

    def test_disarm_all_releases_first_then_disarms_then_reads_back(self):
        p, h = self.client((200, COUNTERS), (200, COUNTERS), (200, COUNTERS))
        after, problems = p.disarm_all()
        self.assertEqual(problems, [])
        self.assertEqual([(r[0], r[2]) for r in h.requests],
                         [("POST", {"ballast": "release"}), ("POST", {"fault": "disarm"}), ("GET", None)])
        self.assertIsNotNone(after)

    def test_disarm_all_still_disarms_when_the_release_got_no_answer(self):
        p, h = self.client((None, None), (None, None), (None, None), (200, COUNTERS), (200, COUNTERS))
        _, problems = p.disarm_all()
        self.assertEqual([r[2] for r in h.requests][-2:], [{"fault": "disarm"}, None])
        self.assertTrue(any("ballast=release answered None" in x for x in problems), problems)

    def test_disarm_all_names_a_ballast_that_is_still_held(self):
        p, _ = self.client((200, HELD), (200, HELD), (200, HELD))
        _, problems = p.disarm_all()
        self.assertEqual(problems, ["a ballast is still held"])


class RegistrationTest(unittest.TestCase):
    def test_it_is_a_one_call_probe_scenario_with_both_get_faults_pre_registered(self):
        self.assertEqual((SC["probe"], tuple(SC["faults"]), SC["calls"], SC["max_calls"]),
                         (True, ("get_status", "get_max_attempts"), 1, 1))
        self.assertEqual(SC["uas"], {"caller": "6101", "detector": "6104"})
        self.assertTrue(SC["ring_required"])
        self.assertEqual(SC["part_of"], "#370")
        self.assertEqual(an.scenario_problems(SC), [])

    def test_the_ballast_is_at_the_floor_with_a_dead_man_past_the_call(self):
        self.assertEqual(SC["ballast_bytes"], 8192)
        self.assertGreaterEqual(SC["ballast_deadman_s"], SC["call_fire_wait_s"] + SC["cancel_after_fire_s"])
        self.assertLessEqual(SC["call_cap_s"], an.MAX_CALL_S)

    def test_a_404_not_a_403_keeps_the_loop_out_of_the_902_fail_fast(self):
        self.assertEqual(SC["get_status"], 404)

    def test_a_ballast_under_the_floor_is_refused(self):
        self.assertTrue(any("floor" in p for p in an.scenario_problems(dict(SC, ballast_bytes=4096))))

    def test_a_dead_man_that_would_fire_mid_call_is_refused(self):
        self.assertTrue(any("before the call can end" in p for p in an.scenario_problems(dict(SC, ballast_deadman_s=5))))
        self.assertTrue(any("1-600" in p for p in an.scenario_problems(dict(SC, ballast_deadman_s=601))))
        self.assertTrue(any("1-600" in p for p in an.scenario_problems(dict(SC, ballast_deadman_s=0))))

    def test_a_cancel_wait_past_the_invite_bound_is_refused(self):
        sc = dict(SC, call_fire_wait_s=15.0, ballast_deadman_s=60)
        self.assertTrue(any("INVITE bound" in p for p in an.scenario_problems(sc)))

    def test_one_ring_is_the_cap_and_thirty_seconds_the_call_cap(self):
        self.assertTrue(any("calls must be 1-1" in p for p in an.scenario_problems(dict(SC, calls=2))))
        self.assertTrue(any("call_cap_s" in p for p in an.scenario_problems(dict(SC, call_cap_s=31))))

    def test_the_get_budget_fits_the_call_cap(self):
        self.assertLessEqual(an.get_giveup_worst_s(SC["get_max_attempts"]), SC["call_cap_s"] - an.HANGUP_MARGIN_S)
        self.assertTrue(any("past the" in p for p in an.scenario_problems(dict(SC, get_max_attempts=40))))

    def test_it_runs_without_the_status_logger_so_no_second_poller_squeezes_the_board(self):
        self.assertTrue(SC["no_status_logger"])

    def test_the_run_is_wrapped_so_the_probe_is_finished_after_it(self):
        self.assertEqual(SC["run"].__name__, "x370_run")
        r = mock.Mock()

        def boom(run, sc):
            raise RuntimeError("boom")
        with self.assertRaises(RuntimeError):
            an.probe_run(boom)(r, SC)
        r.probe_finish.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()

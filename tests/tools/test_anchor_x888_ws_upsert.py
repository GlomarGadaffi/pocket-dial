#!/usr/bin/env python3
"""Host tests for the x888_ws_upsert scenario (tests/load/anchor_scenarios.py, #888).

The scenario drives the bench probe's ws_upsert fault (docs/BENCH_PROBE.md): three synthetic
upserts through the real handleWsEvent(), one per #888 witness branch. These pin the parts that
decide a verdict without a board: the refusal list, the per-branch witness count, the summary,
and that the witness strings are the ones TelephonyAnchorClient.cpp logs. The end-to-end run
against a fake board is X888Test in test_anchor_scenarios.py.

    python3 -m unittest discover -s tests/tools -p 'test_anchor_x888_ws_upsert.py'
"""
import os
import re
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "load"))
import anchor_scenarios as an  # noqa: E402

REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
CLIENT = os.path.join(REPO, "src", "SIP", "TelephonyAnchorClient.cpp")
LOGIC = os.path.join(REPO, "src", "SIP", "BenchProbeLogic.hpp")
FAR = "15550104242"            # a fictional far end

UNQUEUED = "Upset dropped, work item not queued"
ABSORBED = "Upset absorbed while an outbound is in flight"
OWN_LEG = "Upset dropped as own leg with no outbound slot"

# What a probe board logs for three good cases, with the noise around them: a real witness
# line for a real participant (not a synthetic one), and the worker re-check's own-leg line.
EXCERPT = [
    "I (1000) TelephonyAnchor: Successfully initiated call to <x> (own leg 41)",
    "W (2000) BenchProbe: BENCHFAULT ws_upsert fired",
    "W (2001) TelephonyAnchor: %s: nin=0 pending=0 active=0 part=pdb-u1-1 seen=1 (#888)" % UNQUEUED,
    "W (3000) BenchProbe: BENCHFAULT ws_upsert fired",
    "W (3001) TelephonyAnchor: %s: nin=1 pending=0 active=1 part=pdb-u2-2 own=41 seen=1 (#888)" % ABSORBED,
    "W (5000) BenchProbe: BENCHFAULT ws_upsert fired",
    "W (5001) TelephonyAnchor: %s: nin=0 pending=0 active=0 part=pdb-u3-3 seen=1 (#888)" % OWN_LEG,
    "W (5100) TelephonyAnchor: %s: nin=0 pending=0 active=0 part=517 seen=16 (#888)" % OWN_LEG,
    "W (5101) TelephonyAnchor: Upset dropped as own leg at the worker re-check: nin=0 pending=0 "
    "active=0 part=pdb-u3-3 seen=1 (#888)",
]


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def verdicts(lines, fired=(True, True, True)):
    """[(case, verdict, counts)] the way the judge computes them."""
    out = []
    for case, _, _ in an.X888_BRANCHES:
        counts = an.x888_counts(lines, case)
        out.append((case, an.x888_verdict(case, counts, fired[case - 1])[0], counts))
    return out


class RefusalTest(unittest.TestCase):
    def test_the_never_dial_list_is_911_933_113_1001(self):
        self.assertEqual(an.X888_NEVER_DIAL, ("911", "933", "113", "1001"))

    def test_each_forbidden_number_is_refused_by_the_x888_list(self):
        for n in ("911", "933", "113", "1001"):
            with self.subTest(n=n):
                problems = an.x888_destination_problems(n)
                self.assertTrue(any("x888 never-dial list" in p for p in problems), problems)
                self.assertNotIn(n, " ".join(problems), "a refusal never echoes the number")

    def test_an_emergency_far_end_in_any_form_is_refused(self):
        for n in ("9911", "+19335550100", "15559110000", "112", "999", "9933"):
            with self.subTest(n=n):
                self.assertTrue(an.x888_destination_problems(n), n)

    def test_a_valid_far_end_is_accepted(self):
        self.assertEqual(an.x888_destination_problems(FAR), [])
        self.assertEqual(an.x888_destination_problems("+" + FAR), [])

    def test_the_run_refuses_before_it_arms_or_dials(self):
        for ends in (("911",), ("933",), ("113",), ("1001",), (FAR, "911")):
            with self.subTest(ends=ends):
                caller = mock.Mock()
                run = mock.Mock(far_ends=ends, far_end=ends[0], agents={"caller": caller})
                with self.assertRaises(an.run_soak.Abort) as cm:
                    an.x888_run(run, an.SCENARIOS["x888_ws_upsert"])
                self.assertEqual(cm.exception.verdict, "INVALID")
                self.assertIn("before any call", cm.exception.reason)
                caller.invite.assert_not_called()
                run.arm.assert_not_called()
                run.probe.arm.assert_not_called()


class WitnessCountTest(unittest.TestCase):
    def test_each_branch_is_counted_once_for_its_own_case(self):
        for case, name, text in an.X888_BRANCHES:
            counts = an.x888_counts(EXCERPT, case)
            self.assertEqual(counts[name], 1, (case, counts))
            self.assertEqual(sum(counts.values()), 1, "one line is one branch, never two: %r" % counts)

    def test_a_real_participants_line_is_not_a_synthetic_one(self):
        # part=517 is a real participant's own-leg drop: the same string, not this run's upsert
        self.assertEqual(an.x888_counts([EXCERPT[7]], 3)["own-leg"], 0)
        self.assertEqual(an.x888_counts([EXCERPT[7]], 1)["own-leg"], 0)

    def test_the_worker_recheck_line_is_not_the_classification_line(self):
        self.assertEqual(an.x888_counts([EXCERPT[8]], 3), {"unqueued": 0, "absorbed": 0, "own-leg": 0})

    def test_a_line_seen_twice_is_counted_twice(self):
        self.assertEqual(an.x888_counts([EXCERPT[2], EXCERPT[2]], 1)["unqueued"], 2)

    def test_the_three_witness_strings_are_not_substrings_of_each_other(self):
        texts = [t for _, _, t in an.X888_BRANCHES]
        for a in texts:
            for b in texts:
                if a != b:
                    self.assertNotIn(a, b)

    def test_zero_lines_is_invalid_never_pass(self):
        for case, name, _ in an.X888_BRANCHES:
            counts = {n: 0 for _, n, _ in an.X888_BRANCHES}
            verdict, why = an.x888_verdict(case, counts, True)
            self.assertEqual(verdict, "INVALID", (case, why))
            self.assertIn("0 lines", why)

    def test_a_fault_that_never_fired_is_invalid_even_with_a_line(self):
        counts = an.x888_counts(EXCERPT, 1)
        self.assertEqual(an.x888_verdict(1, counts, False)[0], "INVALID")

    def test_exactly_one_line_in_the_right_branch_passes(self):
        for case, _, _ in an.X888_BRANCHES:
            self.assertEqual(an.x888_verdict(case, an.x888_counts(EXCERPT, case), True), ("PASS", ""))

    def test_a_second_line_or_a_line_in_another_branch_fails(self):
        twice = an.x888_counts([EXCERPT[2], EXCERPT[2]], 1)
        self.assertEqual(an.x888_verdict(1, twice, True)[0], "FAIL")
        # case 2 aimed at "absorbed" but the upsert took the "not queued" branch for its id
        wrong = ["W (1) TelephonyAnchor: %s: nin=1 pending=0 active=1 part=pdb-u2-2 seen=1 (#888)" % UNQUEUED]
        counts = an.x888_counts(wrong, 2)
        self.assertEqual(counts, {"unqueued": 1, "absorbed": 0, "own-leg": 0})
        self.assertEqual(an.x888_verdict(2, counts, True)[0], "INVALID", "its own branch has 0 lines")
        both = an.x888_counts(wrong + [EXCERPT[4]], 2)
        self.assertEqual(an.x888_verdict(2, both, True)[0], "FAIL")


class SummaryTest(unittest.TestCase):
    def test_the_case_lines_and_the_summary_on_a_fixed_excerpt(self):
        res = verdicts(EXCERPT)
        self.assertEqual([an.x888_case_line(c, v, k) for c, v, k in res], [
            "case 1 unqueued: PASS (1 line: %s)" % UNQUEUED,
            "case 2 absorbed: PASS (1 line: %s)" % ABSORBED,
            "case 3 own-leg: PASS (1 line: %s)" % OWN_LEG,
        ])
        self.assertEqual(an.x888_summary(res),
                         "x888 summary: unqueued=1 absorbed=1 own-leg=1: 3 PASS, 0 FAIL, 0 INVALID -> PASS")

    def test_a_missing_branch_makes_the_summary_invalid(self):
        res = verdicts([ln for ln in EXCERPT if ABSORBED not in ln])
        self.assertEqual(an.x888_case_line(*res[1]),
                         "case 2 absorbed: INVALID (0 lines: %s)" % ABSORBED)
        self.assertEqual(an.x888_summary(res),
                         "x888 summary: unqueued=1 absorbed=0 own-leg=1: 2 PASS, 0 FAIL, 1 INVALID -> INVALID")

    def test_a_failure_outranks_an_invalid_one(self):
        res = verdicts([ln for ln in EXCERPT if ABSORBED not in ln] + [EXCERPT[2]])
        self.assertEqual(an.x888_summary(res),
                         "x888 summary: unqueued=2 absorbed=0 own-leg=1: 1 PASS, 1 FAIL, 1 INVALID -> FAIL")
        self.assertIn("2 lines", an.x888_case_line(*res[0]))

    def test_a_case_that_took_another_branch_names_it(self):
        res = verdicts(EXCERPT + ["W (1) TelephonyAnchor: %s: nin=0 pending=0 active=0 part=pdb-u3-3 "
                                  "seen=1 (#888)" % UNQUEUED])
        self.assertEqual(an.x888_case_line(*res[2]),
                         "case 3 own-leg: FAIL (1 line: %s; other branches: unqueued=1)" % OWN_LEG)


class WiredToTheFirmwareTest(unittest.TestCase):
    """The scenario counts what the firmware prints, so the two cannot drift apart unseen."""

    def setUp(self):
        self.src = read(CLIENT)
        self.logic = read(LOGIC)

    def test_the_witness_strings_equal_the_ones_the_firmware_logs(self):
        self.assertEqual([t for _, _, t in an.X888_BRANCHES], [UNQUEUED, ABSORBED, OWN_LEG])
        for _, name, text in an.X888_BRANCHES:
            with self.subTest(branch=name):
                literal = '"%s: nin=%%d pending=%%d active=%%d "' % text
                self.assertEqual(self.src.count(literal), 1, "one emitting ESP_LOGW per branch: " + literal)

    def test_the_part_id_the_probe_injects_is_the_one_the_scenario_filters_on(self):
        m = re.search(r'kWsProbeIdPrefix\s*=\s*"([^"]+)"', self.logic)
        self.assertIsNotNone(m)
        self.assertEqual(an.X888_ID_PREFIX, m.group(1))
        self.assertIn('"%s%%d-%%u"' % m.group(1), self.logic, "the id is <prefix><case>-<n>")

    def test_the_fault_names_and_cases_match_the_probe(self):
        m = re.search(r"kFaultNames\[kFaultCount\]\s*=\s*\{([^}]*)\}", self.logic)
        self.assertIsNotNone(m)
        self.assertEqual(tuple(re.findall(r'"([a-z_]+)"', m.group(1))), an.PROBE_FAULTS)
        cases = re.search(r"kWsUpsertCases\s*=\s*(\d+)", self.logic)
        self.assertEqual(int(cases.group(1)), len(an.X888_BRANCHES))

    def test_the_probe_fire_line_is_the_scenarios_path_counter(self):
        self.assertIn('"BENCHFAULT %.*s fired"', read(os.path.join(REPO, "src", "SIP", "BenchProbe.cpp")))
        self.assertEqual(an.count_lines(["W (1) BenchProbe: BENCHFAULT ws_upsert fired"])["bench_ws_upsert"], 1)
        self.assertEqual(an.count_lines(["W (1) BenchProbe: BENCHFAULT token_age fired"])["bench_ws_upsert"], 0)


class RegistrationTest(unittest.TestCase):
    def test_x888_is_registered_as_a_probe_scenario_with_one_call(self):
        sc = an.SCENARIOS["x888_ws_upsert"]
        self.assertEqual((sc["probe"], tuple(sc["faults"]), sc["calls"], sc["max_calls"]),
                         (True, ("ws_upsert",), 1, 1))
        self.assertEqual(sc["path_counter"], "bench_ws_upsert")
        self.assertEqual(sc["uas"], {"caller": "6101", "detector": "6104"})
        self.assertEqual(an.scenario_problems(sc), [])

    def test_one_call_is_the_cap(self):
        sc = an.SCENARIOS["x888_ws_upsert"]
        self.assertTrue(any("calls must be 1-1" in p for p in an.scenario_problems(dict(sc, calls=2))))

    def test_the_call_fits_its_cap_with_the_agent_transactions(self):
        sc = an.SCENARIOS["x888_ws_upsert"]
        worst = sc["call_fire_wait_s"] + sc["cancel_after_fire_s"] + 2 * an.AGENT_TXN_TIMEOUT_S
        self.assertLessEqual(worst, sc["call_cap_s"])
        self.assertTrue(an.scenario_problems(dict(sc, call_fire_wait_s=sc["call_cap_s"])))

    def test_ws_upsert_is_a_probe_fault_the_harness_may_arm(self):
        self.assertIn("ws_upsert", an.PROBE_FAULTS)
        self.assertEqual(an.scenario_problems(dict(an.SCENARIOS["x888_ws_upsert"], faults=("ws_upsert", "ws_drop")))[0:1],
                         ["x888_ws_upsert: ws_drop is not a bench probe fault (%s)" % ", ".join(an.PROBE_FAULTS)])


if __name__ == "__main__":
    unittest.main()

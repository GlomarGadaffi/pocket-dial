#!/usr/bin/env python3
"""Host tests for the get_sock_shutdown bench fault (#370, #350; docs/BENCH_PROBE.md).

The fault shuts down the socket the rx task just published for its GET stream, so the header
read after it finds no response and runRxLoop() rebuilds its handle: the path behind #370 and
#350. It is the ESP-only glue around two pure decisions that BenchProbeLogic_test.cpp covers.
These pin what no host test compiles: the name is registered everywhere the siblings are, the
glue sits in the probe-only blocks and acts at the one place that reaches the rebuild, the log
line the docs promise is the one the firmware prints, and the docs no longer say that no fault
forces the rebuild.

    python3 -m unittest discover -s tests/tools -p 'test_bench_get_sock_shutdown.py'
"""
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "load"))
sys.path.insert(0, HERE)
import anchor_scenarios as an  # noqa: E402
import test_bench_probe_release as rel  # noqa: E402

REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
CLIENT = os.path.join(REPO, "src", "SIP", "TelephonyAnchorClient.cpp")
LOGIC = os.path.join(REPO, "src", "SIP", "BenchProbeLogic.hpp")
GLUE = os.path.join(REPO, "src", "SIP", "BenchProbe.cpp")
DOC = os.path.join(REPO, "docs", "BENCH_PROBE.md")
SCENARIOS = os.path.join(REPO, "tests", "load", "anchor_scenarios.py")
SCENARIO_TESTS = os.path.join(HERE, "test_anchor_scenarios.py")

NAME = "get_sock_shutdown"
# Appended last: the six before it keep their index, in the probe and in the harness.
FIRST_SIX = ("makecall_read_fail", "get_status", "get_max_attempts", "post_stream_fail", "token_age", "ws_upsert")
# The line the firmware prints when it has issued the shutdown; docs/BENCH_PROBE.md quotes it up to the rc.
APPLIED = "BENCHFAULT get_sock_shutdown applied: shutdown(SHUT_RDWR) on the published GET socket, rc="
FIRE = "pd::benchprobe::fire(pd::benchprobe::Fault::GetSockShutdown)"
PUBLISH = "slot->getFd = esp_http_client_get_socket(_getClient);"
HEADER_READ = "esp_http_client_fetch_headers(_getClient);"


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def code_only(text):
    return "\n".join(line.split("//")[0] for line in text.split("\n"))


def names_in(text, pattern):
    m = re.search(pattern, text, re.S)
    return tuple(re.findall(r'"([a-z_]+)"', m.group(1))) if m else ()


def firmware_names():
    return names_in(read(LOGIC), r"kFaultNames\[kFaultCount\]\s*=\s*\{([^}]*)\}")


def fake_board_names():
    return names_in(read(SCENARIO_TESTS), r"class FakeProbeBoard\(.*?\n\s+NAMES = \(([^)]*)\)")


def rx_loop(src):
    start = src.index("for (; attempt < kMaxAttempts && keepRunning(); ++attempt)")
    return src[start:src.index("if (!opened)", start)]


def function_body(src, signature):
    start = src.index(signature)
    return src[start:src.index("\n}\n", start)]


class RegistryTest(unittest.TestCase):
    def test_the_probe_lists_it_after_ws_upsert_so_no_earlier_index_moves(self):
        names = firmware_names()
        self.assertEqual(names[:6], FIRST_SIX)
        self.assertEqual(names[6:7], (NAME,))

    def test_the_harness_lists_it_in_the_same_slot(self):
        self.assertEqual(tuple(an.PROBE_FAULTS[:7]), FIRST_SIX + (NAME,))

    def test_the_fake_probe_board_models_every_fault_the_probe_has_this_one_included(self):
        self.assertIn(NAME, fake_board_names())
        self.assertEqual(fake_board_names(), firmware_names())

    def test_a_scenario_may_pre_register_it_and_still_passes_the_probe_checks(self):
        sc = dict(an.SCENARIOS["x370_pressure_rebuild"], faults=("get_status", "get_max_attempts", NAME))
        self.assertEqual(an.scenario_problems(sc), [])
        unknown = an.scenario_problems(dict(sc, faults=("get_status", "get_max_attempts", NAME + "_x")))
        self.assertTrue(any("is not a bench probe fault" in p for p in unknown), unknown)


class ClientWiringTest(unittest.TestCase):
    """TelephonyAnchorClient.cpp: the one place the fault acts."""

    def setUp(self):
        self.src = read(CLIENT)
        self.loop = rx_loop(self.src)
        self.code = code_only(self.loop)

    def test_it_fires_once_and_only_in_the_rx_loop(self):
        self.assertEqual(self.src.count(FIRE), 1)
        self.assertIn(FIRE, self.loop)

    def at(self, needle):
        """Where `needle` is in the loop's code: an assertion failure, not an exception, when it is not."""
        self.assertIn(needle, self.code)
        return self.code.index(needle)

    def test_it_acts_after_the_fd_is_published_and_before_the_header_read(self):
        self.assertLess(self.at(PUBLISH), self.at(FIRE))
        self.assertLess(self.at(FIRE), self.at(HEADER_READ))

    def test_the_arm_is_spent_only_when_a_socket_is_there_to_shut_down(self):
        due = self.at("pd::benchprobe::getSockShutdownDue(benchGet.sockShutdownLeg, slot->getFd)")
        self.assertLess(due, self.at(FIRE))
        self.assertLess(self.at(FIRE), self.at("shutdown(slot->getFd, SHUT_RDWR)"),
                        "the arm is consumed before the shutdown is issued")

    def test_the_published_fd_is_read_and_shut_down_under_getmutex(self):
        # closePostClient() can close a slot's GET handle from another task, so the fd is used under the
        # same lock that publishes and unpublishes it, as stopMediaStreams does
        self.assertRegex(self.code, r"lock_guard<std::mutex> lock\(_getMutex\);\s*"
                                    r"if \(pd::benchprobe::getSockShutdownDue\(")
        block = self.code[self.at("getSockShutdownDue("):self.at("shutdown(slot->getFd, SHUT_RDWR)")]
        self.assertNotIn("unlock", block)
        self.assertNotIn("stopRequested", self.code, "a transport fault is not a cooperative stop")

    def test_the_fault_neither_skips_an_attempt_nor_adds_an_attempt_line(self):
        # test_anchor_x370_pressure_rebuild.py rests on one attempt line per iteration and no continue
        self.assertIn(FIRE, self.code, "positive control: the fault's glue is in the loop")
        self.assertNotIn("continue;", self.code)
        self.assertEqual(self.code.count("attempt + 1, kMaxAttempts"), 3)

    def test_the_log_line_is_the_one_the_docs_quote_and_the_counters_do_not_mistake_for_a_firing(self):
        self.assertEqual(self.src.count(APPLIED), 1)
        m = re.search(r'"(BENCHFAULT get_sock_shutdown applied[^"]*)"', self.src)
        self.assertIsNotNone(m, "the line is not in the client")
        line = m.group(1)
        self.assertNotIn(" fired", line, "tests/load/anchor_scenarios.py counts 'BENCHFAULT <name> fired'")
        self.assertEqual(an.count_lines(["W (1) TelephonyAnchor: " + line % 0])["bench_fired"], 0)
        self.assertEqual(an.count_lines(["W (1) BenchProbe: BENCHFAULT %s fired" % NAME])["bench_fired"], 1)

    def test_every_line_that_names_it_sits_in_a_probe_only_block(self):
        stray = [n for n, line, guarded in rel.probe_lines(self.src)
                 if guarded is False and re.search(r"GetSockShutdown|sockShutdownLeg|get_sock_shutdown", line)]
        self.assertEqual(stray, [])
        self.assertTrue(any(guarded and "GetSockShutdown" in line for _, line, guarded in rel.probe_lines(self.src)),
                        "positive control: the glue is there, and under the guard")


class ProbeGlueTest(unittest.TestCase):
    """BenchProbe.cpp: which leg the fault may act on."""

    def setUp(self):
        self.src = read(GLUE)

    def test_arming_only_this_fault_still_claims_the_leg(self):
        body = function_body(self.src, "void claimGetFaults(")
        self.assertIn("Fault::GetSockShutdown", body)

    def test_the_rx_loop_is_told_the_leg_is_claimed_and_fires_the_fault_itself(self):
        body = function_body(self.src, "GetLoopFaults takeGetFaults(")
        self.assertIn("g.sockShutdownLeg = true;", body)
        self.assertNotIn("Fault::GetSockShutdown", body, "fired at the site, once a socket is there to shut down")


class DocsTest(unittest.TestCase):
    def setUp(self):
        self.doc = read(DOC)

    def test_the_fault_has_a_table_row_and_a_section(self):
        start = self.doc.index("## Faults")
        table = self.doc[start:self.doc.index("Notes:", start)]
        self.assertRegex(table, r"\|\s*`get_sock_shutdown`\s*\|\s*none\s*\|")
        self.assertIn("### `get_sock_shutdown` (#370, #350)", self.doc)

    def test_the_docs_quote_the_line_the_firmware_prints(self):
        self.assertIn(APPLIED, self.doc)
        self.assertIn(APPLIED, read(CLIENT))

    def test_the_docs_say_an_application_level_fault_is_weaker_evidence_for_350(self):
        self.assertRegex(self.doc, r"application-level fault is weaker evidence for #350")

    def test_the_stale_claims_that_no_fault_forces_the_rebuild_are_corrected_where_they_were_made(self):
        self.assertNotIn("**No fault forces the rebuild.**", self.doc)
        self.assertNotIn("only the ballast can cause one, by chance", self.doc)
        scenarios = read(SCENARIOS)
        for stale in ("No fault forces that path", "No probe fault forces it", "No fault forces the rebuild"):
            self.assertNotIn(stale, scenarios)


if __name__ == "__main__":
    unittest.main()

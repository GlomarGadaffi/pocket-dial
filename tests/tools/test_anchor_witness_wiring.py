"""ESP-only path witnesses that no host test compiles (#888, #902): each witness line is in the
source with the exact text its LOG_COUNTERS regex expects, and carries no number or credential.
The host-compiled witnesses are asserted by their gtests (pdwitness::count)."""
import os
import re
import sys
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "load"))
import anchor_scenarios as an  # noqa: E402

SRC = os.path.join(HERE, "..", "..", "src", "SIP", "TelephonyAnchorClient.cpp")
BENCH = os.path.join(HERE, "..", "..", "src", "SIP", "BenchProbe.cpp")
BENCH_LOGIC = os.path.join(HERE, "..", "..", "src", "SIP", "BenchProbeLogic.hpp")


class EspWitnessWiringTest(unittest.TestCase):
    def setUp(self):
        with open(SRC, encoding="utf-8") as f:
            self.src = f.read()

    def test_952_token_witnesses_are_the_lines_main_emits(self):
        # The format strings as written in ensureToken(), fetchToken() and requestRestartIfTokenStale()
        # (U+2014 is the dash in three of them), each beside the line the board's syslog then carries.
        emitted = {
            "token_refresh_deferred_live": (
                'ESP_LOGW(TAG, "Token near expiry but media streams active — deferring refresh");',
                "W (1) TelephonyAnchor: Token near expiry but media streams active — deferring refresh"),
            "token_refresh_near_expiry": (
                'ESP_LOGI(TAG, "Access token near expiry — refreshing");',
                "I (2) TelephonyAnchor: Access token near expiry — refreshing"),
            "token_retrieved": (
                'ESP_LOGI(TAG, "Retrieved access token (len=%d, lifetime=%llds)",',
                "I (3) TelephonyAnchor: Retrieved access token (len=1043, lifetime=3600s)"),
            "ws_restart_stale_token": (
                'ESP_LOGW(TAG, "WS disconnected/errored with an expiring token — requesting anchor restart '
                'to refresh it");',
                "W (4) TelephonyAnchor: WS disconnected/errored with an expiring token — requesting anchor "
                "restart to refresh it"),
        }
        for name, (source_line, board_line) in emitted.items():
            with self.subTest(counter=name):
                self.assertIn(source_line, self.src)
                self.assertEqual(an.count_lines([board_line])[name], 1)
        failed = (
            ('ESP_LOGE(TAG, "Token request returned HTTP %d", status);',
             "E (5) TelephonyAnchor: Token request returned HTTP 401"),
            ('ESP_LOGE(TAG, "Token failed to write body: %d", writeBytes);',
             "E (6) TelephonyAnchor: Token failed to write body: -1"),
            ('ESP_LOGE(TAG, "Token HTTP connection failed to open: %s", esp_err_to_name(err));',
             "E (7) TelephonyAnchor: Token HTTP connection failed to open: ESP_ERR_HTTP_CONNECT"))
        for source_line, board_line in failed:
            with self.subTest(line=board_line):
                self.assertIn(source_line, self.src)
                self.assertEqual(an.count_lines([board_line])["token_fetch_failed"], 1)

    def test_952_bench_fire_line_is_the_one_bench_token_age_counts(self):
        with open(BENCH, encoding="utf-8") as f:
            bench = f.read()
        with open(BENCH_LOGIC, encoding="utf-8") as f:
            logic = f.read()
        self.assertIn('ESP_LOGW(TAG, "BENCHFAULT %.*s fired", static_cast<int>(n.size()), n.data());', bench)
        self.assertIn('"token_age"', logic, "the fault name that fills the %.*s")
        self.assertEqual(an.count_lines(["W (8) BenchProbe: BENCHFAULT token_age fired"])["bench_token_age"], 1)
        self.assertEqual(an.count_lines(["W (9) BenchProbe: BENCHFAULT get_status fired"])["bench_token_age"], 0)

    def test_888_upset_ignored_while_pending_is_logged_with_the_pending_age(self):
        self.assertIn('"Upset ignored while %d makeCall(s) pending (oldest %lld ms old): "', self.src)
        self.assertIn('"3CX does not repeat a Connected one (#888)"', self.src)
        sample = ("W (1) TelephonyAnchor: Upset ignored while 2 makeCall(s) pending (oldest 1840 ms old): "
                  "3CX does not repeat a Connected one (#888)")
        self.assertEqual(an.count_lines([sample])["upset_ignored_pending_888"], 1)
        # the age is taken where the first pending makeCall begins
        self.assertRegex(self.src, r"_outboundPending\.fetch_add\(1,[^)]*\) == 0\)\s*\n\s*_outboundPendingSinceUs\.store")

    def test_902_failfast_line_is_the_one_the_harness_counts(self):
        self.assertIn('"GET stream: HTTP 403 on %d consecutive attempts for "', self.src)
        self.assertIn('"/callcontrol/<dn>/participants/%s/stream -- giving up now, not at attempt %d (#902)"', self.src)
        self.assertNotIn("getUrl.c_str(),\n\t\t\t\t\t\t\tforbiddenAfterAnswer", self.src)

    def test_884_ctrl_request_witness_is_one_esp_log_line_fed_by_the_connect_event(self):
        self.assertIn('ESP_LOGI(TAG, "ctrl request: attempt %d %s in %lld ms (#884)"', self.src)
        sample = "I (1) TelephonyAnchor: ctrl request: attempt 1 cold in 1130 ms (#884)"
        self.assertEqual(an.count_lines([sample])["ctrl_request_884"], 1)
        self.assertEqual(self.src.count("ctrl request: attempt"), 1, "one witness line, not queueLog")
        self.assertIn("HTTP_EVENT_ON_CONNECTED", self.src)
        self.assertIn("makeAuthedClient(url, HTTP_METHOD_POST, 1024, token, ctrlConnectedHook, &_ctrlConnected)", self.src)

    def test_888_witness_is_not_taken_under_the_mutex(self):
        at = self.src.index('ESP_LOGW(TAG, "Upset ignored while')
        before = self.src[max(0, at - 700):at]
        self.assertIn("if (ignoredPending > 0)", before, "logged after the _mutex block, like the own-leg line")


if __name__ == "__main__":
    unittest.main()

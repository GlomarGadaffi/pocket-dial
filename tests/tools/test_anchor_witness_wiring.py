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


class EspWitnessWiringTest(unittest.TestCase):
    def setUp(self):
        with open(SRC, encoding="utf-8") as f:
            self.src = f.read()

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

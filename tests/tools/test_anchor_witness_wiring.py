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

# Comments and string literals are blanked (length and newlines kept) before any brace is counted.
_TOKEN = re.compile(r'//[^\n]*|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'')
_LOCK = re.compile(r"std::lock_guard<std::mutex> lock\(_mutex\)")
_ESP_LOG = re.compile(r"ESP_LOG[WIE]\(")
_HELPER_CALL = re.compile(r"(?<!::)(witnessSightingLocked|countOutboundLocked)\(")


def _blank(src):
    return _TOKEN.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), src)


def _pairs(code):
    """Map each '{' index to the index of its '}'."""
    stack, pairs = [], {}
    for i, ch in enumerate(code):
        if ch == "{":
            stack.append(i)
        elif ch == "}" and stack:
            pairs[stack.pop()] = i
    return pairs


def _enclosing(pairs, at):
    """(open, close) of the innermost brace block that contains index at, or None."""
    best = None
    for o, c in pairs.items():
        if o < at < c and (best is None or o > best[0]):
            best = (o, c)
    return best


class EspWitnessWiringTest(unittest.TestCase):
    def setUp(self):
        with open(SRC, encoding="utf-8") as f:
            self.src = f.read()
        self.code = _blank(self.src)
        self.pairs = _pairs(self.code)

    def _line(self, at):
        return self.src.count("\n", 0, at) + 1

    def _locks(self):
        return [m.start() for m in _LOCK.finditer(self.code)]

    def _witness_logs(self):
        """Start index of each ESP_LOG statement whose format names #888 (the cap line too)."""
        out = []
        for m in _ESP_LOG.finditer(self.code):
            end = self.code.index(";", m.start())
            if "#888" in self.src[m.start():end]:
                out.append(m.start())
        return out

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
                  "nin=0 active=0 part=517: 3CX does not repeat a Connected one (#888)")
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

    def test_888_no_witness_log_sits_inside_a_mutex_scope(self):
        logs = self._witness_logs()
        self.assertTrue(logs, "no #888 witness log found")
        for p in self._locks():
            _, close = _enclosing(self.pairs, p)
            for at in logs:
                self.assertFalse(p < at < close, "#888 log at line %d is inside the _mutex scope at line %d"
                                 % (self._line(at), self._line(p)))

    def test_888_no_second_mutex_lock_inside_an_open_one(self):
        locks = self._locks()
        for p in locks:
            _, close = _enclosing(self.pairs, p)
            for q in locks:
                self.assertFalse(p < q < close, "_mutex locked again at line %d inside the scope at line %d"
                                 % (self._line(q), self._line(p)))

    def test_888_not_handed_off_branch_takes_the_mutex_once_and_logs_outside_it(self):
        self.assertEqual(self.code.count("if (!handedOff)"), 1)
        open_ = self.code.index("{", self.code.index("if (!handedOff)"))
        close = self.pairs[open_]
        self.assertEqual(len(_LOCK.findall(self.code[open_:close])), 1)
        self.assertFalse(any(open_ < at < close for at in self._witness_logs()))

    def test_888_witness_sighting_is_taken_once_per_upsert_outside_the_leg_loop(self):
        at = self.code.index("for (int i = 0; i < nLegs; ++i)")
        close = self.pairs[self.code.index("{", at)]
        self.assertNotIn("witnessSightingLocked(", self.code[at:close])
        self.assertNotIn("countOutboundLocked(", self.code[at:close])
        sightings = [m.start() for m in _HELPER_CALL.finditer(self.code) if m.group(1) == "witnessSightingLocked"]
        self.assertEqual(len(sightings), 3, "re-check, own-leg classification, and the one after the leg loop")
        self.assertEqual(len([p for p in sightings if p > close]), 1, "one sample per upsert, after the loop")
        self.assertIn("if (unmatched) unqueued = true;", self.src, "the loop only flags a lost work item")

    def test_888_witness_helpers_are_only_called_with_the_mutex_held(self):
        calls = [m.start() for m in _HELPER_CALL.finditer(self.code)]
        self.assertTrue(calls)
        spans = [(p, _enclosing(self.pairs, p)[1]) for p in self._locks()]
        for at in calls:
            self.assertTrue(any(p < at < close for p, close in spans),
                            "witness helper called at line %d without _mutex held" % self._line(at))

    def test_888_witness_helpers_do_not_log(self):
        for name in ("witnessSightingLocked", "countOutboundLocked"):
            start = re.search(r"TelephonyAnchorClient::%s\(" % name, self.code).start()
            body = self.code[self.code.index("{", start):self.pairs[self.code.index("{", start)]]
            self.assertNotIn("ESP_LOG", body, name)

    def test_888_every_sighting_hands_its_cap_status_to_noteWitnessCap(self):
        sightings = [m for m in _HELPER_CALL.finditer(self.code) if m.group(1) == "witnessSightingLocked"]
        self.assertEqual(len(re.findall(r"noteWitnessCap\(\w+\);", self.code)), len(sightings))
        self.assertIn("_witnessCapNoted = true;", self.src, "the cap line is handed out once per boot")

    def test_888_inflight_array_size_is_passed_to_the_counter(self):
        self.assertIn("countOutboundLocked(inflight, POCKETDIAL_MAX_ANCHOR_CALLS, witnessActive, witnessPending)", self.src)
        self.assertIn("never past the caller's array", self.src)

    def test_888_witness_format_literals_are_in_the_source(self):
        for lit in (
            '"Upset ignored while %d makeCall(s) pending (oldest %lld ms old): "',
            '"nin=%d active=%d part=%.24s: "',
            '"Upset absorbed while an outbound is in flight: nin=%d pending=%d active=%d "',
            '"part=%.24s own=%.24s seen=%u (#888)"',
            '"Upset dropped as own leg with no outbound slot: nin=%d pending=%d active=%d "',
            '"Upset dropped as own leg at the worker re-check: nin=%d pending=%d active=%d "',
            '"Upset dropped, work item not queued: nin=%d pending=%d active=%d "',
            '"part=%.24s seen=%u (#888)"',
            '"witness cap reached: no further #888 witness lines this boot"',
        ):
            with self.subTest(lit=lit):
                self.assertIn(lit, self.src)

    def test_888_no_witness_line_carries_a_state_key(self):
        self.assertNotIn("upsetStateOf", self.src)
        self.assertNotIn("state=%", self.src)
        self.assertNotIn("state=n/a", self.src)


if __name__ == "__main__":
    unittest.main()

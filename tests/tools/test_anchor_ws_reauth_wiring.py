"""#336: the ESP arm of the control WebSocket's re-authentication. The decisions are host-compiled
(telephony::wsRestartDecision, raiseWsHeaderGen, startRetryDelayUs, restartDue) and pinned by
TelephonyAnchorLogic_test.cpp. The anchor client that feeds them compiles only on the device, so no
host test reaches the wiring; this pins where each input comes from and where each result is used:
the generation counters, the set_headers record, the restart request and its retry."""
import os
import re
import unittest

SIP = os.path.join(os.path.dirname(__file__), "..", "..", "src", "SIP")


def body_of(src, signature):
    start = src.rindex(signature)   # the last definition: the ESP arm, not a host stub
    brace = src.index("{", start)
    depth = 0
    for i in range(brace, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[brace:i + 1]
    raise AssertionError("unbalanced body for " + signature)


def code_only(text):
    return "\n".join(line.split("//")[0] for line in text.split("\n"))


def read(name):
    with open(os.path.join(SIP, name), encoding="utf-8") as f:
        return code_only(f.read())


LOCK = re.compile(r"std::lock_guard<std::mutex>\s+\w+\(_mutex\);")
IO = re.compile(r"esp_http_client_\w+\s*\(|esp_websocket_client_\w+\s*\(|\bsend\s*\(|\brecv\s*\(")


def lock_scopes(body):
    """The text from each _mutex guard to the end of the block that holds it."""
    scopes = []
    for m in LOCK.finditer(body):
        depth = 0
        for i in range(m.end(), len(body)):
            if body[i] == "{":
                depth += 1
            elif body[i] == "}":
                if depth == 0:
                    scopes.append(body[m.start():i])
                    break
                depth -= 1
        else:
            raise AssertionError("a _mutex guard has no end")
    return scopes


def call_args(body, name):
    """The text of the first call to `name(` up to its closing `);`."""
    at = body.index(name + "(")
    return body[at:body.index(");", at)]


class WsReauthWiringTest(unittest.TestCase):
    longMessage = False   # a failure prints its reason, not the whole function

    def setUp(self):
        self.cpp = read("TelephonyAnchorClient.cpp")
        self.hpp = read("TelephonyAnchorClient.hpp")
        self.fetch = body_of(self.cpp, "bool TelephonyAnchorClient::fetchToken(")
        self.connect = body_of(self.cpp, "bool TelephonyAnchorClient::connectWs(")
        self.request = body_of(self.cpp, "void TelephonyAnchorClient::requestRestartIfTokenStale(")
        self.restart = body_of(self.cpp, "void TelephonyAnchorClient::restartTaskTrampoline(")
        self.tick = body_of(self.cpp, "void TelephonyAnchorClient::tick(")

    def test_the_token_generation_is_bumped_inside_the_existing_install_scope_and_nowhere_else(self):
        scopes = lock_scopes(self.fetch)
        self.assertEqual(len(scopes), 2, "the request copy and the install, no third scope")
        install = scopes[1]
        gate = install.index("installIfNewer(")
        bump = install.index("_tokenGen.fetch_add(")
        self.assertLess(gate, bump, "after the gate has said this token is the installed one")
        self.assertIn("if (installed)", install[gate:bump], "only an installed token counts as a generation")
        self.assertEqual(self.cpp.count("_tokenGen.fetch_add("), 1, "one writer")
        self.assertEqual(self.cpp.count("_tokenGen.store("), 0, "nothing sets it to a value")

    def test_the_header_generation_is_raised_only_when_set_headers_returned_ok(self):
        setter = self.fetch.index("esp_websocket_client_set_headers(")
        raised = self.fetch.index("raiseWsHeaderGen(")
        self.assertLess(setter, raised, "after the call, never before it")
        ok = re.search(r"if \(headerErr == ESP_OK\)\s*\{[^}]*raiseWsHeaderGen\(_wsHeaderGen, gen\);[^}]*\}",
                       self.fetch)
        self.assertIsNotNone(ok, "the raise is the whole body of the ESP_OK branch")
        self.assertNotIn("_connected", ok.group(0), "the return code alone says the next handshake carries it")
        self.assertEqual(self.fetch.count("_wsHeaderGen"), 1, "fetchToken names the record once: the raise")
        for scope in lock_scopes(self.fetch):
            self.assertNotIn("raiseWsHeaderGen", scope, "set_headers and its record are outside _mutex")
        self.assertEqual(self.cpp.count("raiseWsHeaderGen("), 1)

    def test_only_connectWs_stores_the_header_generation_plainly_and_with_the_client_it_describes(self):
        stores = re.findall(r"\b_wsHeaderGen\.store\(", self.cpp)
        self.assertEqual(len(stores), 1, "a plain store is for a brand-new client only")
        scopes = lock_scopes(self.connect)
        copy = [s for s in scopes if "bearerHeader = _bearerHeader;" in s]
        self.assertEqual(len(copy), 1)
        self.assertIn("headerGen = _tokenGen.load(", copy[0], "read with the bearer, under the install lock")
        install = [s for s in scopes if "_wsClient = wsClient;" in s]
        self.assertEqual(len(install), 1)
        self.assertIn("_wsHeaderGen.store(headerGen", install[0], "stamped as the client is published")

    def test_the_restart_decision_is_fed_the_socket_state_in_the_order_the_logic_takes_it(self):
        args = call_args(self.request, "telephony::wsRestartDecision")
        order = [args.index(x) for x in ("_running.load(", "tokenExpiringSoon()", "_connected.load(",
                                         "_wsHeaderGen.load(", "_tokenGen.load(", "nowUs",
                                         "_lastWsRestartRequestUs.load(")]
        self.assertEqual(order, sorted(order), "running, expiring, connected, header gen, token gen, now, last")
        self.assertIsNone(LOCK.search(self.request), "this runs on the WS client's task: no lock")
        self.assertIsNone(IO.search(self.request), "and no I/O")
        none_return = self.request.index("WsRestartReason::None) return;")
        stamp = self.request.index("_lastWsRestartRequestUs.store(")
        request = self.request.index("_restartRequested.store(true")
        self.assertLess(none_return, stamp, "a refused decision stamps nothing")
        self.assertLess(stamp, request)

    def test_a_disconnect_clears_connected_before_it_asks_and_both_events_ask(self):
        start = self.cpp.index("case WEBSOCKET_EVENT_DISCONNECTED:")
        error = self.cpp.index("case WEBSOCKET_EVENT_ERROR:", start)
        disconnected = self.cpp[start:error]
        self.assertLess(disconnected.index("_connected.store(false"), disconnected.index("requestRestartIfTokenStale()"),
                        "the socket's own flag must read down when the stale-header check runs")
        self.assertIn("requestRestartIfTokenStale()", self.cpp[error:self.cpp.index("break;", error)])

    def test_a_failed_restart_rearms_itself_and_a_successful_one_resets(self):
        fail = self.restart.index("if (!self->start())")
        other = self.restart.index("else", fail)
        failed, ok = self.restart[fail:other], self.restart[other:]
        for needle in ("_startFailures.store(", "telephony::startRetryDelayUs(", "_restartNotBeforeUs.store(",
                       "_restartRequested.store(true"):
            self.assertIn(needle, failed, "the failure branch must " + needle)
        self.assertLess(failed.index("_restartNotBeforeUs.store("), failed.index("_restartRequested.store(true"),
                        "the hold is in place before the request can be seen")
        self.assertIn("_startFailures.store(0", ok)
        self.assertIn("_restartNotBeforeUs.store(0", ok)
        self.assertLess(self.restart.index("_restartRequested.store(false"), self.restart.index("self->stop()"),
                        "the request is cleared before the cycle, so a leak during it re-arms")
        self.assertGreater(self.restart.index("_restartInFlight.store(false"),
                           self.restart.rindex("_restartRequested.store(true"),
                           "the in-flight gate is released last")

    def test_a_retry_does_not_repeat_the_reclaiming_line(self):
        self.assertEqual(self.cpp.count("anchor restart: reclaiming socket pool"), 1)
        guarded = re.search(r"if \(self->_startFailures\.load\([^)]*\) == 0\)\s*\{[^}]*"
                            r"anchor restart: reclaiming socket pool", self.restart)
        self.assertIsNotNone(guarded, "the line about detached rx tasks is for a first attempt only")
        self.assertIn("anchor restart: retrying start()", self.restart)

    def test_tick_holds_a_requested_restart_until_restartDue(self):
        at = self.tick.index("_restartRequested.load(")
        spawn = self.tick.index("_restartInFlight.store(true", at)
        gate = self.tick[at:spawn]
        self.assertIn("_restartInFlight.load(", gate)
        self.assertIn("telephony::restartDue(esp_timer_get_time(), _restartNotBeforeUs.load(", gate)
        self.assertIsNone(LOCK.search(gate))
        self.assertIsNone(IO.search(gate))
        self.assertNotIn("ESP_LOG", gate, "tick() logs nothing on this path")

    def test_the_generation_and_retry_state_are_atomics(self):
        for decl in (r"std::atomic<uint32_t>\s+_tokenGen\{0\};", r"std::atomic<uint32_t>\s+_wsHeaderGen\{0\};",
                     r"std::atomic<uint32_t>\s+_startFailures\{0\};", r"std::atomic<int64_t>\s+_restartNotBeforeUs\{0\};",
                     r"std::atomic<int64_t>\s+_lastWsRestartRequestUs\{0\};"):
            with self.subTest(decl=decl):
                self.assertRegex(self.hpp, decl)

    def test_the_343_witness_line_is_unchanged_and_the_new_one_is_not_the_same_line(self):
        with open(os.path.join(SIP, "TelephonyAnchorClient.cpp"), encoding="utf-8") as f:
            raw = f.read()
        self.assertIn('ESP_LOGW(TAG, "WS disconnected/errored with an expiring token — requesting anchor restart '
                      'to refresh it");', raw)
        stale = re.search(r'"WS disconnected/errored with a stale Authorization header[^"]*"', raw)
        self.assertIsNotNone(stale, "the header-behind-the-token restart has a line of its own")
        self.assertNotIn("expiring", stale.group(0), "ws_restart_stale_token must not count this one")


if __name__ == "__main__":
    unittest.main()

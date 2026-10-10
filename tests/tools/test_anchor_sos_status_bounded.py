"""#948: the 911/933 status GET's allocation contract and the bounded teardown, as wired into the
ESP-only anchor client. The decisions are host-tested (tests/SosStatusGet_test.cpp, which drives
src/SIP/SosStatusGet.hpp); this pins that the sos lane of httpGetBody() and closeSosStatusClient()
call them, so putting the old code back in the .cpp turns a test red."""
import os
import re
import sys
import unittest

from test_anchor_own_leg_not_inbound import body_of, code_only

HERE = os.path.dirname(__file__)
SIP = os.path.join(HERE, "..", "..", "src", "SIP")
sys.path.insert(0, os.path.join(HERE, "..", "load"))
import anchor_scenarios as an  # noqa: E402


def slurp(name):
    with open(os.path.join(SIP, name), encoding="utf-8") as f:
        return f.read()


class AnchorSosStatusBoundedTest(unittest.TestCase):
    def setUp(self):
        self.src = slurp("TelephonyAnchorClient.cpp")
        self.hpp = slurp("TelephonyAnchorClient.hpp")
        self.sos_hpp = slurp("SosStatusGet.hpp")
        self.get_body = code_only(body_of(self.src, "bool TelephonyAnchorClient::httpGetBody("))
        m = re.search(r"if \(sosLane\)\s*\{(.*?)\n\t\t\t\}\n", self.get_body, re.S)
        self.assertIsNotNone(m, "the sos lane's read branch in httpGetBody")
        self.sos_read = m.group(1)

    def test_the_sos_read_goes_through_the_arena_helper_and_never_grows_a_vector(self):
        self.assertIn("telephony::readSosBody(", self.sos_read)
        self.assertIn("_sosBody,", self.sos_read)
        self.assertNotIn("std::vector", self.sos_read)
        self.assertNotIn(".insert(", self.sos_read)
        self.assertNotIn("esp_http_client_read(client, tempBuf", self.sos_read)
        # Positive control: the ordinary lane is unchanged and still follows the sos branch.
        self.assertGreater(self.get_body.index("std::vector<char> buffer;"), self.get_body.index("readSosBody("))

    def test_a_failed_short_or_oversize_read_hands_back_no_body_and_no_status(self):
        self.assertIn("esp_http_client_is_complete_data_received(client)", self.sos_read,
                      "esp_http_client_read returns 0 for a peer FIN before the response is complete")
        ok_at = self.sos_read.index("rd == telephony::BodyRead::Ok")
        log_at = self.sos_read.index("ESP_LOGE(")
        self.assertEqual(self.sos_read.count("*statusOut"), 1, "set on Ok only: -1 stays -1 on every failure")
        self.assertTrue(ok_at < self.sos_read.index("*statusOut") < log_at)
        self.assertRegex(self.sos_read, r"rd == telephony::BodyRead::TooBig[^;]*\)\s*break;",
                         "an oversize body is not retried: the same body would not fit again")
        self.assertIn("rd == telephony::BodyRead::AllocFailed", self.sos_read, "nor is a failed hand-back allocation")
        self.assertNotIn("bodyOut.assign", self.sos_read, "the helper assigns bodyOut, on Ok only")
        # the other failures rebuild the handle and retry once, as before
        self.assertRegex(self.sos_read, r"esp_http_client_cleanup\(client\);\s*client = nullptr;\s*continue;")

    def test_the_arena_is_reserved_with_the_handle_and_a_refusal_is_an_error(self):
        reserve = ("sosLane && !_sosBody.reserve(kSosBodyArenaBytes, &psram::allocPreferPsram, "
                   "&psram::freePreferPsram)")
        self.assertIn(reserve, self.get_body)
        at = self.get_body.index(reserve)
        self.assertLess(at, self.get_body.index("makeAuthedClient("), "reserved before the handle is built")
        self.assertRegex(self.get_body[at:at + 400], r"return false;")
        warm = code_only(body_of(self.src, "void TelephonyAnchorClient::warmStatusConnection("))
        self.assertIn("/*sosLane=*/true", warm, "start()'s warm GET is the first to reserve it")
        close = code_only(body_of(self.src, "void TelephonyAnchorClient::closeSosStatusClient("))
        self.assertIn("_sosBody.release();", close, "freed with the handle")

    def test_the_arena_size_comes_from_the_call_slot_count(self):
        self.assertIn("kSosBodyArenaBytes = telephony::sosBodyArenaBytes(POCKETDIAL_MAX_ANCHOR_CALLS);", self.hpp)

    def test_the_911_get_never_waits_for_the_claim(self):
        self.assertRegex(
            self.get_body,
            r"SosStatusClaim sosClaim\(sosLane \? &_sosStatusBusy : nullptr, telephony::kSosGetClaimBoundUs,[^;]*\);\s*"
            r"if \(!sosClaim\.held\(\)\)\s*\{\s*telephony::noteGetFallback\(_sosWitness, warm\);\s*return false;")
        self.assertNotIn("flag->exchange(true", code_only(self.src), "no claim spin is left in the anchor client")
        self.assertNotIn("struct SosStatusClaim", self.src)
        self.assertNotIn("vTaskDelay(1)", self.get_body)
        self.assertRegex(code_only(self.sos_hpp), r"kSosGetClaimBoundUs\s*=\s*0;", "a 911 waits for nothing")

    def test_a_bad_alloc_anywhere_in_the_911_get_is_an_error_not_a_terminate(self):
        sig = "bool TelephonyAnchorClient::httpGetBody("
        start = self.src.rindex(sig)
        body = body_of(self.src, sig)
        body_at = self.src.index(body, start)
        self.assertRegex(self.src[start + len(sig):body_at], r"\)\s*try\s*$", "a function-try-block")
        tail = self.src[body_at + len(body):]
        handler = code_only(tail[:tail.index("\n}\n")])
        self.assertRegex(handler, r"^\s*catch \(const std::bad_alloc&\)\s*\{")
        for needle in ("if (!sosLane) throw;", "bodyOut.clear();", "if (statusOut) *statusOut = -1;", "return false;"):
            self.assertIn(needle, handler)
        self.assertIn("catch (const std::bad_alloc&)", code_only(self.sos_hpp), "the hand-back assign has its own catch")

    def test_a_911_whose_list_reads_all_fail_is_refused_like_any_call(self):
        # The operator kept the 503 on #948 (adopting an unkeyed leg on the 911 lane is #977).
        make = code_only(body_of(self.src, "bool TelephonyAnchorClient::makeCall("))
        self.assertIn("telephony::readOwnLegWindow(", make)
        self.assertNotIn("unreadMakecallStep(", make, "the window loop lives in the host-tested helper")
        self.assertIn("telephony::unreadOutcome(!ownLeg.empty())", make, "no lane argument: one outcome for every call")
        self.assertNotIn("Proceed", make, "no branch lets a call go on with no own leg")
        self.assertNotIn("Proceed", code_only(self.sos_hpp))
        m = re.search(r"if \(outcome == telephony::UnreadOutcome::Adopt\)\s*\{.*?\n\t\t\}\n\t\telse\n\t\t\{(.*?)\n\t\t\}\n", make, re.S)
        self.assertIsNotNone(m, "the Adopt branch and the refusal that follows it")
        self.assertIn("ORPHANED on 3CX (#349/#328)", m.group(1), "the refusal")
        self.assertNotIn("success = true", m.group(1), "the refusal does not set success")

    def test_teardown_is_bounded_at_ten_ms_with_a_fallback(self):
        close = code_only(body_of(self.src, "void TelephonyAnchorClient::closeSosStatusClient("))
        self.assertRegex(close, r"telephony::closeWithinBound\(\s*_sosStatusBusy,\s*kSosTickUs,\s*sosNowUs,\s*sosPause,")
        self.assertIn("_sosWitness);", close)
        hpp = code_only(self.sos_hpp)
        bound = int(re.search(r"kSosClaimBoundUs\s*=\s*([\d']+);", hpp).group(1).replace("'", ""))
        self.assertLessEqual(bound, 10000, "the ruling's ceiling for closeSosStatusClient()")
        self.assertIn("SosStatusClaim claim(&flag, kSosClaimBoundUs,", body_of(hpp, "bool closeWithinBound("))

    def test_start_ends_with_the_heap_witness(self):
        start = code_only(body_of(self.src, "bool TelephonyAnchorClient::start("))
        tail = start[start.rindex("warmStatusConnection();"):]
        m = re.search(r'ESP_LOGI\(TAG, "start: free heap %u B, internal min free %u B, sos status arena %u B \(#948\)",'
                      r"\s*static_cast<unsigned>\(esp_get_free_heap_size\(\)\),"
                      r"\s*static_cast<unsigned>\(heap_caps_get_minimum_free_size\(MALLOC_CAP_INTERNAL\)\),"
                      r"\s*static_cast<unsigned>\(_sosBody\.capacity\(\)\)\);\s*return true;\s*\}\s*$", tail)
        self.assertIsNotNone(m, "the last statement of start() before its final return")

    def test_the_fallback_and_heap_witness_lines_are_the_ones_the_harness_counts(self):
        for needle in ("911 status handle: teardown claim not won within the bound, handle and arena left to the "
                       "in-flight GET (#948)",
                       "911 status GET: handle claim held, no status read, the call takes the conservative route (#948)"):
            self.assertIn(needle, self.sos_hpp)
            self.assertEqual(an.count_lines(["W (1) anchor: " + needle]).get(
                "sos_status_teardown_fallback_948" if "teardown" in needle else "sos_status_get_fallback_948"), 1)
        self.assertIn("kLinesPerSite = 3", self.sos_hpp, "capped per boot")

    def test_the_warm_get_follows_the_ws_connect_and_a_911_during_it_still_routes(self):
        start = code_only(body_of(self.src, "bool TelephonyAnchorClient::start("))
        self.assertEqual(start.count("warmStatusConnection();"), 1)
        warm_at = start.index("warmStatusConnection();")
        # after the token, so the warm GET reads HTTP 200 (the bench line), and after the WS connect
        self.assertGreater(warm_at, start.index("fetchToken()"))
        self.assertGreater(warm_at, start.index("connectWs()"), "the warm GET follows connectWs()")
        self.assertGreater(warm_at, start.index("startWsWorkers();"))
        self.assertGreater(warm_at, start.index("warmCtrlConnection();"), "main's order: ctrl warm, then status warm")
        self.assertLess(warm_at, start.index("createTaskPreferPsram("), "and before the slot pre-warm task")
        # _connected is set exactly where it was: only the WS connect event, never start()
        self.assertEqual(code_only(self.src).count("_connected.store(true"), 1)
        self.assertIn("_connected.store(true", code_only(body_of(self.src, "void TelephonyAnchorClient::handleWsEvent(")))
        self.assertNotIn("_connected", start.replace("_connected = false", ""), "start() does not touch _connected")
        # a 911 landing while the warm GET holds the sos claim is never refused for it: its status GET fails
        # at once (the claim, above), resolveDevice() fails, and makeCall() takes the legacy makecall endpoint
        make = code_only(body_of(self.src, "bool TelephonyAnchorClient::makeCall("))
        m = re.search(r"if \(deviceId\.empty\(\) && resolveDevice\(sosLane\)\)\s*\{(.*?)\n\t\}\n", make, re.S)
        self.assertIsNotNone(m, "the lazy device resolve")
        self.assertNotIn("return", m.group(1), "a refused resolveDevice() does not end the call")
        self.assertIn("std::string makeCallUrl = deviceId.empty() ? legacyUrl : deviceUrl(deviceId);", make,
                      "an unresolved device id means the legacy makecall endpoint")
        resolve = code_only(body_of(self.src, "bool TelephonyAnchorClient::resolveDevice("))
        self.assertRegex(resolve, r"if \(!httpGetBody\(url, body, &status, sosLane\) \|\| status != 200\)\s*\{[^}]*return false;")
        # makeCall() still refuses unless _running AND _connected, which the connect event satisfies
        self.assertRegex(make, r"!_running\.load\(std::memory_order_acquire\)\s*\|\|\s*"
                               r"!_connected\.load\(std::memory_order_acquire\)")

    def test_the_warm_get_is_not_a_911_and_logs_the_line_the_bench_gate_reads(self):
        warm = code_only(body_of(self.src, "void TelephonyAnchorClient::warmStatusConnection("))
        self.assertIn("httpGetBody(url, body, &status, /*sosLane=*/true, /*warm=*/true);", warm)
        self.assertIn('ESP_LOGI(TAG, "Sos status connection pre-warmed (HTTP %d)", status);', warm,
                      "the operator's bench gate looks for this line, with HTTP 200 on success")
        self.assertNotIn("_sosWitness", warm, "the warm GET records no 911 fallback")
        self.assertRegex(code_only(self.sos_hpp), r"inline void noteGetFallback\(SosWitness& witness, bool warm\)\s*\{\s*"
                                                  r"if \(!warm\) witness\.note\(SosFallback::Get\);")

    def test_the_largest_sos_body_is_witnessed(self):
        self.assertLess(self.sos_read.index("esp_http_client_get_content_length(client)"),
                        self.sos_read.index("telephony::readSosBody("), "read before the connection is closed")
        ok_at = self.sos_read.index("rd == telephony::BodyRead::Ok")
        self.assertTrue(ok_at < self.sos_read.index("_sosBodyWitness.noteBody(bodyOut.size(), _sosBody.capacity());")
                        < self.sos_read.index("ESP_LOGE("))
        self.assertIn("if (rd == telephony::BodyRead::TooBig) _sosBodyWitness.noteOversize(contentLen, _sosBody.capacity());",
                      self.sos_read)
        hpp = code_only(self.sos_hpp)
        self.assertIn("kLinesPerKind = 8", hpp)
        for line, counter in (("911 status body: %u B, the largest this boot, in a %u B arena (#948)",
                               "sos_status_body_max_948"),
                              ("911 status body over the %u B arena: content-length %lld B, -1 is unknown (#948)",
                               "sos_status_body_oversize_948")):
            self.assertIn(line, self.sos_hpp)
            self.assertIn(counter, an.LOG_COUNTERS)
        sample = "I (9300) anchor: 911 status body: 612 B, the largest this boot, in a 12288 B arena (#948)"
        self.assertEqual(an.count_lines([sample])["sos_status_body_max_948"], 1)
        sample = ("W (9301) anchor: 911 status body over the 12288 B arena: content-length 13000 B, "
                  "-1 is unknown (#948)")
        self.assertEqual(an.count_lines([sample])["sos_status_body_oversize_948"], 1)


if __name__ == "__main__":
    unittest.main()

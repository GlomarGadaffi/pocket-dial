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
            r"SosStatusClaim sosClaim\(sosLane \? &_sosStatusBusy : nullptr, /\*boundUs=\*/0,[^;]*\);\s*"
            r"if \(!sosClaim\.held\(\)\)\s*\{\s*_sosWitness\.note\(telephony::SosFallback::Get\);\s*return false;")
        self.assertNotIn("flag->exchange(true", code_only(self.src), "no claim spin is left in the anchor client")
        self.assertNotIn("struct SosStatusClaim", self.src)
        self.assertNotIn("vTaskDelay(1)", self.get_body)

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


if __name__ == "__main__":
    unittest.main()

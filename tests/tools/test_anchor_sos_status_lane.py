"""#941 (Rule 5): a 911/933 makeCall() must never wait on _statusMutex. httpGetBody()
holds that mutex across esp_http_client_open and esp_http_client_read (2 s timeouts),
and makeCall() reaches it through resolveDevice() and resolveOutboundLeg(), so a 911
queued behind any other task's status GET. The emergency lane now drives its own
handle (_sosStatusClient, built at start()) under a lock-free claim. The anchor client
is ESP-only, so this pins the wiring."""
import os
import re
import unittest

from test_anchor_own_leg_not_inbound import body_of, code_only

SRC = os.path.join(os.path.dirname(__file__), "..", "..", "src", "SIP", "TelephonyAnchorClient.cpp")
HPP = os.path.join(os.path.dirname(__file__), "..", "..", "src", "SIP", "SosStatusGet.hpp")   # #948: the claim lives here


class AnchorSosStatusLaneTest(unittest.TestCase):
    def setUp(self):
        with open(SRC, encoding="utf-8") as f:
            self.src = f.read()
        self.get_body = code_only(body_of(self.src, "bool TelephonyAnchorClient::httpGetBody("))
        self.make = code_only(body_of(self.src, "bool TelephonyAnchorClient::makeCall("))
        self.resolve_leg = code_only(body_of(self.src, "std::string TelephonyAnchorClient::resolveOutboundLeg("))
        self.resolve_dev = code_only(body_of(self.src, "bool TelephonyAnchorClient::resolveDevice("))

    def test_ordinary_status_gets_are_unchanged(self):
        # Positive control: every other caller still goes through the shared, mutex-guarded handle.
        self.assertIn("_statusMutex", self.get_body)
        self.assertIn("_statusClient", self.get_body)
        for sig in ("std::string TelephonyAnchorClient::getLegStatus(",
                    "std::string TelephonyAnchorClient::reconcileParticipantId(",
                    "std::string TelephonyAnchorClient::getParticipantCaller("):
            self.assertIn("httpGetBody(url, body, &status)", body_of(self.src, sig), sig)

    def test_the_sos_lane_never_takes_the_status_mutex(self):
        self.assertIn("sosLane ? _sosStatusClient : _statusClient", self.get_body,
                      "the emergency lane must drive its own handle")
        self.assertRegex(self.get_body, r"if \(!sosLane\)\s*statusLock\.lock\(\);",
                         "_statusMutex may be taken only off the emergency lane")
        self.assertNotRegex(self.get_body, r"lock_guard<std::mutex>\s+\w+\(_statusMutex\)",
                            "an unconditional lock_guard on _statusMutex is the #941 wait")
        self.assertIn("defer_lock", self.get_body)

    def test_the_sos_lane_holds_no_mutex_across_its_io(self):
        self.assertIn("telephony::SosStatusClaim sosClaim(sosLane ? &_sosStatusBusy : nullptr,", self.get_body,
                      "exclusion on the sos handle is the lock-free claim")
        with open(HPP, encoding="utf-8") as f:
            claim_hpp = code_only(f.read())
        self.assertIn("exchange(true", body_of(claim_hpp, "bool claimWithin("))
        self.assertNotRegex(claim_hpp, r"mutex|lock_guard|unique_lock")

    def test_makecall_marks_an_emergency_and_forwards_it_to_both_resolvers(self):
        self.assertIn("const bool sosLane = pbx::classifyEmergencyDial(destination).isEmergency;", self.make)
        self.assertEqual(self.make.count("resolveDevice(sosLane)"), 2,
                         "both the lazy resolve and the stale-device re-resolve")
        self.assertNotIn("resolveDevice()", self.make)
        self.assertIn("httpGetBody(url, body, &status, sosLane)", self.resolve_dev)
        self.assertIn("httpGetBody(url, body, &status, pbx::classifyEmergencyDial(destination).isEmergency)",
                      self.resolve_leg, "the fallback list read is the 911's other status GET")

    def test_the_sos_handle_is_built_at_init_and_freed_at_teardown(self):
        warm = code_only(body_of(self.src, "void TelephonyAnchorClient::warmStatusConnection("))
        self.assertIn("httpGetBody(url, body, &status, /*sosLane=*/true, /*warm=*/true)", warm,
                      "start() must build the sos handle, so the first 911 resumes a warm session")
        shutdown = code_only(body_of(self.src, "void TelephonyAnchorClient::shutdownImpl("))
        self.assertIn("closeSosStatusClient();", shutdown)
        close = code_only(body_of(self.src, "void TelephonyAnchorClient::closeSosStatusClient("))
        self.assertRegex(close, r"telephony::closeWithinBound\(\s*_sosStatusBusy,",
                         "teardown must not free the handle under an in-flight 911 GET")
        self.assertIn("esp_http_client_cleanup(_sosStatusClient);", close)


if __name__ == "__main__":
    unittest.main()

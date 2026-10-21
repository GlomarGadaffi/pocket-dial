"""#949 item 1 (Rule 5): the tel_wsw worker's outbound Connected -> Answered read used to go through
getLegStatus() -> httpGetBody() on the shared lane, so a 911's Answered waited on _statusMutex behind
any other status GET (#941/#948 moved only makeCall off it). The worker now reads on the sos lane for
a slot whose emergency number is set, and an empty read there is UNKNOWN: never answered, never the
dialing branch. The anchor client is ESP-only; the decisions are host-tested in
tests/OutboundLegStatus_test.cpp, this pins that the worker calls them."""
import os
import unittest

from test_anchor_own_leg_not_inbound import body_of, code_only

SRC = os.path.join(os.path.dirname(__file__), "..", "..", "src", "SIP", "TelephonyAnchorClient.cpp")
HPP = os.path.join(os.path.dirname(__file__), "..", "..", "src", "SIP", "TelephonyAnchorClient.hpp")


class AnchorLegStatusSosLaneTest(unittest.TestCase):
    def setUp(self):
        with open(SRC, encoding="utf-8") as f:
            self.src = f.read()
        with open(HPP, encoding="utf-8") as f:
            self.hpp = code_only(f.read())
        self.get_leg = code_only(body_of(self.src, "std::string TelephonyAnchorClient::getLegStatus("))
        self.worker = code_only(body_of(self.src, "void TelephonyAnchorClient::processWsWork("))

    def test_get_leg_status_takes_a_lane_and_forwards_it(self):
        self.assertIn("std::string getLegStatus(const std::string& legId, bool sosLane = false);", self.hpp)
        self.assertIn("httpGetBody(url, body, &status, sosLane)", self.get_leg)

    def test_the_worker_reads_through_the_bounded_lane_chooser_for_an_emergency_slot(self):
        self.assertIn("telephony::readOutboundLegStatus(emergency,", self.worker)
        self.assertIn("getLegStatus(controlLeg, sosLane)", self.worker)
        self.assertIn("s->emergency.load(std::memory_order_acquire) != 0", self.worker)

    def test_an_unknown_read_neither_answers_nor_takes_the_dialing_branch(self):
        self.assertIn("telephony::outboundStep(statusStr, emergency)", self.worker)
        self.assertIn("OutboundStep::Unknown", self.worker)
        self.assertIn("OutboundStep::Answered", self.worker)
        unknown = self.worker.index("OutboundStep::Unknown")
        dialing_pre_warm = self.worker.index("startRxIfNeeded(controlLeg);")
        self.assertLess(unknown, dialing_pre_warm, "Unknown is handled before the dialing branch")

    def test_ordinary_callers_still_use_the_shared_lane(self):
        # Positive control: the other readers pass no lane, so they keep _statusMutex.
        for sig in ("std::string TelephonyAnchorClient::reconcileParticipantId(",
                    "std::string TelephonyAnchorClient::getParticipantCaller("):
            self.assertIn("httpGetBody(url, body, &status)", body_of(self.src, sig), sig)


if __name__ == "__main__":
    unittest.main()

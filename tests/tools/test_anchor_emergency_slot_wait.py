"""#743: a 911/933 whose call slot is still tearing down (the victim of a #624
pre-emption on the async anchor, or a call that ended just before the 911 was
dialed) must not lose its ring-time rx prime to that race. makeCall() keeps
asking startRxIfNeeded() for the slot through pd::emergencySlotRetryContinues
(RxRestart.hpp, pinned by RxRestart_test.cpp) instead of giving up on the first
refusal, then re-checks the leg once, because an upsert that landed during the
wait was ignored. The anchor client is ESP-only, so this pins the wiring."""
import os
import re
import unittest

SRC = os.path.join(os.path.dirname(__file__), "..", "..", "src", "SIP", "TelephonyAnchorClient.cpp")


def body_of(src, signature):
    start = src.rindex(signature)   # the last definition: the early one is the host stub
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


class AnchorEmergencySlotWaitTest(unittest.TestCase):
    def setUp(self):
        with open(SRC, encoding="utf-8") as f:
            self.src = f.read()
        self.make_call = body_of(self.src, "bool TelephonyAnchorClient::makeCall(")

    def test_make_call_keeps_asking_for_the_slot_for_an_emergency(self):
        self.assertIn("all %d call slots busy", self.make_call,
                      "positive control: the busy log for an ordinary call is still there")
        self.assertIn("pd::emergencySlotRetryContinues(", self.make_call,
                      "makeCall() must retry the slot through the pinned policy")
        self.assertIn("classifyEmergencyDial(destination)", self.make_call,
                      "the retry is keyed on the dialed number, not on a flag nobody sets")
        self.assertRegex(self.make_call,
                         r"while \(pd::emergencySlotRetryContinues\([^)]*\)\)\s*\{[^}]*startRxIfNeeded\(ownLeg\)",
                         "the loop must re-ask startRxIfNeeded() for the same leg")

    def test_the_wait_runs_off_the_client_mutex(self):
        # startRxIfNeeded() takes _mutex itself, and the teardown that frees the
        # slot (freeSlotLocked) runs under _mutex too: a poll that held it could
        # never see the slot come free.
        m = re.search(r"while \(pd::emergencySlotRetryContinues\([^)]*\)\)\s*\{[^}]*\}", self.make_call)
        self.assertIsNotNone(m, "no retry loop in makeCall()")
        self.assertNotIn("lock(_mutex)", m.group(0))
        self.assertIn("vTaskDelay(", m.group(0), "the poll must yield between asks")

    def test_a_prime_that_waited_rechecks_the_leg_once(self):
        # While the wait runs, _outboundPending > 0 makes handleWsEvent() ignore an
        # upsert for this unkeyed leg, and Telephony does not repeat a Connected
        # one: without a re-check, a 911 answered during the wait never fires
        # Answered. Only a prime that waited queues it (an ordinary call is as before).
        tail = self.make_call[self.make_call.index("while (pd::emergencySlotRetryContinues("):]
        self.assertRegex(tail, r"if \(primed && waitedUs > 0\)",
                         "the re-check must be gated on a prime that actually waited")
        recheck = tail[tail.index("if (primed && waitedUs > 0)"):]
        self.assertIn("upsetInFlight.exchange(true", recheck,
                      "it must take the same single-flight claim handleWsEvent() takes")
        self.assertIn("item->kind       = WsWork::Upset;", recheck)
        self.assertIn("item->controlLeg = ownLeg;", recheck)
        self.assertIn("enqueueWsWork(item)", recheck)
        self.assertRegex(recheck, r"upsetInFlight\.store\(false",
                         "a refused enqueue must release the claim, or the leg's upserts wedge")


if __name__ == "__main__":
    unittest.main()

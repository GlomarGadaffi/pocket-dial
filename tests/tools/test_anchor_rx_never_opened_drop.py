"""#379: when 3CX refuses the GET stream for the whole retry budget, runRxLoop must
report CallEvent::MediaNeverOpened, and RequestsHandler's anchor callback must hand it
to anchorMediaNeverOpenedLocked() (its drop/keep decision is pinned by
AnchorRouting_test.cpp). The anchor client is ESP-only and the callback is wired only
for a real anchor, so no host test reaches this wiring."""
import os
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


class AnchorRxNeverOpenedDropTest(unittest.TestCase):
    longMessage = False   # a failure prints its reason, not all of runRxLoop

    def setUp(self):
        tac = read("TelephonyAnchorClient.cpp")
        self.rx = body_of(tac, "void TelephonyAnchorClient::runRxLoop(")
        self.drop = body_of(tac, "bool TelephonyAnchorClient::dropCall(")
        self.rh = read("RequestsHandler.cpp")

    def test_a_spent_budget_reports_the_leg(self):
        self.assertIn("stream never opened", self.rx, "positive control: this is runRxLoop")
        at = self.rx.find("if (attempt >= kMaxAttempts && keepRunning())")
        self.assertNotEqual(at, -1, "only a spent budget with no teardown under way reports the leg")
        self.assertIn("CallEvent::MediaNeverOpened", self.rx[at:at + 400])
        # Never dropCall()/stopMediaStreams() here: they join this very task (2 s, then detach).
        self.assertIn("stopMediaStreams(", self.drop, "positive control: dropCall joins the rx task")
        self.assertNotIn("dropCall(", self.rx)
        self.assertNotIn("stopMediaStreams(", self.rx)

    def test_the_anchor_callback_routes_it(self):
        self.assertRegex(self.rh, r"CallEvent::MediaNeverOpened\)\s*\{\s*anchorMediaNeverOpenedLocked\(ev\.participantId\);",
                         "the anchor event callback must hand MediaNeverOpened to its handler")


if __name__ == "__main__":
    unittest.main()

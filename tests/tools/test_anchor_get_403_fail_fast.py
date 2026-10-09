"""#902: a run of 403s on the media GET stream gives up after
telephony::kGetForbiddenMaxAfterAnswer attempts, not after the whole budget, for
an ordinary outbound leg only. The decision is pinned by TelephonyAnchorLogic_test.cpp;
this pins its wiring into the ESP-only TelephonyAnchorClient, which no host test
compiles: the rx loop feeds every parsed status to it, a give-up takes the existing
spent-budget path (MediaNeverOpened), and only makeCall's non-emergency leg is marked."""
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


class AnchorGet403FailFastTest(unittest.TestCase):
    longMessage = False

    def setUp(self):
        tac = read("TelephonyAnchorClient.cpp")
        self.rx = body_of(tac, "void TelephonyAnchorClient::runRxLoop(")
        self.make = body_of(tac, "bool TelephonyAnchorClient::makeCall(")
        self.free = body_of(tac, "void TelephonyAnchorClient::freeSlotLocked(")

    def test_the_rx_loop_counts_403s_after_the_answer_and_gives_up_by_the_spent_budget_path(self):
        self.assertRegex(self.rx, r"forbiddenAfterAnswer\s*=\s*telephony::nextGetForbiddenCount\(\s*"
                                  r"forbiddenAfterAnswer,\s*status\)")
        at = self.rx.find("telephony::getForbiddenGivesUp(")
        self.assertNotEqual(at, -1)
        self.assertIn("slot->getFailFast.load", self.rx[at:at + 200])
        tail = self.rx[at:at + 900]
        self.assertRegex(tail, r"attempt\s*=\s*kMaxAttempts;\s*break;",
                         "a give-up must reach the existing MediaNeverOpened report, not a new path")
        self.assertIn("if (attempt >= kMaxAttempts && keepRunning())", self.rx)

    def test_the_count_sits_with_the_parsed_answers_only(self):
        parsed = self.rx.find("if (telephony::httpResponseParsed(status))")
        give = self.rx.find("telephony::getForbiddenGivesUp(")
        transport = self.rx.find("transport failure (no HTTP response")
        self.assertTrue(0 <= parsed < give < transport, "the 403 count belongs to a real HTTP answer")

    def test_only_makecalls_non_emergency_leg_is_marked_and_a_freed_slot_is_cleared(self):
        self.assertRegex(self.make, r"getFailFast\.store\(\s*!emergency")
        self.assertIn("getFailFast.store(false", self.free)
        others = [m.start() for m in re.finditer(r"getFailFast\.store\(", read("TelephonyAnchorClient.cpp"))]
        self.assertEqual(len(others), 2, "no other path may mark a leg fail-fast")


if __name__ == "__main__":
    unittest.main()

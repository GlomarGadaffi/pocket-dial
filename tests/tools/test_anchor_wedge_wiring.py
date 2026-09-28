"""#667: tick() must count a wedged outbound slot through pd::anchorSlotLooksWedged,
and the outbound upset path must mark a listed (Dialing) leg as ringing. The anchor
client is ESP-only, so no host test can reach tick(); this pins the wiring that
AnchorWedge_test.cpp's predicate depends on."""
import os
import re
import unittest

SRC = os.path.join(os.path.dirname(__file__), "..", "..", "src", "SIP", "TelephonyAnchorClient.cpp")


def body_of(src, signature):
    start = src.rindex(signature)   # the last definition: line ~62 is the host stub
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


class AnchorWedgeWiringTest(unittest.TestCase):
    def setUp(self):
        self.src = open(SRC, encoding="utf-8").read()

    def test_tick_uses_the_predicate(self):
        tick = body_of(self.src, "void TelephonyAnchorClient::tick(")
        self.assertIn("tel_reconcile", tick, "positive control: tick() spawns the reconcile worker")
        self.assertIn("pd::anchorSlotLooksWedged(", tick)
        self.assertIn("ringing.load(", tick)
        self.assertNotRegex(tick, r"nowUs\s*-\s*s\.outboundActiveSetUs\s*>=",
                            "tick() must not keep its own inline wedge test")

    def test_listed_outbound_leg_is_marked_ringing(self):
        m = re.search(r"if \(!statusStr\.empty\(\)\)\s*\{[^}]*ringing\.store\(true", self.src)
        self.assertIsNotNone(m, "the outbound upset path must set ringing for a listed leg")

    def test_ringing_is_cleared_with_the_outbound_flags(self):
        free = body_of(self.src, "void TelephonyAnchorClient::freeSlotLocked(")
        self.assertIn("outboundActive.store(false", free, "positive control")
        self.assertIn("ringing.store(false", free)


if __name__ == "__main__":
    unittest.main()

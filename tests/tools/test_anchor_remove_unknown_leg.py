"""#1097: a WS "Participant Remove" that names no call slot must end no call.
processWsWork()'s Remove branch used to fall back to the only active slot
("if (active == 1) dropLeg = only->participantId;"), so a Remove for another
handset's refused makecall (the #1095 race) stopped a live 911's media and
reported it Dropped, and RequestsHandler BYEd it. The decision is now
telephony::removeTargetSlot() (TelephonyAnchorLogic.hpp, pinned by
TelephonyAnchorLogic_test.cpp RemoveTarget.*). processWsWork() is ESP-only, so
no host test reaches the wiring; this pins where the decision is applied."""
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


class AnchorRemoveUnknownLegTest(unittest.TestCase):
    longMessage = False

    def setUp(self):
        work = body_of(read("TelephonyAnchorClient.cpp"), "void TelephonyAnchorClient::processWsWork(")
        self.assertIn("if (w.kind == WsWork::Remove)", work, "positive control: the Remove branch")
        self.remove = body_of(work, "if (w.kind == WsWork::Remove)")

    def test_the_slot_comes_from_the_pure_decision(self):
        self.assertIn("telephony::removeTargetSlot(_calls, w.partId)", self.remove,
                      "the Remove branch must take its slot from telephony::removeTargetSlot()")
        self.assertIn("dropLeg = _calls[", self.remove, "the dropped leg is the chosen slot's own leg")

    def test_no_only_active_slot_fallback(self):
        self.assertIn("dropLeg", self.remove, "positive control: the branch names a leg to drop")
        for shape in ("active == 1", "only->participantId", "active++", "++active"):
            self.assertNotIn(shape, self.remove,
                             "a Remove that names no slot must not fall back to the only active call: " + shape)

    def test_media_stops_only_for_the_chosen_slot(self):
        guard = self.remove.find("if (!dropLeg.empty())")
        self.assertNotEqual(guard, -1, "positive control: the drop is guarded on a chosen slot")
        stop = self.remove.find("stopMediaStreams(")
        self.assertGreater(stop, guard, "stopMediaStreams() runs only for a chosen slot")
        self.assertEqual(self.remove.count("stopMediaStreams("), 1, "one media stop, for the chosen slot")
        self.assertIn("stopMediaStreams(dropLeg)", self.remove)

    def test_an_unmatched_remove_still_reports_its_own_id(self):
        # #533: a Remove that names no slot is reported Dropped for ITS id, which RequestsHandler
        # matches by participant id: a no-op for an unknown leg, a BYE for a live session's leg.
        unmatched = self.remove.find("else", self.remove.find("if (!dropLeg.empty())"))
        self.assertNotEqual(unmatched, -1, "positive control: the #533 branch")
        self.assertIn("CallEvent ev{CallEvent::Dropped, w.partId", self.remove[unmatched:],
                      "an unmatched Remove reports its own id, never a slot's")


if __name__ == "__main__":
    unittest.main()

"""#379/#681: an upsert for a leg this PBX created must never be announced as an
inbound call. The decision is telephony::inboundAnnounceAllowed() over
telephony::AnchorOwnLegs (TelephonyAnchorLogic.hpp, pinned by
TelephonyAnchorLogic_test.cpp). The anchor client that applies it is ESP-only, so
no host test reaches the wiring; this pins where it is applied, and that the hold
stays bounded."""
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


GATE = "telephony::inboundAnnounceAllowed(_ownLegs, "


class AnchorOwnLegNotInboundTest(unittest.TestCase):
    longMessage = False   # a failure prints its reason, not the whole function

    def setUp(self):
        tac = read("TelephonyAnchorClient.cpp")
        self.make = body_of(tac, "bool TelephonyAnchorClient::makeCall(")
        self.drop = body_of(tac, "bool TelephonyAnchorClient::dropCall(")
        self.free = body_of(tac, "void TelephonyAnchorClient::freeSlotLocked(")
        self.work = body_of(tac, "void TelephonyAnchorClient::processWsWork(")
        self.ws = body_of(tac, "void TelephonyAnchorClient::handleWsEvent(")
        self.resolve = body_of(tac, "std::string TelephonyAnchorClient::resolveOutboundLeg(")

    def test_the_makecall_response_makes_the_leg_ours_before_it_is_keyed(self):
        keyed = self.make.find("startRxIfNeeded(ownLeg)")
        self.assertNotEqual(keyed, -1, "positive control: makeCall keys its own leg")
        named = self.make.find("_ownLegs.noteNamed(ownLeg, esp_timer_get_time(), postSeq)")
        self.assertNotEqual(named, -1, "makeCall must note the leg the makecall response named")
        self.assertLess(named, keyed, "noted before the slot is keyed, so no window is uncovered")
        self.assertIn("telephony::ownLegMayBeHeld(ownLegSource)", self.make[:named],
                      "only a leg 3CX named as ours is held, never the list fallback's guess")
        took = self.make.find("postSeq = _wsSeq;")
        self.assertNotEqual(took, -1, "makeCall must take the WS event number before its makecall goes out")
        self.assertLess(took, self.make.find("httpPostBody("),
                        "a Remove received after the makecall went out may be this leg's own")

    def test_a_freed_outbound_slot_hands_its_leg_to_the_table(self):
        cleared = self.free.find("slot.participantId.clear()")
        self.assertNotEqual(cleared, -1, "positive control: freeSlotLocked clears the slot")
        noted = self.free.find("_ownLegs.note(slot.participantId, ")
        self.assertNotEqual(noted, -1, "freeSlotLocked must note an outbound slot's leg")
        self.assertLess(noted, cleared, "noted before the id is cleared")
        self.assertIn("slot.ownLegHeld", self.free[:noted], "only a slot whose leg 3CX named as ours")
        self.assertIn("slot.ownLegHeld = false;", self.free,
                      "a freed slot must not pass the flag to the next call, which may be inbound")
        self.assertNotIn("farPartId", self.free[:noted], "a far-leg id can be a genuine inbound call's")

    def test_a_drop_never_makes_a_leg_ours(self):
        self.assertIn("_droppedLegs.add(partId);", self.drop, "positive control: this is dropCall")
        self.assertIn("_ownLegs.refresh(partId, ", self.drop, "a drop holds a leg already ours")
        self.assertNotIn("_ownLegs.note(", self.drop,
                         "dropCall also drops refused inbound legs; noting them would hold back a PSAP callback")

    def test_the_list_fallback_reports_where_the_leg_came_from(self):
        for src in ("OwnLegSource::MakecallResult", "OwnLegSource::OwnPartyDn",
                    "OwnLegSource::FirstControllable"):
            self.assertIn(src, self.resolve, "resolveOutboundLeg must report " + src)
        self.assertIn("slot->ownLegHeld = ownLegHeld;", self.make, "makeCall marks a slot whose leg 3CX named as ours")

    def test_a_remove_releases_the_leg_in_ws_order(self):
        start = self.ws.find("else if (evTypeNum == TEL_EV_REMOVE)")
        end = self.ws.find("else if (evTypeNum == TEL_EV_DTMF)")
        self.assertTrue(0 <= start < end, "positive control: the Remove branch")
        branch = self.ws[start:end]
        released = branch.find("_ownLegs.release(partId, ++_wsSeq);")
        self.assertNotEqual(released, -1, "3CX's Remove must release the id at receipt, in WS order")
        self.assertLess(released, branch.find("enqueueWsWork(item)"))
        noted = branch.find("_ownLegs.note(partId, ")
        self.assertTrue(0 <= noted < released,
                        "a live own slot's leg is noted before the release, or a re-created entry loses it")
        start = self.work.find("if (w.kind == WsWork::Remove)")
        end = self.work.find("std::string controlLeg = w.controlLeg;")
        self.assertTrue(0 <= start < end, "positive control: the Remove branch precedes the Upset body")
        self.assertNotIn("_ownLegs.", self.work[start:end], "a Remove must not hold the id again")

    def test_queued_work_carries_its_ws_order(self):
        seq = self.ws.find("seq = ++_wsSeq;")
        self.assertNotEqual(seq, -1, "each upsert takes its WS sequence number under the classifier's lock")
        self.assertLess(seq, self.ws.find(GATE + "partId, "))
        self.assertIn(GATE + "partId, esp_timer_get_time(), seq)", self.ws)
        self.assertRegex(self.ws, r"item->seq\s*=\s*seq;", "a queued upsert carries its WS sequence number")
        self.assertIn(GATE + "controlLeg, esp_timer_get_time(), w.seq)", self.work,
                      "the worker judges an item by when it was received, not when it runs")

    def test_the_worker_checks_before_it_claims_a_slot_or_announces(self):
        claim = self.work.find("allocSlotLocked(controlLeg)")
        announce = self.work.find("CallEvent::Incoming")
        self.assertTrue(0 <= claim < announce, "positive control: the inbound branch claims, then announces")
        gate = self.work.find(GATE + "controlLeg, ")
        self.assertNotEqual(gate, -1, "the inbound branch must ask before it claims a slot")
        self.assertLess(gate, claim)
        lock = self.work.rfind("std::lock_guard<std::mutex> lock(_mutex);", 0, gate)
        between = self.work[lock:claim]
        self.assertTrue(lock != -1 and "{" not in between and "}" not in between,
                        "the check and the claim must be one _mutex hold")

    def test_the_worker_skips_media_for_its_own_leg_and_does_not_extend_the_hold(self):
        m = re.search(r"if \(ownLeg\)\s*\{([^{}]*)\}\s*else\s*\{\s*startMediaStreams\(controlLeg\);\s*\}", self.work)
        self.assertIsNotNone(m, "an own leg must not get startMediaStreams()")
        self.assertNotIn("_ownLegs.", m.group(1), "a suppressed upsert must not extend the hold (bounded)")

    def test_the_ws_classifier_checks_an_unkeyed_upset_first(self):
        m = re.search(r"if \(s\)\s*\{\s*controlLegs\[nLegs\+\+\] = partId;\s*\}\s*else if \(!"
                      + re.escape(GATE) + r"partId, [^\n]*\)\s*\{([^{}]*)\}\s*else\s*\{", self.ws)
        self.assertIsNotNone(m, "an unkeyed upset for our own leg must be ignored before the in-flight mapping")
        self.assertNotIn("_ownLegs.", m.group(1), "a suppressed upsert must not extend the hold (bounded)")
        self.assertNotIn("controlLegs[", m.group(1))
        self.assertIn("if (pending == 0) controlLegs[nLegs++] = partId;", self.ws,
                      "every other upset is classified exactly as before")


if __name__ == "__main__":
    unittest.main()

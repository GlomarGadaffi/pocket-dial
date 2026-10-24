"""#1095: a leg 3CX removed after the makecall went out, before its response named
it, must fail the call at once: no slot, no GET stream, and the caller answered
by runTelCtl()'s makeCall-failed path (503; NOT ROUTED for a 911/933). The
decision is telephony::OwnLegs::removedSince() (TelephonyAnchorLogic.hpp, pinned
by TelephonyAnchorLogic_test.cpp). makeCall() is ESP-only, so no host test
reaches the wiring; this pins where it is applied."""
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


class AnchorRemovedBeforeNamedTest(unittest.TestCase):
    longMessage = False

    def setUp(self):
        self.make = body_of(read("TelephonyAnchorClient.cpp"), "bool TelephonyAnchorClient::makeCall(")
        self.run_tel_ctl = body_of(read("RequestsHandler.cpp"), "void RequestsHandler::runTelCtl(")

    def test_a_removed_leg_fails_the_call_before_any_slot_or_stream(self):
        named = self.make.find("_ownLegs.noteNamed(ownLeg, esp_timer_get_time(), postSeq)")
        keyed = self.make.find("startRxIfNeeded(ownLeg)")
        self.assertNotEqual(named, -1, "positive control: makeCall notes the leg the response named")
        self.assertNotEqual(keyed, -1, "positive control: makeCall keys its own leg")
        check = self.make.find("_ownLegs.removedSince(ownLeg, postSeq)", named)
        self.assertNotEqual(check, -1, "makeCall must ask whether 3CX removed the named leg during the makecall")
        self.assertLess(check, keyed, "asked before the slot is keyed and the GET stream primed")
        between = self.make[check:keyed]
        self.assertIn("return false;", between, "a removed leg must fail the call before its slot is keyed")
        self.assertIn("ownLegOut->clear()", between, "a failed call hands the engine no leg to bind")

    def test_a_911_is_failed_the_same_way_not_exempted(self):
        check = self.make.find("_ownLegs.removedSince(ownLeg, postSeq)")
        self.assertNotEqual(check, -1, "makeCall must ask whether 3CX removed the named leg")
        sos_wait = self.make.find("pd::emergencySlotRetryContinues(")
        self.assertNotEqual(sos_wait, -1, "positive control: the #743 911/933 slot wait")
        self.assertLess(check, sos_wait, "decided before the 911/933 slot wait, which would only delay the answer")
        guard = self.make[self.make.rfind("if (", 0, check):check]
        for word in ("sosDial", "sosLane", "emergency", "isEmergency"):
            self.assertNotIn(word, guard, "the check must not depend on the call being a 911/933")

    def test_the_failed_makecall_answers_the_caller(self):
        failed = self.run_tel_ctl.find("if (!_anchorClient->makeCall(job.dest, &ownLeg))")
        self.assertNotEqual(failed, -1, "positive control: runTelCtl's makeCall-failed branch")
        branch = self.run_tel_ctl[failed:self.run_tel_ctl.index("return;", failed)]
        self.assertIn("refuseRingingAnchor(job.callId, _asyncOutbox)", branch, "the caller gets its final 503")
        self.assertIn("/*routed=*/false", branch, "a 911/933 is reported NOT ROUTED")


class AnchorRemovedBeforeBindTest(unittest.TestCase):
    """The backstop for a Remove received after makeCall()'s check, before the engine
    binds the leg (EmergencyNotify_test.cpp AnchorLegRemovedBeforeBind drives the
    engine side). Its proof rests on three ESP-only facts pinned here."""
    longMessage = False

    def setUp(self):
        self.client = read("TelephonyAnchorClient.cpp")
        self.query = body_of(self.client, "bool TelephonyAnchorClient::ownLegRemovedSinceNamed(")
        self.run_tel_ctl = body_of(read("RequestsHandler.cpp"), "void RequestsHandler::runTelCtl(")

    def test_the_ws_task_records_a_remove_before_it_queues_the_dropped(self):
        remove = self.client.find("else if (evTypeNum == TEL_EV_REMOVE)")
        self.assertNotEqual(remove, -1, "positive control: the WS task's Remove branch")
        released = self.client.find("_ownLegs.release(partId, ++_wsSeq);", remove)
        queued = self.client.find("item->kind   = WsWork::Remove;", remove)
        self.assertNotEqual(released, -1, "the Remove must be recorded on the WS task")
        self.assertNotEqual(queued, -1, "positive control: the Remove is queued for the worker")
        self.assertLess(released, queued,
                        "recorded before the worker can report Dropped, or the backstop has a window")
        self.assertIn("std::lock_guard<std::mutex> lock(_mutex);", self.client[remove:released])

    def test_the_esp_query_is_a_locked_lookup_with_no_io_or_allocation(self):
        self.assertIn("std::lock_guard<std::mutex> lock(_mutex);", self.query)
        self.assertIn("_ownLegs.removedSinceNamed(ownLeg)", self.query)
        for word in ("new ", "std::string ", "http", "vTaskDelay", "evCb", "_eventCb"):
            self.assertNotIn(word, self.query, "the query must stay a lookup: " + word)

    def test_run_tel_ctl_asks_after_the_bind_outside_its_lock_and_fails_once(self):
        bind = self.run_tel_ctl.find("bindOutboundParticipant(job.callId, ownLeg)")
        ask = self.run_tel_ctl.find("_anchorClient->ownLegRemovedSinceNamed(ownLeg)")
        lock = self.run_tel_ctl.find("std::lock_guard<pd::TimedMutex> lock(_mutex);", bind)
        self.assertNotEqual(bind, -1, "positive control: the bind")
        self.assertNotEqual(ask, -1, "runTelCtl must ask whether 3CX removed the bound leg")
        self.assertLess(bind, ask, "asked after the bind: a Remove it misses is matched by #880")
        self.assertLess(ask, lock, "asked outside RequestsHandler's _mutex: no nested anchor lock")
        self.assertIn("bound &&", self.run_tel_ctl[bind:lock], "only a bound leg is asked about")
        branch = self.run_tel_ctl[lock:]
        self.assertIn("anchorDroppedLocked(ownLeg);", branch, "the missed Dropped is replayed for this leg only")
        for word in ("sosLane", "isEmergency", "emergency"):
            self.assertNotIn(word, self.run_tel_ctl[ask - 60:ask + 60], "no 911/933 exemption or gate")


if __name__ == "__main__":
    unittest.main()

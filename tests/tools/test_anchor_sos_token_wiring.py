"""#862 (operator rulings on #945): the ESP arm of the 911/933 token rules. The decisions are
host-compiled (telephony::sosRetryOn401, TokenLanes, TokenInstallGate) and pinned by
TokenBodyArena_test.cpp. The anchor client that feeds them compiles only on the device, so no host
test reaches the wiring; this pins where each rule is applied."""
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


class SosTokenWiringTest(unittest.TestCase):
    longMessage = False   # a failure prints its reason, not the whole function

    def setUp(self):
        tac = read("TelephonyAnchorClient.cpp")
        self.make = body_of(tac, "bool TelephonyAnchorClient::makeCall(")
        self.free = body_of(tac, "void TelephonyAnchorClient::freeSlotLocked(")
        self.fetch = body_of(tac, "bool TelephonyAnchorClient::fetchToken(")

    def test_ruling_1_the_401_step_asks_whether_another_911_is_pending_or_up(self):
        at = self.make.index("telephony::sosRetryOn401(")
        step = self.make[at:at + 700]
        self.assertIn("sosScope.id()", step, "the witness names the call that lost")
        self.assertIn("sosScope.anotherPending()", step, "a makeCall() of another 911/933 pending")
        self.assertIn("for (const CallSlot& s : _calls)", step, "a call whose streams are up")
        self.assertIn("s.emergency.load(std::memory_order_acquire)", step)

    def test_ruling_1_a_911_slot_is_marked_before_makecall_returns_and_cleared_when_freed(self):
        keyed = self.make.index("startRxIfNeeded(ownLeg)")
        marked = self.make.index("slot->emergency.store(emergency, std::memory_order_release)")
        self.assertLess(keyed, marked, "positive control: the mark follows the slot being keyed")
        self.assertIn("slot->getFailFast.store(", self.make[marked - 200:marked],
                      "set in the block that already sets the slot's other per-call flags, under _mutex")
        self.assertLess(marked, self.make.index("return success;"),
                        "before makeCall() returns, so it overlaps the pending scope with no gap")
        self.assertIn("slot.emergency.store(false, std::memory_order_release)", self.free,
                      "the one place a slot goes back to free")

    def test_ruling_4_every_911_fetch_names_its_call_to_the_arena_claim(self):
        self.assertEqual(self.make.count("fetchToken(telephony::TokenLane::Emergency, false, sosScope.id())"), 2,
                         "the fetch before the POST (no token) and the 401 step's")
        self.assertNotIn("fetchToken(telephony::TokenLane::Emergency)", self.make,
                         "a 911/933 fetch that does not name its call leaves an anonymous claim loss")
        self.assertRegex(self.fetch, r"(?s)claimWaiting\(.*?\},\s*sosCallId\);",
                         "the refused claim's witness is emitted by claimWaiting, which needs the number")

    def test_ruling_2_a_response_is_installed_only_if_its_request_was_issued_after_the_installed_one(self):
        claim = self.fetch.index("_tokenLanes.claimWaiting(")
        issued = self.fetch.index("const int64_t issuedUs = esp_timer_get_time();")
        opened = self.fetch.index("esp_http_client_open(")
        self.assertLess(claim, issued, "stamped after the lane claim, which start() may have waited for")
        self.assertLess(issued, opened, "and before the request is issued")
        gate = self.fetch.index("installed = _tokenGate.installIfNewer(issuedUs);")
        assign = self.fetch.index("_accessToken.assign(")
        lock = self.fetch.rindex("std::lock_guard<std::mutex> lock(_mutex);", 0, gate)
        self.assertLess(gate, assign, "the cache is assigned only after the gate says so")
        self.assertIn("if (installed)", self.fetch[gate:assign])
        discarded = self.fetch.index("if (!installed) _tokenGate.noteDiscarded(lane);")
        between = self.fetch[lock:discarded]
        self.assertEqual(between.count("{") - between.count("}"), -1,
                         "the discard's witness is emitted after _mutex is released")
        self.assertNotEqual(self.fetch.find("success = true;", discarded), -1,
                            "a discard is a success: a token issued later is installed")
        self.assertIn("if (installed)", self.fetch[discarded:self.fetch.index("Retrieved access token")],
                      "only an installed token is reported as retrieved")


if __name__ == "__main__":
    unittest.main()

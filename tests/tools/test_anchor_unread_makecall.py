"""#349: makeCall()'s POST reached 3CX and its response was never read. 3CX may have
placed the call (on .244 it did), so makeCall() reads the live participant list
until the leg appears and adopts it. The decision is telephony::unreadMakecallStep()
(TelephonyAnchorLogic.hpp, pinned by TelephonyAnchorLogic_test.cpp). makeCall() is
ESP-only, so no host test reaches the wiring; this pins where it is applied.
These are substring and order pins on source text, not behaviour: they do not
prove the branch structure around them, the _running stop or the time base."""
import unittest

from test_anchor_own_leg_not_inbound import body_of, read


class AnchorUnreadMakecallTest(unittest.TestCase):
    longMessage = False

    def setUp(self):
        tac = read("TelephonyAnchorClient.cpp")
        self.make = body_of(tac, "bool TelephonyAnchorClient::makeCall(")
        self.resolve = body_of(tac, "std::string TelephonyAnchorClient::resolveOutboundLeg(")
        start = self.make.find("else if (requestSent && !telephony::httpResponseParsed(status))")
        end = self.make.find("if (success)", start)
        self.assertTrue(0 <= start < end, "positive control: the unread-response branch")
        self.unread = self.make[start:end]

    def test_the_list_is_read_until_the_pure_decision_stops(self):
        # #948: the window loop moved into telephony::readOwnLegWindow (SosStatusGet.hpp, host-tested
        # by SosStatusGet_test.cpp), which is where unreadMakecallStep() is asked.
        self.assertIn("telephony::readOwnLegWindow(", self.unread,
                      "the unread branch must run the window, not stop on the first list answer")
        self.assertIn("unreadMakecallStep(", body_of(read("SosStatusGet.hpp"), "UnreadWindow readOwnLegWindow("),
                      "the window asks unreadMakecallStep()")
        self.assertNotIn("kReconcileAttempts", self.unread, "a fixed attempt count does not bound the window")
        self.assertIn("telephony::kUnreadAdoptPollMs", self.unread)

    def test_an_emergency_call_takes_the_same_path(self):
        self.assertNotIn("mergency", self.unread,
                         "a 911/933 is adopted exactly like any call: never gated, delayed or dropped here")

    def test_an_adopted_leg_is_held_before_it_is_keyed(self):
        adopted = self.make.find("ownLegSource = telephony::OwnLegSource::AdoptedAfterUnreadResponse;")
        self.assertNotEqual(adopted, -1, "an adopted leg must be marked as ours")
        held = self.make.find("telephony::ownLegMayBeHeld(ownLegSource)")
        self.assertTrue(0 <= adopted < held, "marked before the hold is decided")
        self.assertLess(held, self.make.find("startRxIfNeeded(ownLeg)"))

    def test_an_adopted_leg_is_checked_again_once_keyed(self):
        self.assertRegex(self.make, r"if \(primed && \(waitedUs > 0 \|\| adopted\)\)",
                         "an upsert for the leg during the reads was ignored, and 3CX does not repeat a Connected one")

    def test_the_adopt_line_matches_the_scenario(self):
        self.assertEqual(self.unread.count("adopting the call instead of failing it (#349)"), 1)
        self.assertRegex(self.unread, r'"makeCall: no response read \(status=%d\) but 3CX has our leg %s')

    def test_the_adopt_reads_skip_an_earlier_calls_leg(self):
        self.assertRegex(self.unread,
                         r"resolveOutboundLeg\(std::string\(\), destination, &listStatus, &ownLegSource, &counts, "
                         r"/\*skipOurs=\*/true\)",
                         "the adopt reads must skip a leg the PBX already dropped or holds from an earlier call")
        self.assertIn("ownLeg = resolveOutboundLeg(respBody, destination, nullptr, &ownLegSource);", self.make,
                      "a read makecall response is unchanged")
        self.assertIn("telephony::classifyListLeg(", self.resolve)
        self.assertRegex(self.resolve,
                         r"skipOurs && \(_droppedLegs\.contains\(id\) \|\| "
                         r"_ownLegs\.holds\(id, esp_timer_get_time\(\), _wsSeq\)\)",
                         "only the adopt reads skip, on both tables, read under _mutex with the slot check")
        lock = self.resolve.rfind("std::lock_guard<std::mutex> lock(_mutex);", 0, self.resolve.find("skipOurs && ("))
        between = self.resolve[lock:self.resolve.find("skipOurs && (")]
        self.assertTrue(lock != -1 and "}" not in between, "the tables are read under _mutex")

    def test_the_list_lines_say_what_was_listed(self):
        self.assertIn("counts.dcAbsent", self.unread + self.resolve)
        self.assertIn("candidate", self.unread[self.unread.find("adopting the call"):],
                      "the adopt line must say how many candidates the read had")


if __name__ == "__main__":
    unittest.main()

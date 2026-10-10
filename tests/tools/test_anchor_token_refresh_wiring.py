"""#862 (#945): the ESP arm of the 10-minute background token refresh. The decision, the witnesses and
the maintenance lane's arena are host-compiled (telephony::maintRefreshDecision, maintRefreshWakeDue,
TokenLanes) and pinned by TokenBodyArena_test.cpp (TokenMaint.*, TokenInstall.AMaintenance*). The
anchor client that feeds them compiles only on the device, so no host test reaches the wiring; this
pins where each rule is applied: tick() asks without locking, the job on tel_maint decides again,
the fetch re-checks the pending 911/933 before any I/O, and nothing here writes the 911/933 flags."""
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


LOCK = re.compile(r"lock_guard|unique_lock|scoped_lock|\.lock\(\)|try_lock|xSemaphoreTake")
IO = re.compile(r"esp_http_client_\w+\s*\(|\bsend\s*\(|\brecv\s*\(")


class TokenRefreshWiringTest(unittest.TestCase):
    longMessage = False   # a failure prints its reason, not the whole function

    def setUp(self):
        self.cpp = read("TelephonyAnchorClient.cpp")
        self.hpp = read("TelephonyAnchorClient.hpp")
        self.tick = body_of(self.cpp, "void TelephonyAnchorClient::tick(")
        self.job = body_of(self.cpp, "void TelephonyAnchorClient::maintRefreshTaskTrampoline(")
        self.fetch = body_of(self.cpp, "bool TelephonyAnchorClient::fetchToken(")
        self.ensure = body_of(self.cpp, "bool TelephonyAnchorClient::ensureToken(")
        self.streams = body_of(self.cpp, "bool TelephonyAnchorClient::mediaStreamsLive(")
        self.make = body_of(self.cpp, "bool TelephonyAnchorClient::makeCall(")

    def test_tick_asks_the_pure_test_and_wakes_the_job_without_locking_or_io(self):
        at = self.tick.index("telephony::maintRefreshWakeDue(")
        end = self.tick.index("wakeMaint(kMaintTokenRefresh)")
        asked = self.tick[self.tick.rindex("if (_running", 0, at):end]
        self.assertIn("_maintRefreshInFlight.load(", asked, "the in-flight gate is read before anything else")
        self.assertIn("_lastMaintRefreshUs.load(", asked, "the retry floor's stamp feeds the test")
        self.assertIsNone(LOCK.search(asked), "tick() runs on the SIP task with RequestsHandler's lock held")
        self.assertIsNone(IO.search(asked), "and does no I/O")
        stamp = self.tick.index("_lastMaintRefreshUs.store(", at)
        gate = self.tick.index("_maintRefreshInFlight.store(true", at)
        self.assertLess(stamp, end, "the floor counts from this try, stamped before the wake")
        self.assertLess(gate, end, "the gate is taken before the wake, as every other job's is")
        after = self.tick[end:end + 300]
        self.assertIn("_maintRefreshInFlight.store(false", after, "a wake with no task releases its gate")
        self.assertLess(end, self.tick.index("if (!anyWedged) return;"),
                        "before the reconcile gate, whose early returns would skip it")

    def test_the_job_has_its_own_notify_bit_and_is_dispatched_by_the_maint_task(self):
        bits = re.findall(r"kMaint\w+\s*=\s*1u\s*<<\s*(\d+)", self.hpp)
        self.assertEqual(len(bits), len(set(bits)), "every tel_maint job has a bit of its own")
        self.assertIn("kMaintTokenRefresh = 1u << 3", self.hpp)
        loop = body_of(self.cpp, "void TelephonyAnchorClient::maintTaskTrampoline(")
        self.assertRegex(loop, r"jobs & kMaintTokenRefresh\)\s*maintRefreshTaskTrampoline\(arg\)")

    def test_the_job_decides_again_on_tel_maint_and_holds_no_lock_across_the_fetch(self):
        wanted = self.job.index("maintRefreshWanted(")
        fetch = self.job.index("fetchToken(telephony::TokenLane::Maintenance)")
        self.assertLess(wanted, fetch, "the decision comes first")
        decision = self.job[:fetch]
        for read_ in ("_running.load(", "_tokenObtainedUs.load(", "_tokenLifetimeUs.load(",
                      "mediaStreamsLive()", "anySosSlot()"):
            self.assertIn(read_, decision, "every input is read in the job, not carried over from the tick")
        self.assertIsNone(LOCK.search(self.job), "no lock of its own, so none can be held across the fetch")
        self.assertEqual(self.job.count("fetchToken("), 1)
        self.assertNotIn("waitForArena", self.job, "the maintenance lane never waits for its arena")
        self.assertNotIn("true", self.job[fetch:self.job.index(";", fetch)])
        gate = self.job.index("_maintRefreshInFlight.store(false")
        self.assertGreater(gate, fetch, "the gate is cleared last, after the fetch")
        self.assertNotIn("vTaskDelete", self.job, "it runs on tel_maint and must return")

    def test_the_job_reads_the_911_flags_and_never_writes_them(self):
        for name, body in (("the job", self.job), ("tick", self.tick)):
            self.assertNotIn(".emergency.store(", body, name + " does not write CallSlot::emergency")
            self.assertNotIn("EmergencyScope", body, name + " does not open a 911/933 scope")
        anyfn = body_of(self.cpp, "bool TelephonyAnchorClient::anySosSlot(")
        self.assertIn("s.emergency.load(std::memory_order_acquire)", anyfn)
        self.assertIsNone(LOCK.search(anyfn), "atomic loads only")
        self.assertNotIn("Maintenance", self.make, "the 911/933 makeCall() path is not touched")
        self.assertNotIn("maintRefresh", self.make)

    def test_the_fetch_rechecks_a_pending_911_before_the_background_refresh_issues_its_request(self):
        claim = self.fetch.index("_tokenLanes.claimWaiting(")
        recheck = self.fetch.index("lane != telephony::TokenLane::Emergency && !_tokenLanes.ordinaryRefreshMayStart(waitForArena)")
        issued = self.fetch.index("const int64_t issuedUs = esp_timer_get_time();")
        witness = self.fetch.index("_tokenLanes.noteMaintRefresh(")
        opened = self.fetch.index("esp_http_client_open(")
        self.assertLess(claim, recheck, "the arena is claimed first")
        self.assertLess(recheck, issued, "the 911/933 is checked before the request is issued")
        self.assertLess(issued, witness, "the line is left as the request is issued")
        self.assertLess(witness, opened, "and before the connect")
        self.assertIn("lane == telephony::TokenLane::Maintenance", self.fetch[witness - 120:witness],
                      "only the background refresh leaves it")
        self.assertIn("noteMaintSkip(telephony::MaintRefreshReason::EmergencyPending)", self.fetch[recheck:issued],
                      "a refresh turned away at the re-check leaves its skip line")
        self.assertIsNone(re.search(r"lane == telephony::TokenLane::Ordinary\s*&&\s*!_tokenLanes", self.fetch),
                          "the old Ordinary-only re-check is gone: the Maintenance lane is held back too")

    def test_the_background_refresh_gets_the_911_lanes_overall_deadline_and_the_ordinary_lane_does_not(self):
        self.assertIn("const int64_t deadlineUs = lane != telephony::TokenLane::Ordinary ? "
                      "issuedUs + telephony::kSosTokenBudgetUs : 0;", self.fetch)

    def test_the_install_is_the_same_newer_issued_gate_for_every_lane(self):
        gate = self.fetch.index("installed = _tokenGate.installIfNewer(issuedUs);")
        self.assertNotIn("Maintenance", self.fetch[gate - 400:gate + 1200],
                         "no lane-specific install logic: the gate decides by issue time alone")
        self.assertIn("if (!installed) _tokenGate.noteDiscarded(lane);", self.fetch)

    def test_ensureToken_and_the_job_share_one_definition_of_streams_up(self):
        self.assertIn("mediaStreamsLive()", self.ensure)
        self.assertNotIn("getMutex", self.ensure, "ensureToken() keeps no second copy of the scan")
        self.assertIn("s.postLive.load(std::memory_order_acquire)", self.streams)
        self.assertIn("s.getClient != nullptr", self.streams)
        self.assertEqual(len(re.findall(r"lock_guard<std::mutex>\s+getLock\(s\.getMutex\)", self.streams)), 1,
                         "a slot's getMutex is held for the pointer read and released with the iteration")
        self.assertIsNone(IO.search(self.streams))


if __name__ == "__main__":
    unittest.main()

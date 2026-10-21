"""#977 (owner ruling, option 2): a 911/933 whose #349 window ended with every participant-list read errored
is still refused (503, NOT ROUTED) at the end of the window, as on main. 3CX may nevertheless hold a live call
to the PSAP, so makeCall() arms a sweep before it returns and tel_maint runs it after: it reads the list again,
within the window's own bound, and drops the one leg that shows. The decisions are host-tested
(tests/SosStatusGet_test.cpp, src/SIP/SosStatusGet.hpp); the anchor client is ESP-only, so no host test reaches
the wiring. This pins where the decisions are applied, by substring and order on source text: it proves no
timing, and not the branch structure around what it quotes."""
import re
import unittest

from test_anchor_own_leg_not_inbound import body_of, read

LOCK = re.compile(r"lock_guard|unique_lock|scoped_lock|\.lock\(\)|xSemaphoreTake")
IO = re.compile(r"httpGetBody|httpPostBody|performCtrl|resolveOutboundLeg|dropCall|vTaskDelay|esp_http_client")
ALLOC = re.compile(r"\bnew\b|\bmalloc\b|\bcalloc\b|xTaskCreate|createTaskPreferPsram|std::thread")

LINES = (
    "911 orphan sweep: the leg left on 3CX was found and dropped (#977)",
    "911 orphan sweep: the leg left on 3CX was found, the drop failed (#977)",
    "911 orphan sweep: no leg listed within the bound, none dropped (#977)",
    "911 orphan sweep: more than one candidate leg, none dropped (#977)",
    "911 orphan sweep: anchor stopping, ended (#977)",
    "911 orphan sweep: tel_maint reached it after the bound, nothing read (#977)",
    "911 orphan sweep: no tel_maint task, not armed (#977)",
)


class AnchorOrphanSweepTest(unittest.TestCase):
    longMessage = False

    def setUp(self):
        self.cpp = read("TelephonyAnchorClient.cpp")
        self.hpp = read("TelephonyAnchorClient.hpp")
        self.sos = read("SosStatusGet.hpp")
        self.make = body_of(self.cpp, "bool TelephonyAnchorClient::makeCall(")
        self.arm = body_of(self.cpp, "void TelephonyAnchorClient::armOrphanSweep(")
        self.sweep = body_of(self.cpp, "void TelephonyAnchorClient::orphanSweepBody(")
        start = self.make.find("else if (requestSent && !telephony::httpResponseParsed(status))")
        end = self.make.find("if (success)", start)
        self.assertTrue(0 <= start < end, "positive control: the unread-response branch")
        self.unread = self.make[start:end]

    # ── the caller's path ─────────────────────────────────────────────────────────

    def test_the_sweep_is_armed_in_the_refusal_branch_only_and_the_result_is_unchanged(self):
        self.assertEqual(self.make.count("armOrphanSweep("), 1, "one call site")
        refusal_at = self.unread.index("a call may be ORPHANED on 3CX (#349/#328)")
        self.assertNotIn("armOrphanSweep", self.unread[:refusal_at], "not on the adopt branch")
        tail = self.unread[refusal_at:]
        self.assertIn("telephony::orphanSweepWanted(sosLane, outcome, reads, listsRead)", tail)
        self.assertIn("armOrphanSweep(postSeq, armSeq);", tail, "postSeq of the latest POST, and the event number at the arm")
        self.assertIn("const uint64_t armSeq = readPostSeq();", self.unread[:refusal_at], "read before the refusal is logged")
        self.assertNotIn("success = true", tail, "the refusal still sets nothing: the caller gets its 503")
        self.assertNotIn("Proceed", self.make)
        self.assertIn("telephony::unreadOutcome(!ownLeg.empty())", self.unread, "one outcome for every call")
        self.assertRegex(self.make, r"return success;\s*\}\s*$", "makeCall() still returns what it did")

    def test_nothing_is_added_to_the_911_path_but_the_arm(self):
        tail = self.unread[self.unread.index("a call may be ORPHANED on 3CX (#349/#328)"):]
        self.assertIsNone(LOCK.search(tail), "no lock after the refusal is logged")
        self.assertIsNone(IO.search(tail), "no I/O and no wait after the refusal is logged")
        self.assertRegex(self.unread, r"if \(counts\.read\) \+\+listsRead;",
                         "the reads that showed the list are counted in the window's own read, no extra read")
        self.assertEqual(self.unread.count("resolveOutboundLeg("), 1, "the window's reads are the only reads")
        self.assertIn("/*skipOurs=*/true", self.unread)

    def test_arming_takes_no_lock_does_no_io_and_waits_for_nothing(self):
        self.assertIsNone(LOCK.search(self.arm), "armOrphanSweep() runs on the 911's worker")
        self.assertIsNone(IO.search(self.arm), "no I/O, no vTaskDelay")
        hold = self.arm.index("_orphanHoldUntilUs.store(telephony::orphanHoldUntil(nowUs)")
        armed = self.arm.index("_orphanArmedUs.store(nowUs")
        wake = self.arm.index("wakeMaint(kMaintOrphanSweep)")
        self.assertTrue(hold < armed < wake, "the hold is raised before anything can run, and the wake is last")
        after = self.arm[wake:]
        self.assertIn("_orphanHoldUntilUs.store(0", after, "a wake with no task takes the hold back")
        self.assertIn("_orphanArmedUs.store(0", after)
        self.assertIn("_orphanWitness.noteNoWorker()", after)

    # ── the hold ──────────────────────────────────────────────────────────────────

    def test_the_hold_is_the_pending_count_the_classifier_reads_and_makecalls_own_count_is_untouched(self):
        count = body_of(self.cpp, "int TelephonyAnchorClient::countOutboundLocked(")
        self.assertRegex(count, r"pending = telephony::pendingWithOrphanHold\(_outboundPending\.load\([^)]*\),\s*"
                                r"_orphanHoldUntilUs\.load\([^)]*\), esp_timer_get_time\(\),\s*"
                                r"!partId \|\| _pendingSeen\.seenIn\(\*partId, _orphanPostSeq\.load\(std::memory_order_relaxed\),\s*"
                                r"_orphanArmSeq\.load\(std::memory_order_relaxed\)\)\);")
        self.assertIn("struct PendingDec", self.make)
        self.assertRegex(self.make, r"~PendingDec\(\) \{ c\.fetch_sub\(1, std::memory_order_acq_rel\); \}",
                         "the makeCall RAII is as it was: the hold is a separate, time-bounded thing")

    def test_the_hold_is_ended_on_every_exit_and_only_if_it_is_still_this_sweeps(self):
        self.assertIn("const int64_t holdUntilUs = telephony::orphanHoldUntil(armedUs);", self.sweep)
        end = self.sweep.index("struct HoldEnd")
        self.assertIn("compare_exchange_strong(until, 0", self.sweep[end:self.sweep.index("holdEnd{")])
        self.assertLess(self.sweep.index("armedUs == 0) return;"), end, "no arm, no hold of its own to end")
        self.assertLess(end, self.sweep.index("telephony::runOrphanSweep("), "a destructor: every exit, a throw included")

    # ── the job ───────────────────────────────────────────────────────────────────

    def test_the_job_has_its_own_bit_and_tel_maint_runs_it_first(self):
        self.assertIn("kMaintOrphanSweep = 1u << 4", self.hpp)
        loop = body_of(self.cpp, "void TelephonyAnchorClient::maintTaskTrampoline(")
        self.assertRegex(loop, r"jobs & kMaintOrphanSweep\)\s*orphanSweepTaskTrampoline\(arg\)")
        self.assertLess(loop.index("kMaintOrphanSweep"), loop.index("kMaintRestart"),
                        "it runs against a deadline, ahead of the long jobs")
        self.assertNotIn("vTaskDelete", self.sweep, "it runs on tel_maint and must return")
        self.assertIsNone(ALLOC.search(self.sweep), "no task, thread or new/malloc of its own")
        self.assertIsNone(ALLOC.search(self.arm))

    def test_the_sweep_state_is_a_few_atomics_and_nothing_that_allocates(self):
        decls = [l for l in self.hpp.split("\n") if "_orphan" in l and ";" in l and "(" not in l]
        self.assertEqual(len(decls), 5, "armed time, POST seq, arm seq, hold, witness")
        for line in decls[:4]:
            self.assertIn("std::atomic<", line)
        self.assertNotRegex("\n".join(decls), r"std::(string|vector|map|function)")

    def test_the_bound_runs_from_the_arm_and_the_sweep_sleeps_in_vtaskdelay(self):
        self.assertRegex(self.sweep, r"telephony::runOrphanSweep\(\s*armedUs,")
        self.assertIn("[] { vTaskDelay(pdMS_TO_TICKS(telephony::kOrphanSweepPollMs)); }", self.sweep)
        self.assertEqual(self.sweep.count("vTaskDelay("), 1, "the one pause, between reads")
        self.assertNotRegex(self.sweep, r"\b(while|for|do)\b\s*[({]", "no loop of its own: the driver is the loop")
        self.assertRegex(self.sos, r"kOrphanSweepWindowUs\s*=\s*kUnreadAdoptWindowUs;")

    def test_the_read_is_on_the_ordinary_lane_and_an_allocation_failure_is_a_failed_read(self):
        self.assertIn("resolveOutboundLeg(std::string(), std::string(), &listStatus, &source, &counts, /*skipOurs=*/true,"
                      "\n\t\t\t\t\t\t\t\t\t/*fresh=*/true)",
                      self.sweep, "an empty destination is the ordinary status lane (#941), and it never waits on the shared lock")
        for sos in ("sosLane", "_sosStatus", "_sosBody", "/*sosLane=*/true", "classifyEmergencyDial"):
            self.assertNotIn(sos, self.sweep, "never the 911 handle: its claim is a 911's own GET")
        self.assertGreaterEqual(self.sweep.count("catch (const std::bad_alloc&)"), 2, "drop and the driver (the read's is the helper's)")
        self.assertIn("catch (const std::bad_alloc&)", body_of(self.sos, "OrphanRead readOrphanOnce("))

    def test_a_read_is_no_decision_while_a_makecall_is_in_flight(self):
        # The guards (pending before and after the read, a makeCall that began and ended during it) live in
        # telephony::readOrphanOnce, which the host tests run (SosOrphanSweep.ASweepReadDecidesNothing...). The
        # ESP arm must go through it and lend it the same two atomics it used to read inline.
        read_at = self.sweep.index("telephony::readOrphanOnce(")
        arm = self.sweep[read_at:]
        self.assertIn("[this] { return _outboundPending.load(std::memory_order_acquire); },", arm)
        self.assertIn("[this] { return _outboundPendingSinceUs.load(std::memory_order_acquire); },", arm)
        self.assertNotIn("rd.stranger", self.sweep, "the stranger decision is the helper's")
        self.assertIn("template <class ReadFn, class PendingFn, class SinceFn, class SeenFn>\nOrphanRead readOrphanOnce(", self.sos)
        helper = body_of(self.sos, "OrphanRead readOrphanOnce(")
        self.assertIn("if (pendingCount() > 0 || pendingSinceUs() != sinceUs) return {};", helper)

    def test_no_lock_is_held_across_io_in_the_sweep(self):
        locks = [m.start() for m in LOCK.finditer(self.sweep)]
        self.assertEqual(len(locks), 3, "the stranger check, the hold hook and the candidate check, each a scope of its own")
        self.assertRegex(self.sweep, r"\{\s*std::lock_guard<std::mutex> lock\(_mutex\);\s*"
                                     r"_ownLegs\.noteNamed\(leg, esp_timer_get_time\(\), postSeq\);\s*\}",
                         "a scope of its own, one table call, no I/O inside")
        self.assertRegex(self.sweep, r"\{\s*std::lock_guard<std::mutex> lock\(_mutex\);\s*"
                                     r"return _pendingSeen\.seenIn\(leg, postSeq, armSeq\);\s*\}",
                         "after the read, never across it")
        self.assertRegex(self.sweep, r"std::lock_guard<std::mutex> lock\(_mutex\);\s*"
                                     r"return _pendingSeen\.anyIn\(postSeq, armSeq\);")

    def test_the_leg_is_ours_before_its_drop_and_before_the_hold_ends(self):
        hook = self.sweep[self.sweep.index("[this, postSeq, holdUntilUs](const std::string& leg)"):]
        noted = hook.index("_ownLegs.noteNamed(")
        released = hook.index("_orphanHoldUntilUs.compare_exchange_strong(until, 0")
        dropped = hook.index("dropOrphanLeg(leg)")
        self.assertTrue(noted < released < dropped, "noteNamed, then the hold ends, then the drop")

    def test_the_end_is_counted_by_the_witness_and_the_harness_token_is_not_reused(self):
        self.assertIn("_orphanWitness.noteEnd(r.end);", self.sweep)
        for line in LINES:
            self.assertEqual(self.sos.count(line), 1, line)
        self.assertRegex(self.sos, r"kLinesPerEnd\s*=\s*8;")
        for text in (self.sweep, self.arm):
            self.assertNotIn("ORPHANED", text, "tests/load/anchor_scenarios.py counts that token as the #349 refusal")

    # ── Rule 5 review of #1040 ────────────────────────────────────────────────────

    def test_the_sweep_drop_takes_no_ctrl_mutex_so_answercall_never_queues_behind_it(self):
        # dropCall() ends in performCtrl(), which holds _ctrlMutex for the whole POST (up to 5 to 7 s), and
        # answerCall() waits on it. The sweep's drop is a fresh-client POST, as makeCall()'s is.
        self.assertNotIn("dropCall(", self.sweep)
        self.assertNotIn("performCtrl", self.sweep)
        drop = body_of(self.cpp, "bool TelephonyAnchorClient::dropOrphanLeg(")
        self.assertIn("httpPostBody(", drop)
        for shared in ("performCtrl", "_ctrlMutex", "_ctrlClient", "stopMediaStreams"):
            self.assertNotIn(shared, drop)
        self.assertIn("/drop", drop)

    def test_the_sweep_read_has_a_handle_of_its_own_and_takes_no_status_lock(self):
        get = body_of(self.cpp, "bool TelephonyAnchorClient::httpGetBody(")
        self.assertIn("if (!sosLane && !fresh) statusLock.lock();", get)
        self.assertIn("freshGuard{freshClient}", get)
        self.assertIn("fresh ? freshClient : sosLane", get)
        resolve = body_of(self.cpp, "std::string TelephonyAnchorClient::resolveOutboundLeg(")
        self.assertIn("httpGetBody(url, body, &status, pbx::classifyEmergencyDial(destination).isEmergency, false, fresh)",
                      resolve)

    def test_the_classifier_holds_only_an_id_seen_while_a_makecall_was_pending(self):
        count = body_of(self.cpp, "int TelephonyAnchorClient::countOutboundLocked(")
        self.assertIn("_pendingSeen.seenIn(*partId, _orphanPostSeq", count)
        self.assertIn("const std::string* partId", self.hpp)
        ws = self.cpp[self.cpp.index("std::string controlLegs[POCKETDIAL_MAX_ANCHOR_CALLS];"):]
        ws = ws[:ws.index("if (nLegs == 0) break;")]
        self.assertIn("countOutboundLocked(inflight, POCKETDIAL_MAX_ANCHOR_CALLS, witnessActive, witnessPending, &partId)", ws)
        self.assertIn("if (_outboundPending.load(std::memory_order_acquire) > 0) _pendingSeen.note(partId, seq);", ws)

    def test_the_sweep_read_marks_a_pick_the_window_never_saw_as_a_stranger(self):
        # point 1 and the Opus blocker: seen means first noted in (postSeq, armSeq], decided by the host-tested helper.
        read_at = self.sweep.index("telephony::readOrphanOnce(")
        self.assertIn("_pendingSeen.seenIn(leg, postSeq, armSeq)", self.sweep[read_at:])
        self.assertIn("telephony::PendingSeenIds<", self.hpp)
        helper = body_of(self.sos, "OrphanRead readOrphanOnce(")
        self.assertIn("rd.stranger = !rd.leg.empty() && !seen(rd.leg);", helper)

    def test_a_sweep_with_no_leg_upserted_in_the_window_reads_nothing(self):
        self.assertIn("_orphanArmSeq.load(std::memory_order_relaxed)", self.sweep)
        self.assertIn("if (r.reads == 0 && !hasCandidate())", self.sos)

    # ── the list read ─────────────────────────────────────────────────────────────

    def test_a_list_that_was_fetched_and_parsed_is_marked_read_after_the_leg_walk(self):
        resolve = body_of(self.cpp, "std::string TelephonyAnchorClient::resolveOutboundLeg(")
        walk = resolve.index("cJSON_ArrayForEach(elem, root)")
        marked = resolve.index("counts.read = true;")
        self.assertLess(walk, marked, "after the early returns: a failed or unparsed list is not marked")
        self.assertLess(marked, resolve.index("*countsOut = counts;"))
        self.assertRegex(read("TelephonyAnchorLogic.hpp"), r"struct ListLegCounts\s*\{\s*bool read = false;")


if __name__ == "__main__":
    unittest.main()

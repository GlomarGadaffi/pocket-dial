"""#977 (owner ruling, option 2): a 911/933 whose #349 window ended with every participant-list read errored
is still refused (503, NOT ROUTED) at the end of the window, as on main. 3CX may nevertheless hold a live call
to the PSAP, so makeCall() arms a sweep before it returns and tel_sweep runs it after: it reads the list again,
within the window's own bound, and drops the one leg that shows. The decisions are host-tested
(tests/SosStatusGet_test.cpp, src/SIP/SosStatusGet.hpp); the anchor client is ESP-only, so no host test reaches
the wiring. This pins where the decisions are applied, by substring and order on source text: it proves no
timing, and not the branch structure around what it quotes."""
import os
import re
import unittest

from test_anchor_own_leg_not_inbound import SIP, body_of, read

LOCK = re.compile(r"lock_guard|unique_lock|scoped_lock|\.lock\(\)|xSemaphoreTake")
IO = re.compile(r"httpGetBody|httpPostBody|performCtrl|resolveOutboundLeg|dropCall|vTaskDelay|esp_http_client")
ALLOC = re.compile(r"\bnew\b|\bmalloc\b|\bcalloc\b|xTaskCreate|createTaskPreferPsram|std::thread")

LINES = (
    "911 orphan sweep: the leg left on 3CX was found and dropped (#977)",
    "911 orphan sweep: the leg left on 3CX was found, the drop failed (#977)",
    "911 orphan sweep: no leg listed within the bound, none dropped (#977)",
    "911 orphan sweep: more than one candidate leg, none dropped (#977)",
    "911 orphan sweep: anchor stopping, ended (#977)",
    "911 orphan sweep: tel_sweep reached it after the bound, nothing read (#977)",
    "911 orphan sweep: no tel_sweep task, not armed (#977)",
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
        self.assertIn("armOrphanSweep(postSeq, armSeq, destination);", tail, "postSeq of the latest POST, and the event number at the arm")
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

    def test_arming_takes_only_the_state_mutex_briefly_does_no_io_and_waits_for_nothing(self):
        # The arm, its window and its number are one snapshot (OrphanArmSlot), written under _mutex: no I/O inside.
        self.assertEqual(len(LOCK.findall(self.arm)), 2, "arm and disarm, each a scope of its own")
        self.assertRegex(self.arm, r"\{\s*std::lock_guard<std::mutex> lock\(_mutex\);\s*"
                                   r"_orphanArm\.arm\(nowUs, postSeq, armSeq, destination\);\s*\}")
        self.assertIsNone(IO.search(self.arm), "no I/O, no vTaskDelay")
        arm = self.arm.index("_orphanArm.arm(")
        hold = self.arm.index("_orphanHoldUntilUs.store(telephony::orphanHoldUntil(nowUs)")
        wake = self.arm.index("wakeSweep()")
        self.assertTrue(arm < hold < wake, "armed, then the hold is raised, and the wake is last")
        after = self.arm[wake:]
        self.assertIn("_orphanHoldUntilUs.store(0", after, "a wake with no task takes the hold back")
        self.assertIn("_orphanArm.disarm();", after)
        self.assertIn("_orphanWitness.noteNoWorker()", after)

    # ── the hold ──────────────────────────────────────────────────────────────────

    def test_the_hold_is_the_pending_count_the_classifier_reads_and_makecalls_own_count_is_untouched(self):
        count = body_of(self.cpp, "int TelephonyAnchorClient::countOutboundLocked(")
        self.assertRegex(count, r"pending = telephony::pendingWithOrphanHold\(_outboundPending\.load\([^)]*\),\s*"
                                r"_orphanHoldUntilUs\.load\([^)]*\), esp_timer_get_time\(\),\s*"
                                r"!partId \|\| _pendingSeen\.seenIn\(\*partId, _orphanArm\.postSeq\(\), _orphanArm\.armSeq\(\)\)\);")
        self.assertIn("struct PendingDec", self.make)
        self.assertRegex(self.make, r"~PendingDec\(\) \{ c\.fetch_sub\(1, std::memory_order_acq_rel\); \}",
                         "the makeCall RAII is as it was: the hold is a separate, time-bounded thing")

    def test_the_hold_is_ended_on_every_exit_and_only_if_it_is_still_this_sweeps(self):
        self.assertIn("const int64_t holdUntilUs = telephony::orphanHoldUntil(armedUs);", self.sweep)
        end = self.sweep.index("struct HoldEnd")
        self.assertIn("compare_exchange_strong(until, 0", self.sweep[end:self.sweep.index("holdEnd{")])
        self.assertLess(self.sweep.index("if (!_orphanArm.take(arm)) return;"), end, "no arm, no hold of its own to end")
        self.assertLess(end, self.sweep.index("telephony::runOrphanSweep("), "a destructor: every exit, a throw included")

    # ── the job ───────────────────────────────────────────────────────────────────

    def test_the_sweep_runs_on_its_own_task_so_a_restart_on_tel_maint_never_waits_on_its_io(self):
        # Round 8: tel_maint runs the restart. A sweep op in flight (a GET or POST, a getaddrinfo with no timeout)
        # cannot be stopped, so the sweep has a task of its own and tel_maint never runs, joins or waits for it.
        loop = body_of(self.cpp, "void TelephonyAnchorClient::maintTaskTrampoline(")
        self.assertNotIn("OrphanSweep", loop, "tel_maint no longer runs the sweep")
        self.assertNotIn("orphanSweepBody", loop)
        self.assertNotIn("kMaintOrphanSweep", self.hpp)
        self.assertIn("std::atomic<TaskHandle_t> _sweepHandle{nullptr};", self.hpp)
        task = body_of(self.cpp, "void TelephonyAnchorClient::sweepTaskTrampoline(")
        self.assertIn("xTaskNotifyWait(0, UINT32_MAX, nullptr, portMAX_DELAY);", task)
        self.assertIn("self->orphanSweepBody();", task)
        wake = body_of(self.cpp, "bool TelephonyAnchorClient::wakeSweep(")
        self.assertIn("_sweepHandle.load(std::memory_order_acquire)", wake)
        self.assertNotIn("_maintHandle", wake, "the arm never wakes tel_maint")
        self.assertNotIn("wakeMaint", self.arm)
        self.assertIn("wakeSweep()", self.arm)
        start = body_of(self.cpp, "bool TelephonyAnchorClient::start(")
        self.assertLess(start.index('"tel_maint"'), start.index('"tel_sweep"'))
        dtor = body_of(self.cpp, "TelephonyAnchorClient::~TelephonyAnchorClient(")
        self.assertIn("_sweepHandle.exchange(nullptr)", dtor)
        self.assertRegex(self.sweep, r"telephony::sweepMayContinue\(_running\.load\(std::memory_order_acquire\),\s*"
                                     r"_restartRequested\.load\(std::memory_order_acquire\)\)",
                         "and it still starts no op once a restart is wanted")
        self.assertNotIn("vTaskDelete", self.sweep, "it runs on its own task and must return")
        self.assertIsNone(ALLOC.search(self.sweep), "no task, thread or new/malloc of its own")
        self.assertIsNone(ALLOC.search(self.arm))
        gate = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools", "ci", "task_stacks.json"),
                    encoding="utf-8").read()
        self.assertIn('"name": "tel_sweep", "entry": "sweepTaskTrampoline\\\\("', gate, "the stack gate knows the new task")

    def test_the_no_psram_internal_budget_counts_tel_sweep(self):
        # #1116: with no PSRAM the sweep's stack falls back to internal DRAM, allocated before the receiver slots, so
        # the 72 KB static_assert in RtpTaskSlots.hpp must count it, from the one constant the class uses.
        slots = read("RtpTaskSlots.hpp")
        budget = slots[slots.index("#if !defined(CONFIG_SPIRAM)"):]
        self.assertIn("kSweepStackBytes", budget, "the no-PSRAM assert leaves out tel_sweep's stack")
        self.assertRegex(slots, r"kSweepStackBytes\s*=\s*13376")
        self.assertRegex(self.hpp, r"kSweepStackBytes\s*=\s*pd::rtpslots::kSweepStackBytes")

    def test_tel_sweep_is_a_static_task_on_a_boot_allocated_psram_stack(self):
        # Round 9: a dynamic internal 6 KB stack cost ~6.7 KB of internal heap for good (BigDog's bench). The sweep's
        # call graph (resolveOutboundLeg, httpPostBody, cJSON, the in-memory tables, esp_log witnesses) does no flash
        # write (nvs_*, esp_partition_*, esp_flash_*, esp_ota_*) and no ISR-context code, and tel_ctl, which runs the
        # same httpPostBody/resolveOutboundLeg, is already PSRAM-stacked. So it takes the rx-slot pattern (#479).
        self.assertIn("pd::StaticTaskSlot _sweepMem;", self.hpp)
        ctor = body_of(self.cpp, "TelephonyAnchorClient::TelephonyAnchorClient(")
        self.assertIn(
            '_sweepMem.alloc("tel_sweep", kSweepStackBytes, PD_TASK_STACK_CAPS, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);', ctor,
            "allocated once at construction, so start() allocates nothing")
        self.assertIn("kSweepStackBytes = 13376", self.hpp)
        start = body_of(self.cpp, "bool TelephonyAnchorClient::start(")
        self.assertRegex(start, r'xTaskCreateStatic\(&TelephonyAnchorClient::sweepTaskTrampoline, "tel_sweep",\s*'
                                r'_sweepMem\.bytes, this, 4, _sweepMem\.stack, _sweepMem\.tcb\)')
        self.assertNotIn('xTaskCreate(&TelephonyAnchorClient::sweepTaskTrampoline', start)
        self.assertIn("_sweepMem.stack == nullptr", start, "a failed boot allocation refuses, logged, never a crash")
        # nothing on the sweep's path reaches a flash write
        for text in (self.sweep, body_of(self.cpp, "bool TelephonyAnchorClient::dropOrphanLeg("),
                     body_of(self.cpp, "std::string TelephonyAnchorClient::resolveOutboundLeg(")):
            self.assertIsNone(re.search(r"nvs_|esp_partition|esp_flash|esp_ota|spi_flash|CdrRing|endCall\(", text))

    def test_the_tel_sweep_stack_watermark_is_on_status(self):
        with open(os.path.join(SIP, "..", "Helpers", "HttpServer.cpp"), encoding="utf-8") as f:
            http = f.read()
        self.assertIn('pdAppendHwmField(json, "stackHwm_tel_sweep", pdStackHwmBytes("tel_sweep"));', http)
        self.assertIn('\\"stackHwm_tel_sweep\\":null', http, "and the host / no-ESP path keeps the key as null")

    def test_the_comments_state_the_guarantee_exactly(self):
        # The other pins read comment-stripped code; this one reads the files as they are.
        raw = {}
        for name in ("TelephonyAnchorClient.cpp", "TelephonyAnchorClient.hpp", "SosStatusGet.hpp"):
            with open(os.path.join(SIP, name), encoding="utf-8") as f:
                raw[name] = f.read()
        for text in raw.values():
            self.assertNotIn("tel_maint runs it", text)
            self.assertNotIn("Runs on tel_maint, after the 503", text)
            self.assertNotIn("ever delays a restart", text)
            self.assertNotIn("never waits in front of one", text)
            self.assertNotIn("must not wait behind a sweep", text)
        cpp = raw["TelephonyAnchorClient.cpp"]
        sweep_doc = cpp[cpp.index("// Runs on tel_sweep"):cpp.index("void TelephonyAnchorClient::orphanSweepBody(")]
        self.assertIn("never waits on the sweep", sweep_doc)
        self.assertIn("kOrphanOpBudgetUs", raw["SosStatusGet.hpp"])

    def test_the_sweep_state_is_a_few_atomics_and_nothing_that_allocates(self):
        decls = [l for l in self.hpp.split("\n") if "_orphan" in l and ";" in l and "(" not in l and "//" not in l.split("_orphan")[0]]
        self.assertEqual(len(decls), 3, "the arm snapshot, the hold, the witness")
        self.assertIn("telephony::OrphanArmSlot _orphanArm;", "\n".join(decls))
        self.assertIn("std::atomic<int64_t>  _orphanHoldUntilUs", "\n".join(decls))
        self.assertNotRegex("\n".join(decls), r"std::(string|vector|map|function)")
        self.assertIn("telephony::UnslottedRecord _unslottedEmergency;", self.hpp)

    def test_the_bound_runs_from_the_arm_and_the_sweep_sleeps_in_vtaskdelay(self):
        self.assertRegex(self.sweep, r"telephony::runOrphanSweep\(\s*armedUs,")
        self.assertIn("[] { vTaskDelay(pdMS_TO_TICKS(telephony::kOrphanSweepPollMs)); }", self.sweep)
        self.assertEqual(self.sweep.count("vTaskDelay("), 1, "the one pause, between reads")
        self.assertNotRegex(self.sweep, r"\b(while|for|do)\b\s*[({]", "no loop of its own: the driver is the loop")
        self.assertRegex(self.sos, r"kOrphanSweepWindowUs\s*=\s*kUnreadAdoptWindowUs;")

    def test_the_read_is_on_the_ordinary_lane_and_an_allocation_failure_is_a_failed_read(self):
        self.assertIn("resolveOutboundLeg(std::string(), std::string(), &listStatus, &source, &counts, /*skipOurs=*/true,"
                      "\n\t\t\t\t\t\t\t\t\t/*fresh=*/true, &rd.partyDn, &rd.partyCid, deadlineUs)",
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
        self.assertEqual(len(locks), 4, "the take, the stranger check, the hold hook and the candidate check, each a scope of its own")
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
        self.assertIn("httpGetBody(url, body, &status, pbx::classifyEmergencyDial(destination).isEmergency, false, fresh, deadlineUs)",
                      resolve)

    def test_the_classifier_holds_only_an_id_seen_while_a_makecall_was_pending(self):
        count = body_of(self.cpp, "int TelephonyAnchorClient::countOutboundLocked(")
        self.assertIn("_pendingSeen.seenIn(*partId, _orphanArm.postSeq(), _orphanArm.armSeq())", count)
        self.assertIn("const std::string* partId", self.hpp)
        ws = self.cpp[self.cpp.index("std::string controlLegs[POCKETDIAL_MAX_ANCHOR_CALLS];"):]
        ws = ws[:ws.index("if (nLegs == 0) break;")]
        self.assertIn("countOutboundLocked(inflight, POCKETDIAL_MAX_ANCHOR_CALLS, witnessActive, witnessPending, &partId)", ws)
        self.assertIn("if (_outboundPending.load(std::memory_order_acquire) > 0) _pendingSeen.note(partId, seq, _outboundPending.load(std::memory_order_acquire));", ws)

    def test_the_sweep_read_marks_a_pick_the_window_never_saw_as_a_stranger(self):
        # point 1 and the Opus blocker: seen means first noted in (postSeq, armSeq], decided by the host-tested helper.
        read_at = self.sweep.index("telephony::readOrphanOnce(")
        self.assertIn("_pendingSeen.seenIn(leg, postSeq, armSeq)", self.sweep[read_at:])
        self.assertIn("telephony::PendingSeenIds<", self.hpp)
        helper = body_of(self.sos, "OrphanRead readOrphanOnce(")
        self.assertIn("rd.stranger = !rd.leg.empty() && !(seen(rd.leg) && partyIsDestination(destDigits, rd.partyDn, rd.partyCid));", helper)

    def test_a_sweep_with_no_leg_upserted_in_the_window_reads_nothing(self):
        self.assertIn("const uint64_t armSeq = arm.armSeq;", self.sweep)
        self.assertIn("if (r.reads == 0 && !hasCandidate())", self.sos)

    # ── Rule 5 review of #1040, round 4 ───────────────────────────────────────────

    def test_a_911_that_succeeded_with_no_own_leg_ends_the_sweep_before_a_drop(self):
        make = self.make
        branch = make[make.index("could not resolve own leg id"):]
        branch = branch[:branch.index("else")]
        self.assertIn("if (sosLane && _unslottedEmergency.note())", branch)
        self.assertIn("the orphan sweep is disabled until reboot", branch, "logged once")
        self.assertIn("return _unslottedEmergency.recorded();", self.sweep)
        self.assertNotIn("_unslottedEmergency = ", self.cpp, "sticky: nothing clears it")

    def test_the_party_strings_are_copied_only_when_the_caller_wants_them(self):
        resolve = body_of(self.cpp, "std::string TelephonyAnchorClient::resolveOutboundLeg(")
        self.assertIn("const bool wantParty = partyDnOut || partyCidOut;", resolve)
        self.assertEqual(resolve.count("partyOf(elem,"), 4)
        self.assertEqual(resolve.count("if (wantParty)"), 2, "both pick sites")

    # ── Rule 5 review of #1040, round 7 ───────────────────────────────────────────

    def test_the_sweeps_io_runs_under_a_short_overall_deadline_so_a_restart_never_waits_on_it(self):
        # keepGoing is checked only between operations, so the GET and the POST themselves are bounded: each
        # esp_http_client operation is armed from what is left of the op budget (telephony::opTimeoutMs, host-tested).
        self.assertRegex(self.sos, r"kOrphanOpBudgetUs\s*=\s*1'500'000;")
        self.assertIn("const int64_t deadlineUs = esp_timer_get_time() + telephony::kOrphanOpBudgetUs;", self.sweep)
        self.assertIn("/*fresh=*/true, &rd.partyDn, &rd.partyCid, deadlineUs)", self.sweep)
        drop = body_of(self.cpp, "bool TelephonyAnchorClient::dropOrphanLeg(")
        self.assertIn("const int64_t deadlineUs = esp_timer_get_time() + telephony::kOrphanOpBudgetUs;", drop)
        self.assertIn("httpPostBody(dropUrl, \"application/json\", \"{}\", resp, &status, nullptr, deadlineUs)", drop)
        post = body_of(self.cpp, "bool TelephonyAnchorClient::httpPostBody(")
        self.assertGreaterEqual(post.count("armTokenOpTimeout(client, deadlineUs)"), 4, "open, write, headers, each read")
        get = body_of(self.cpp, "bool TelephonyAnchorClient::httpGetBody(")
        self.assertGreaterEqual(get.count("armTokenOpTimeout(client, deadlineUs)"), 3, "open, headers, each drain read")
        self.assertIn("deadlineUs", self.hpp)

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

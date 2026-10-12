"""#986 slice 3: pin, at the source level, what the host tests cannot see.

AdminPinOffthread_test.cpp proves the behaviour: the digit's drain hands off and
returns, the result is applied on a tick, the accounting is unchanged. What it cannot
see is (a) that nothing on the digit path calls the hash at all, so a later edit that
puts a hash call back into onDigit() or the drain fails here even if a test seam hides
it, (b) that the worker task is the one caller of the hash, and reaches no flash API (it
may have a PSRAM stack only because of that: PsramTask.hpp, #277), and (c) that the
apply sits inside tick()'s _mutex scope.
"""
import json
import os
import re
import unittest

REPO = os.path.join(os.path.dirname(__file__), "..", "..")
SRC = os.path.join(REPO, "src")

HASH_CALLS = ("hashSecret(", "hashSecretDigest(", "verifyDtmfPin(", "matchesDtmfPin(")
FLASH_CALLS = ("nvs_", "esp_partition", "esp_flash", "esp_ota", "spi_flash", "nvs.h", "nvs_flash.h")


def code(path):
    """Source with // and /* */ comments removed, so a comment can't satisfy a pin."""
    with open(os.path.join(SRC, path), encoding="utf-8") as f:
        text = f.read()
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def func_body(text, signature):
    """Body of the function whose header matches `signature` (a regex ending before the '{'),
    found by matching braces, so it works for a method at any indentation."""
    m = re.search(signature + r"[^{;]*\{", text, re.S)
    assert m, signature + " not found"
    depth, i = 1, m.end()
    while depth:
        c = text[i]
        depth += (c == "{") - (c == "}")
        i += 1
    return text[m.end():i - 1]


class TheDigitPathNeverHashes(unittest.TestCase):
    def setUp(self):
        self.dtmf = code("SIP/DtmfFeatureCodes.cpp")
        self.rh = code("SIP/RequestsHandler.cpp")

    def test_on_digit_hands_off_and_calls_no_hash(self):
        b = func_body(self.dtmf, r"void DtmfFeatureCodes::onDigit\(")
        for bad in HASH_CALLS + ("AdminAuth::",):
            self.assertNotIn(bad, b, "onDigit() runs under _mutex on the SIP or tick task: " + bad)
        self.assertEqual(b.count("adminpin::submit("), 1, "one hand-off per completed entry")
        # the entry is cleared once handed over, so trailing digits do not each draw a refusal
        after = b[b.index("adminpin::submit("):]
        self.assertIn("accum.digits.clear();", after[:after.index("return;")])

    def test_the_whole_dtmf_file_never_reaches_the_hash_or_the_auth_state(self):
        for bad in HASH_CALLS + ("AdminAuth::",):
            self.assertNotIn(bad, self.dtmf)

    def test_the_rfc4733_drain_calls_no_hash(self):
        b = func_body(self.rh, r"void RequestsHandler::drainDtmfInbox\(")
        for bad in HASH_CALLS + ("AdminAuth::", "adminpin::"):
            self.assertNotIn(bad, b)
        self.assertIn("_dtmf.onDigit(", b)

    def test_the_sip_info_path_reaches_the_same_on_digit(self):
        info = func_body(self.dtmf, r"void DtmfFeatureCodes::onInfo\(")
        self.assertIn("onDigit(", info)
        for bad in HASH_CALLS:
            self.assertNotIn(bad, info)

    def test_a_999_waits_for_its_confirm_digit_before_it_is_handed_over(self):
        b = func_body(self.dtmf, r"void DtmfFeatureCodes::onDigit\(")
        self.assertLess(b.index('code == "999" && rest.size() < 4'), b.index("adminpin::submit("))

    def test_a_refusal_is_logged_like_a_wrong_pin_and_counts_nothing_here(self):
        b = func_body(self.dtmf, r"void DtmfFeatureCodes::onDigit\(")
        self.assertIn("handoff != adminpin::SubmitResult::Accepted", b)
        self.assertEqual(b.count('"[admin] DTMF admin auth failed"'), 2, "non-digit PIN and refusal")


class TheWorkerIsTheOnlyCallerOfTheHash(unittest.TestCase):
    def test_matches_dtmf_pin_is_called_from_the_worker_file_only(self):
        callers = []
        for root in ("src", "main"):
            for d, _, files in os.walk(os.path.join(REPO, root)):
                for name in files:
                    if not name.endswith((".cpp", ".hpp", ".h", ".c")):
                        continue
                    path = os.path.join(d, name)
                    with open(path, encoding="utf-8", errors="replace") as f:
                        text = re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", f.read(), flags=re.S))
                    for call in ("matchesDtmfPin(", "verifyDtmfPin(", "hashSecretDigest(", "hashSecret("):
                        if call in text:
                            callers.append((os.path.relpath(path, REPO).replace(os.sep, "/"), call))
        self.assertEqual(
            sorted(callers),
            sorted([
                ("src/Helpers/AdminAuth.cpp", "matchesDtmfPin("),
                ("src/Helpers/AdminAuth.cpp", "verifyDtmfPin("),
                ("src/Helpers/AdminAuth.cpp", "hashSecretDigest("),
                ("src/Helpers/AdminAuth.cpp", "hashSecret("),
                ("src/Helpers/AdminAuth.hpp", "matchesDtmfPin("),
                ("src/Helpers/AdminAuth.hpp", "verifyDtmfPin("),
                ("src/SIP/AdminPinVerify.cpp", "matchesDtmfPin("),
            ]),
            "the DTMF path may reach the hash only through AdminPinVerify.cpp's worker hasher",
        )

    def test_the_worker_hasher_is_run_only_by_the_task_and_the_host_seam(self):
        src = code("SIP/AdminPinVerify.cpp")
        self.assertEqual(src.count("matchesDtmfPin("), 1)
        self.assertEqual(len(re.findall(r"\brealHash\b", src)), 3, "definition, the task, the host seam")
        task = func_body(src, r"void pinVerifyTask\(void\* arg\)")
        self.assertIn("workOnce(realHash)", task)
        # the SIP side calls submit/applyIfReady, never workOnce
        for fn in ("SubmitResult submit\\(", "bool applyIfReady\\("):
            self.assertNotIn("workOnce", func_body(src, fn))

    def test_verify_dtmf_pin_is_the_three_steps_and_there_is_one_hash_loop(self):
        a = code("Helpers/AdminAuth.cpp")
        v = func_body(a, r"bool verifyDtmfPin\(const std::string& pin\)")
        self.assertLess(v.index("beginDtmfPinVerify("), v.index("finishDtmfPinVerify("))
        self.assertIn("finishDtmfPinVerify(t, matchesDtmfPin(t, pin, nullptr))", v)
        self.assertEqual(a.count("kHashIterations"), 1, "one SHA-256 round loop")
        self.assertIn("hashSecretDigest(salt, secret, digest, nullptr)",
                      func_body(a, r"std::string hashSecret\(const std::string& salt, const std::string& secret\)"))
        self.assertIn("hashSecretDigest(t.salt, pin, digest, yield)",
                      func_body(a, r"bool matchesDtmfPin\("))


class TheWorkerReachesNoFlashAndNoSharedState(unittest.TestCase):
    def setUp(self):
        self.src = code("SIP/AdminPinVerify.cpp")
        self.auth = code("Helpers/AdminAuth.cpp")
        self.logic = code("SIP/AdminPinVerifyLogic.hpp")

    def test_the_worker_file_includes_and_calls_no_flash_api(self):
        for bad in FLASH_CALLS:
            self.assertNotIn(bad, self.src)
            self.assertNotIn(bad, self.logic)

    def test_the_hash_chain_takes_no_lock_and_reads_no_auth_state(self):
        chain = (func_body(self.auth, r"bool matchesDtmfPin\(") +
                 func_body(self.auth, r"void hashSecretDigest\(") +
                 func_body(self.auth, r"void hexInto\("))
        for bad in FLASH_CALLS + ("state()", "loadCredentialLocked", "lock_guard", "unique_lock", "mutex",
                                  "new ", "malloc", "vector", "ESP_LOG", "esp_timer"):
            self.assertNotIn(bad, chain, "the worker's hash must hold no lock, touch no AdminAuth state, allocate nothing")
        self.assertIsNone(re.search(r"std::string\b", chain), "std::string allocates; the chain uses views and arrays")
        w = func_body(self.logic, r"bool workOnce\(Hash&& hash\)")
        for bad in ("lock", "mutex", "new ", "ESP_LOG"):
            self.assertNotIn(bad, w)
        self.assertIsNone(re.search(r"std::string\b", w))

    def test_the_task_has_a_psram_stack_only_because_it_never_flashes(self):
        start = func_body(self.src, r"void start\(\)")
        self.assertEqual(len(re.findall(r"xTaskCreate\w*\(|createTaskPreferPsram\(", self.src)), 1)
        self.assertRegex(start, r'createTaskPreferPsram\(pinVerifyTask, "pin_verify", kStackBytes, &h, 1, &task, 0\)')
        self.assertRegex(self.src, r"constexpr uint32_t kStackBytes = 4096;")
        self.assertNotIn("PD_ASSERT_NOT_PSRAM_STACK", self.src, "that macro is for tasks that flash")

    def test_no_function_local_static_sits_on_the_task_call_chain(self):
        task = func_body(self.src, r"void pinVerifyTask\(void\* arg\)")
        for bad in ("handoff()", "executor()", "running()", "static "):
            self.assertNotIn(bad, task, "a function-local static puts __cxa_guard (1376 B) on the task's chain")

    def test_the_round_loop_yields_a_tick_and_only_the_worker_asks_for_it(self):
        self.assertRegex(self.src, r"void yieldOneTick\(\) \{ vTaskDelay\(1\); \}")
        self.assertIn("matchesDtmfPin(j.ticket, std::string_view(j.pin), kYield)", self.src)
        self.assertIn("if (yield != nullptr && i % AdminAuth::kYieldEveryRounds == 0) yield();", self.auth)

    def test_the_worker_logs_one_capped_witness_line_after_the_hash_and_never_the_result(self):
        task = func_body(self.src, r"void pinVerifyTask\(void\* arg\)")
        # one call site, a plain local counter, capped, and after the hash
        self.assertEqual(len(re.findall(r"\bESP_LOG[EWIDV]\(", task)), 1, "one log call site in the task")
        self.assertIn("unsigned logged = 0;", task)
        self.assertNotIn("static ", task)
        self.assertRegex(self.src, r"constexpr unsigned kWitnessLines = 16;")
        self.assertLess(task.index("workOnce(realHash)"), task.index("logged < kWitnessLines"))
        self.assertLess(task.index("logged < kWitnessLines"), task.index("ESP_LOGW("))
        self.assertLess(task.index("esp_timer_get_time()"), task.index("workOnce(realHash)"), "timed from before the hash")
        self.assertLess(task.index("uxTaskGetStackHighWaterMark"), task.index("ESP_LOGW("), "mark read before the line's own log call")
        self.assertIn("++logged;", task)
        self.assertLess(task.index("++logged;"), task.index("ESP_LOGW("))
        # the arguments are the count, the cap, the time, the mark and the stack size: nothing else
        call = re.search(r'ESP_LOGW\(kTag, "([^"]*)",([^;]*)\);', task, re.S)
        self.assertIsNotNone(call)
        fmt, args = call.group(1), [a.strip() for a in call.group(2).split(",")]
        self.assertEqual(args, ["logged", "kWitnessLines", "ms", "hwm", "static_cast<unsigned>(kStackBytes)"])
        self.assertEqual(fmt.count("%"), len(args))
        for word in ("pin", "match", "candidate", "length", "result", "digit"):
            self.assertNotIn(word, fmt.lower(), "the witness line must not name the PIN or the result")
        for word in ("matched", "Job", "job", "ticket", "salt"):
            self.assertNotIn(word, task, "the task body never touches the job's contents or the result")
        # the log call is not inside the hash chain, nor anywhere that holds a lock of ours
        self.assertEqual(len(re.findall(r"\bESP_LOG[EWIDV]\(", self.src)), 2, "the task's line and start()'s failure line")
        self.assertNotIn("lock", task.lower())

    def test_the_stack_figure_says_logging_is_included(self):
        with open(os.path.join(SRC, "SIP", "AdminPinVerify.cpp"), encoding="utf-8") as f:
            raw = f.read()
        before = raw[:raw.index("constexpr uint32_t kStackBytes")]
        self.assertIn("logging is included in the figure", before)
        self.assertIn("BEFORE", before[before.rindex("What the worker's stack has to hold"):],
                      "the comment says which high-water reading the line carries")

    def test_the_task_is_in_the_stack_budget_table(self):
        with open(os.path.join(REPO, "tools", "ci", "task_stacks.json"), encoding="utf-8") as f:
            rows = [r for r in json.load(f)["tasks"] if r.get("file") == "src/SIP/AdminPinVerify.cpp"]
        self.assertEqual([(r["name"], r["bytes"]) for r in rows], [("pin_verify", 4096)])
        self.assertEqual(rows[0]["entry"], "\\bpinVerifyTask\\(")

    def test_the_file_is_in_both_builds(self):
        for path in ("main/CMakeLists.txt", "tests/CMakeLists.txt"):
            with open(os.path.join(REPO, path), encoding="utf-8") as f:
                self.assertIn("../src/SIP/AdminPinVerify.cpp", f.read(), path)

    def test_the_worker_is_started_at_boot_from_the_dtmf_loader(self):
        load = func_body(code("SIP/DtmfFeatureCodes.cpp"), r"void DtmfFeatureCodes::load\(\)")
        self.assertIn("adminpin::start();", load)
        self.assertLess(load.index("adminpin::start();"), load.index("nvs_open") if "nvs_open" in load else len(load))


class TheApplyRunsInsideTicksMutexScope(unittest.TestCase):
    def setUp(self):
        self.rh = code("SIP/RequestsHandler.cpp")

    def test_apply_is_called_from_tick_only_and_after_the_lock_is_taken(self):
        self.assertEqual(self.rh.count("applyAdminPin("), 1, "only tick() applies a result")
        tick = func_body(self.rh, r"void RequestsHandler::tick\(\)")
        self.assertEqual(tick.count("_dtmf.applyAdminPin();"), 1)
        lock = tick.index("std::lock_guard<pd::TimedMutex> lock(_mutex);")
        apply_ = tick.index("_dtmf.applyAdminPin();")
        drain = tick.index("drainDtmfInbox();")
        end_of_scope = tick.index("drainPassLocked(_tickOutboxScratch, _tickLogScratch);")
        flush = tick.index("flushPass(_tickOutboxScratch, _tickLogScratch);")
        self.assertLess(lock, apply_)
        self.assertLess(drain, apply_)
        self.assertLess(apply_, end_of_scope, "inside the lock scope, so its log and sends ride out with this pass")
        self.assertLess(end_of_scope, flush)
        # nothing between the lock and the apply closes the scope
        between = tick[lock:apply_]
        self.assertEqual(between.count("{"), between.count("}"), "no scope closed between the lock and the apply")

    def test_the_apply_runs_the_accounting_before_the_code(self):
        src = code("SIP/AdminPinVerifyLogic.hpp")
        b = func_body(src, r"bool applyIfReady\(Finish&& finish, Run&& run\)")
        self.assertLess(b.index("finish(_job.ticket, _job.matched)"), b.index("run("))
        self.assertLess(b.index("run("), b.index("_phase.store(Phase::Idle"))
        d = func_body(code("SIP/DtmfFeatureCodes.cpp"), r"void DtmfFeatureCodes::applyAdminPin\(\)")
        self.assertIn("runAdminCode(job.code, job.confirm)", d)
        self.assertLess(d.index("if (!authenticated)"), d.index("findSession(job.callId)"))
        self.assertLess(d.index("findSession(job.callId)"), d.index("runAdminCode("))


class HandoffOrder(unittest.TestCase):
    def setUp(self):
        self.logic = code("SIP/AdminPinVerifyLogic.hpp")

    def test_submit_refuses_a_busy_slot_before_it_asks_adminauth_and_wakes_last(self):
        b = func_body(self.logic, r"SubmitResult submit\(")
        cas = b.index("compare_exchange_strong")
        begin = b.index("begin(_job.ticket)")
        run = b.index("Phase::Running")
        wake = b.index("_ex.wake()")
        self.assertLess(cas, begin, "a busy slot must be refused before AdminAuth is asked (nothing counted)")
        self.assertLess(begin, run)
        self.assertLess(run, wake, "the worker is woken only once the slot says Running")
        self.assertIn("Phase::Idle", b[begin:run], "a refused begin gives the slot back")

    def test_the_worker_publishes_done_after_the_hash_and_the_pin_wipe(self):
        b = func_body(self.logic, r"bool workOnce\(Hash&& hash\)")
        self.assertLess(b.index("hash("), b.index("scrub(_job.pin)"))
        self.assertLess(b.index("scrub(_job.pin)"), b.index("Phase::Done"))


if __name__ == "__main__":
    unittest.main()

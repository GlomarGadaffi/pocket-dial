"""#985 slice 0: pin, at the source level, what the host tests cannot see.

MediaTx_test.cpp proves the arithmetic, the L2 counters and the MediaBridge wiring on a fake
clock. What it cannot see is the ESP-only code: that the 20 ms loops only RECORD (no log, no
allocation, no lock, no printf), that HoldMusic counts a missed tick only in the branch where
xTaskDelayUntil said it missed, that the failed fallback sendto is counted where it happens, that
the old _l2TxErrors aggregate is untouched, that the witness lines are written from tick() and
nowhere else, and that TCP_NODELAY is applied to the audio POST socket and to nothing else, off
by default, in RAM only.
"""
import os
import re
import unittest

REPO = os.path.join(os.path.dirname(__file__), "..", "..")
SRC = os.path.join(REPO, "src")


def read(path, root=SRC):
    with open(os.path.join(root, path), encoding="utf-8") as f:
        return f.read()


_TOKEN = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', re.S)


def strip_comments(text):
    """Drop // and /* */ comments in one left-to-right pass, so a '/*' inside a // comment or a
    string does not open a block comment that swallows real code."""
    return _TOKEN.sub(lambda m: m.group(0) if m.group(0)[0] in "\"'" else " ", text)


def code(path, root=SRC):
    """Source with // and /* */ comments removed, so a comment can't satisfy a pin."""
    return strip_comments(read(path, root))


def func_body(text, signature):
    """Body of the function whose header matches `signature` (a regex ending before the '{'),
    found by matching braces."""
    m = re.search(signature + r"[^{;]*\{", text, re.S)
    assert m, signature + " not found"
    depth, i = 1, m.end()
    while depth:
        c = text[i]
        depth += (c == "{") - (c == "}")
        i += 1
    return text[m.end():i - 1]


# Nothing a 20 ms media task may do while it records: allocate, lock, format, log.
FORBIDDEN_IN_THE_HOT_PATH = (
    "std::string", "std::vector", "std::function", "std::mutex", "lock_guard", "unique_lock",
    "malloc", "calloc", "realloc", "new ", "printf", "snprintf", "ESP_LOG", "PD_WITNESS",
    "queueLog", "std::cout", "std::cerr", "vTaskDelay", "xSemaphore", "xQueue",
)


def src_files():
    for root, _dirs, files in os.walk(SRC):
        for name in files:
            if name.endswith((".cpp", ".hpp", ".h")):
                path = os.path.join(root, name)
                yield os.path.relpath(path, SRC).replace(os.sep, "/"), strip_comments(read(path, SRC))


class TheRecordingCallsOnlyRecord(unittest.TestCase):
    def setUp(self):
        self.stats = code("SIP/MediaTxStats.hpp")

    def test_the_whole_stats_header_has_nothing_that_blocks_allocates_or_logs(self):
        for bad in FORBIDDEN_IN_THE_HOT_PATH:
            self.assertNotIn(bad, self.stats, "MediaTxStats.hpp is called from 20 ms media tasks: " + bad)

    def test_every_atomic_in_it_is_32_bits_or_a_flag(self):
        # 64-bit atomics are not lock-free on Xtensa: they go through a libatomic critical section.
        for m in re.finditer(r"std::atomic<\s*([^>]+?)\s*>", self.stats):
            self.assertIn(m.group(1), ("uint32_t", "uint8_t", "bool"), m.group(0))

    def test_the_recording_functions_are_only_atomic_arithmetic(self):
        for sig in (r"static void recordWrite\(", r"static void recordTickMiss\(", r"static void recordFeedFrame\(",
                    r"static void recordL2Fail\(", r"static void recordL2RetryOk\(", r"static void noteSlow\(",
                    r"void add\(", r"static void raiseTo\("):
            body = func_body(self.stats, sig)
            for bad in FORBIDDEN_IN_THE_HOT_PATH:
                self.assertNotIn(bad, body, sig + ": " + bad)

    def test_the_witness_is_drained_by_tick_and_by_nothing_else(self):
        users = [p for p, text in src_files() if "takeWitness(" in text]
        self.assertEqual(sorted(users), ["SIP/MediaTxStats.hpp", "SIP/RequestsHandler.cpp"])
        rh = code("SIP/RequestsHandler.cpp")
        self.assertEqual(rh.count("reportMediaTxWitnesses();"), 1, "one call, from tick()")
        tick = func_body(rh, r"void RequestsHandler::tick\(")
        self.assertLess(tick.index("flushPass(_tickOutboxScratch, _tickLogScratch);"),
                        tick.index("reportMediaTxWitnesses();"), "after tick()'s lock scope and its flush")
        report = func_body(rh, r"void RequestsHandler::reportMediaTxWitnesses\(")
        self.assertIn("kLegs + 1) * pd::MediaTx::kWitnessPerSlot", report, "bounded by the table")

    def test_the_media_tasks_added_no_log_allocation_or_lock(self):
        mb = code("SIP/MediaBridge.cpp")
        for sig in (r"void MediaBridge::onHandsetRtp\(", r"void MediaBridge::feedMohTick\("):
            body = func_body(mb, sig)
            for bad in ("ESP_LOG", "PD_WITNESS", "printf", "snprintf", "new ", "malloc", "std::string "):
                self.assertNotIn(bad, body, sig + ": " + bad)
            self.assertIn("pd::MediaTx::recordWrite(", body)
        # the stamps sit AROUND the call, not in a wrapper: no new frame under the deepest path (#273)
        for body in (func_body(mb, r"void MediaBridge::onHandsetRtp\("), func_body(mb, r"void MediaBridge::feedMohTick\(")):
            self.assertLess(body.index("nowUs()"), body.index("_anchor->writeAudio("))
        l2 = code("Helpers/L2RtpFrame.cpp")
        t = func_body(l2, r"bool EgressChannel::transmit\(")
        for bad in FORBIDDEN_IN_THE_HOT_PATH:
            self.assertNotIn(bad, t, "EgressChannel::transmit: " + bad)

    def test_the_bridge_keeps_its_stamp_in_a_32_bit_atomic(self):
        self.assertNotIn("atomic<int64_t>", code("SIP/MediaBridge.hpp"))
        self.assertNotIn("atomic<uint64_t>", code("SIP/MediaBridge.hpp"))


class HoldMusicCountsAMissOnlyWhereTheLoopSawOne(unittest.TestCase):
    def test_a_miss_is_recorded_in_the_pdfalse_branch_before_the_deadline_is_reset(self):
        hm = code("SIP/HoldMusic.cpp")
        run = func_body(hm, r"void HoldMusic::runLoop\(")
        m = re.search(r"if \(xTaskDelayUntil\(&next, pdMS_TO_TICKS\(PTIME_MS\)\) == pdFALSE\)\s*\{(.*?)\n\t\t\}", run, re.S)
        self.assertIsNotNone(m, "the pdFALSE branch moved or changed")
        branch = m.group(1)
        self.assertIn("pd::MediaTx::recordTickMiss(", branch)
        self.assertLess(branch.index("recordTickMiss("), branch.index("next = xTaskGetTickCount();"),
                        "the overrun is read before the deadline is reset")
        # the original reset is still the last statement of the branch
        self.assertTrue(branch.rstrip().endswith("next = xTaskGetTickCount();"))
        self.assertEqual(run.count("pd::MediaTx::"), 1, "nothing else in the 20 ms loop records")

    def test_the_old_aggregate_is_untouched_and_still_counts_every_failed_ready_transmit(self):
        for path in ("SIP/HoldMusic.cpp", "SIP/RtpSender.cpp"):
            text = code(path)
            self.assertEqual(text.count("++_l2TxErrors;"), 1, path)
            # shape the split counters' sum relies on (MediaTx_test: TheFourCausesSumTo...):
            # transmit() runs only after updateAddressing() returned true, and the aggregate
            # counts exactly its false return
            self.assertRegex(text, r"updateAddressing\([^{;]*\{[^{}]*?l2Success\s*=\s*\S*[lL]2Channel\.transmit\("
                                   r"[^;]*;\s*if \(!l2Success\)\s*\{\s*\+\+_l2TxErrors;", path)
        hm = code("SIP/HoldMusic.cpp")
        self.assertIn("long HoldMusic::l2TxErrors() const", hm)
        hs = code("Helpers/HttpServer.cpp")
        self.assertIn(r'\"mohL2Errors\"', hs, "the old status field keeps its name and meaning")

    def test_transmit_has_one_caller_family_and_one_status_consumer(self):
        callers = [p for p, text in src_files() if re.search(r"\.transmit\(", text) and "EgressChannel" in text or
                   (p in ("SIP/HoldMusic.cpp", "SIP/RtpSender.cpp") and "l2Channel.transmit(" in text.replace("_l2Channel", "l2Channel"))]
        self.assertEqual(sorted(set(callers)), ["SIP/HoldMusic.cpp", "SIP/RtpSender.cpp"])
        users = [p for p, text in src_files() if "EthAccess::transmitL2(" in text]
        self.assertEqual(users, ["Helpers/L2RtpFrame.cpp"], "the only consumer of TxStatus")

    def test_a_failed_fallback_sendto_is_counted_where_rtpsender_makes_it(self):
        rs = code("SIP/RtpSender.cpp")
        self.assertEqual(rs.count("recordFallbackSendFail()"), 1)
        i = rs.index("recordFallbackSendFail()")
        before = rs[:i]
        self.assertRegex(before[before.rindex("sendto("):], r"sendto\([^;]*?\)\s*<\s*0\)\s*\{\s*pd::MediaTx::$")
        self.assertIn("!l2Success && sock >= 0", before[-400:])
        # the desktop (Linux) arm has no L2 path, so its sendto is not a fallback and stays as it was
        linux = rs[rs.rindex("#elif defined(__linux__)"):]
        self.assertNotIn("recordFallbackSendFail", linux)


class TheStatusBlock(unittest.TestCase):
    def setUp(self):
        self.hs = code("Helpers/HttpServer.cpp")
        self.api = read("docs/API.md", REPO)

    def test_mediatx_is_built_after_mutexhold_and_before_the_bench_only_key(self):
        status = func_body(self.hs, r"void HttpServer::sendApiStatus\(")
        self.assertEqual(status.count("pdAppendMediaTx(json);"), 1)
        self.assertLess(status.index('",\\"mutexHold\\":{'), status.index("pdAppendMediaTx(json);"))
        self.assertLess(status.index("pdAppendMediaTx(json);"), status.index("#if POCKETDIAL_HTTP_DRAM_ACCOUNT"))

    def test_the_block_is_one_noinline_function_with_no_arrays_and_no_platform_arm(self):
        i = self.hs.index("static void pdAppendMediaTx(JsonOut& json)")
        self.assertIn("noinline", self.hs[i - 160:i], "keeps sendApiStatus's frame where it was (#405)")
        body = func_body(self.hs, r"static void pdAppendMediaTx\(JsonOut& json\)")
        for bad in ("#if", "std::string", "char ", "snprintf"):
            self.assertNotIn(bad, body)
        self.assertIn(r'\"mediaTx\"', body)

    def test_every_key_is_documented(self):
        body = func_body(self.hs, r"static void pdAppendMediaTx\(JsonOut& json\)")
        hist = func_body(self.hs, r"static void pdAppendMediaTxHist\(")
        keys = set(re.findall(r'\\"([A-Za-z0-9]+)\\":', body + hist))
        self.assertTrue({"mediaTx", "nodelay", "write", "legOver", "hold", "feed", "l2", "build", "tx", "poolMin",
                         "errPoolEmpty", "errZeroLen", "errNoHandle", "errDriver", "retryOk",
                         "fallbackSendFail"} <= keys, keys)
        # the field table's mediaTx rows, up to the note after the table
        start = self.api.index("| `mediaTx` |")
        rows = self.api[start:self.api.index("> **Task-Watchdog coverage", start)]
        for key in sorted(keys):
            self.assertRegex(rows, r"[`.]" + re.escape(key) + r"\b", "docs/API.md does not document mediaTx key " + key)
        self.assertIn("POST /api/media-tx", self.api)


class TheL2RetryLivesInTransmitAndNowhereElse(unittest.TestCase):
    """#999: one immediate retry of a driver error. Both producers (RtpSender::runLoop and
    HoldMusic::runLoop) reach the driver through EgressChannel::transmit, so the retry is there
    once; MediaTx_test.cpp holds the behaviour, this holds the shape the host cannot see."""

    def setUp(self):
        self.t = func_body(code("Helpers/L2RtpFrame.cpp"), r"bool EgressChannel::transmit\(")

    def test_the_second_hand_off_is_the_same_frame_and_only_a_driver_error_reaches_it(self):
        t = self.t
        self.assertEqual(t.count("EthAccess::transmitL2("), 2)
        self.assertIn("EthAccess::TxStatus status = EthAccess::transmitL2(frame.data(), len);", t)
        gate = re.search(r"const bool retried = \(status == EthAccess::TxStatus::DriverError\);\s*"
                         r"if \(retried\)\s*\{\s*status = EthAccess::transmitL2\(frame\.data\(\), len\);\s*\}", t)
        self.assertIsNotNone(gate, "the retry is gated on DriverError and on nothing else")
        self.assertLess(t.index("EthAccess::transmitL2("), gate.start(), "the retry follows the first attempt")
        # one frame: not drawn again, not rebuilt
        self.assertEqual(t.count("DmaFramePool::acquire("), 1)
        self.assertEqual(t.count("patchTick("), 1)

    def test_it_adds_no_wait_no_loop_and_no_clock_read(self):
        t = self.t
        for bad in ("for (", "while (", "do {", "taskYIELD", "vTaskDelay", "esp_rom_delay_us", "ets_delay_us",
                    "usleep", "sleep_for", "xTask"):
            self.assertNotIn(bad, t, "EgressChannel::transmit: " + bad)
        self.assertEqual(t.count("nowUs()"), 3, "the three stamps of #985, none inside the retry")

    def test_the_hand_off_stamp_is_taken_after_the_retry_and_a_rescue_is_not_a_failure(self):
        t = self.t
        gate_end = re.search(r"if \(retried\)\s*\{\s*status = EthAccess::transmitL2\(frame\.data\(\), len\);\s*\}", t).end()
        self.assertGreater(t.index("const uint32_t t2 = pd::MediaTx::nowUs();"), gate_end,
                           "l2.tx covers both attempts")
        ok = re.search(r"if \(status == EthAccess::TxStatus::Ok\)\s*\{\s*if \(retried\)\s*\{\s*"
                       r"pd::MediaTx::recordL2RetryOk\(\);\s*\}\s*return true;\s*\}", t)
        self.assertIsNotNone(ok, "a retry that was accepted counts retryOk and returns true")
        self.assertEqual(t.count("recordL2RetryOk("), 1)
        # the failure counter is picked from the FINAL status, once
        self.assertEqual(t.count("recordL2Fail("), 3)
        self.assertIn("recordL2Fail(status == EthAccess::TxStatus::NoHandle", t)
        self.assertLess(ok.end(), t.index("recordL2Fail(status =="))

    def test_neither_producer_has_a_retry_of_its_own(self):
        for path in ("SIP/RtpSender.cpp", "SIP/HoldMusic.cpp"):
            text = code(path)
            self.assertEqual(text.count("l2Channel.transmit("), 1, path)
            for bad in ("transmitL2", "TxStatus", "DriverError", "recordL2RetryOk"):
                self.assertNotIn(bad, text, path + ": " + bad)
        users = [p for p, text in src_files() if "recordL2RetryOk(" in text]
        self.assertEqual(sorted(users), ["Helpers/L2RtpFrame.cpp", "SIP/MediaTxStats.hpp"])

    def test_retryok_sits_between_errdriver_and_fallbacksendfail_and_the_docs_state_the_sum(self):
        body = func_body(code("Helpers/HttpServer.cpp"), r"static void pdAppendMediaTx\(JsonOut& json\)")
        self.assertLess(body.index(r'\"errDriver\"'), body.index(r'\"retryOk\"'))
        self.assertLess(body.index(r'\"retryOk\"'), body.index(r'\"fallbackSendFail\"'))
        self.assertIn("pd::MediaTx::l2RetryOk()", body)
        stats = code("SIP/MediaTxStats.hpp")
        self.assertIn("s_.l2RetryOk.store(0, kRelaxed);", stats, "zeroed with its neighbours")
        self.assertIn("first attempts that failed = `errDriver` + `retryOk`", read("docs/API.md", REPO))


class TheNagleSwitch(unittest.TestCase):
    """TCP_NODELAY on the anchor's audio POST socket: off by default, RAM only, that socket only."""

    def setUp(self):
        self.tac = code("SIP/TelephonyAnchorClient.cpp")
        self.stats = code("SIP/MediaTxStats.hpp")

    def test_the_default_is_off_and_it_is_not_persisted_anywhere(self):
        self.assertRegex(self.stats, r"kNodelayDefault\s*=\s*false;")
        self.assertRegex(self.stats, r"std::atomic<bool> s_nodelay\{kNodelayDefault\}")
        self.assertIn("s_nodelay.store(kNodelayDefault, kRelaxed);", self.stats, "a reset returns to the boot value")
        for bad in ("nvs_", "Nvs", "Preferences", "persist", "Persist", "DeviceConfig", "flash"):
            self.assertNotIn(bad, self.stats, bad)
        hs = code("Helpers/HttpServer.cpp")
        for bad in ("nvs_", "NvsWriter", "persist", "Persist", "DeviceConfig::"):
            self.assertNotIn(bad, func_body(hs, r"void HttpServer::sendApiMediaTx\("), bad)
        mentions = sorted(p for p, text in src_files() if re.search(r"nodelay", text, re.I))
        self.assertEqual(mentions, ["Helpers/HttpServer.cpp", "Helpers/index_html.h", "SIP/MediaTxStats.hpp", "SIP/TelephonyAnchorClient.cpp"],
                         "no store, no config key, no other reader of the flag (the page only posts it)")

    def test_tcp_nodelay_is_set_in_one_helper_and_nowhere_else_in_the_tree(self):
        users = [p for p, text in src_files() if "TCP_NODELAY" in text]
        self.assertEqual(users, ["SIP/TelephonyAnchorClient.cpp"])
        self.assertEqual(len(re.findall(r"IPPROTO_TCP, TCP_NODELAY", self.tac)), 1)
        helper = func_body(self.tac, r"static void applyAudioNodelay\(")
        self.assertIn("TCP_NODELAY", helper)
        # the flag is checked before the socket is touched: off means no setsockopt and no log
        self.assertLess(helper.index("if (!pd::MediaTx::nodelay()) return;"), helper.index("esp_http_client_get_socket("))
        self.assertLess(helper.index("if (!pd::MediaTx::nodelay()) return;"), helper.index("setsockopt("))
        self.assertLess(helper.index("if (!pd::MediaTx::nodelay()) return;"), helper.index("ESP_LOG"))
        # one log line per socket: a set and a failure, nothing else
        self.assertEqual(len(re.findall(r"ESP_LOG[IWE]\(", helper)), 2)

    def test_the_helper_is_called_once_for_the_audio_post_client_after_both_opens(self):
        self.assertEqual(self.tac.count("applyAudioNodelay("), 2, "the definition and one call")
        start = func_body(self.tac, r"bool TelephonyAnchorClient::startMediaStreams\(")
        self.assertEqual(start.count("applyAudioNodelay("), 1)
        call = re.search(r"applyAudioNodelay\(([^;]*)\);", start).group(1)
        self.assertTrue(call.startswith("slot->postClient,"), call)
        opens = [m.start() for m in re.finditer(r"esp_http_client_open\(slot->postClient, -1\)", start)]
        self.assertEqual(len(opens), 2, "the first open and the retry on a rebuilt handle")
        at = start.index("applyAudioNodelay(")
        self.assertGreater(at, opens[1], "after the retry: both successful opens land on the one call")
        self.assertLess(at, start.index("slot->postLive.store(true"), "before any write can happen")

    def test_it_never_runs_in_the_write_path_or_on_another_client(self):
        write = func_body(self.tac, r"bool TelephonyAnchorClient::writeAudio\(")
        for bad in ("setsockopt", "TCP_NODELAY", "applyAudioNodelay", "nodelay"):
            self.assertNotIn(bad, write, "writeAudio is the 20 ms loop")
        # every esp_http_client_open site is inventoried: a new one must be classified here
        # (and left without the option unless it opens the audio POST stream).
        self.assertEqual(self.tac.count("esp_http_client_open("), 8)
        audio = re.findall(r"esp_http_client_open\(slot->postClient, -1\)", self.tac)
        self.assertEqual(len(audio), 2)
        others = re.findall(r"esp_http_client_open\(([^;]*?)\)[;) ]", self.tac)
        self.assertEqual(sorted(a.split(",")[0] for a in others if "-1" not in a),
                         sorted(["client", "client", "client", "slot.postClient", "h", "_getClient"]))

    def test_the_setter_is_owner_gated_and_csrf_checked(self):
        hs = code("Helpers/HttpServer.cpp")
        m = re.search(r'req\.method == "POST" && req\.path == "/api/media-tx"\)\s*\{(.*?)\n\t\}', hs, re.S)
        self.assertIsNotNone(m)
        self.assertIn("requireAdmin(clientSock, req, true, AdminAuth::Role::Owner)", m.group(1))
        self.assertIn("sendApiMediaTx(clientSock, req.body)", m.group(1))
        self.assertNotIn('"GET" && req.path == "/api/media-tx"', hs.replace("\\", ""))

    def test_the_status_block_carries_the_flag(self):
        hs = code("Helpers/HttpServer.cpp")
        body = func_body(hs, r"static void pdAppendMediaTx\(JsonOut& json\)")
        self.assertIn('\\"nodelay\\":', body)
        self.assertIn("pd::MediaTx::nodelay()", body)


if __name__ == "__main__":
    unittest.main()

"""#991: one flash-writer task for the CDR ring and the NVS writer.

FlashWriter_test.cpp drives the pass (flashwriter::passOnce) on the host. What it
cannot see is the board half, pinned here at the source level: one plain-stack
task where there were two (cdr_persist, nvs_writer), the #277 assert, a pass
before every wait, each source's producer waking it after its overwrite, each
source's start() publishing itself last (so the task never reaches a half-made
source, and nothing is deleted after the task could have seen it), the stack
table, and the status field the bench reads. cdr_archive is deliberately not
merged (FlashWriter.hpp says why) and keeps its own task.
"""
import json
import os
import re
import sys
import unittest

REPO = os.path.join(os.path.dirname(__file__), "..", "..")
SRC = os.path.join(REPO, "src")
sys.path.insert(0, os.path.join(REPO, "tools", "ci"))
import task_stack_gate  # noqa: E402

FW = "Helpers/FlashWriter.cpp"
CDR = "SIP/CdrRing.cpp"
NVS = "Helpers/NvsWriter.cpp"


def raw(path):
    with open(os.path.join(SRC, path), encoding="utf-8") as f:
        return f.read()


def code(path):
    """Source with // and /* */ comments removed, so a comment can't satisfy a pin."""
    text = re.sub(r"/\*.*?\*/", "", raw(path), flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def body(path, signature, indent=""):
    m = re.search(signature + r"\s*\{(.*?)\n" + indent + r"\}", code(path), re.S)
    assert m, signature + " not found in " + path
    return m.group(1)


def in_order(test, text, *markers):
    at = [text.index(m) for m in markers]
    test.assertEqual(at, sorted(at), " < ".join(markers))


class OneTask(unittest.TestCase):
    def test_one_create_site_for_the_flash_writer_and_none_left_for_the_two_it_replaced(self):
        sites = task_stack_gate.count_sites(REPO)
        self.assertEqual(sites.get("src/Helpers/FlashWriter.cpp"), 1)
        self.assertNotIn("src/SIP/CdrRing.cpp", sites)
        self.assertNotIn("src/Helpers/NvsWriter.cpp", sites)
        creates = []
        for top in ("src", "main"):
            for dp, _, fns in os.walk(os.path.join(REPO, top)):
                for fn in fns:
                    if fn.endswith((".c", ".cpp", ".h", ".hpp")):
                        with open(os.path.join(dp, fn), encoding="utf-8", errors="ignore") as f:
                            creates += re.findall(r"xTaskCreate\w*\([^;]*?\"(\w+)\"", f.read(), re.S)
        self.assertEqual(creates.count("flash_writer"), 1)
        self.assertNotIn("cdr_persist", creates)
        self.assertNotIn("nvs_writer", creates)
        self.assertIn("cdr_archive", creates, "#991: the SD archive stays a task of its own")

    def test_the_task_is_plain_internal_core_0_priority_1(self):
        src = code(FW)
        self.assertRegex(src, r'xTaskCreatePinnedToCore\(flashWriterTask, "flash_writer", 6144, nullptr, 1, &h, 0\)')
        for bad in ("PD_TASK_STACK_CAPS", "createTaskPreferPsram", "WithCaps", "xTaskCreateStatic"):
            self.assertNotIn(bad, src, "#277: a task that writes flash must not have a PSRAM stack")

    def test_the_task_asserts_its_stack_then_passes_then_waits(self):
        task = body(FW, r"void flashWriterTask\(void\*\)", "\t")
        in_order(self, task, "PD_ASSERT_NOT_PSRAM_STACK();",
                 "passOnce<&CdrRing::writePending, &nvswriter::writePending>()",
                 "ulTaskNotifyTake(pdTRUE, portMAX_DELAY)")
        self.assertEqual(code(FW).count("portMAX_DELAY"), 1, "the one blocking wait")

    def test_start_is_idempotent_and_publishes_the_handle_after_the_create(self):
        b = body(FW, r"bool start\(\)")
        in_order(self, b, "taskHandle().load(", "xTaskCreatePinnedToCore(", "taskHandle().store(h")
        failed = b[b.index("xTaskCreatePinnedToCore("):b.index("taskHandle().store(h")]
        self.assertIn("ESP_LOGE(", failed)
        self.assertIn("return false;", failed)

    def test_wake_never_notifies_a_task_that_does_not_exist(self):
        self.assertRegex(body(FW, r"void wake\(\)"), r"if \(h != nullptr\) xTaskNotifyGive\(h\);")


class CdrRingSource(unittest.TestCase):
    def setUp(self):
        self.src = code(CDR)
        self.unit = body(CDR, r"unsigned CdrRing::writePending\(\)")
        self.start = body(CDR, r"void ensureWriterTaskStarted\(\)", "\t")

    def test_no_task_of_its_own(self):
        self.assertEqual(re.findall(r"xTaskCreate\w*\(", self.src), [])
        self.assertNotIn("portMAX_DELAY", self.src, "the ring must never park the shared task on its own queue")

    def test_persist_wakes_the_writer_after_the_overwrite(self):
        p = body(CDR, r"void CdrRing::persist\(\)")
        in_order(self, p, "persistAction(", "xQueueOverwrite(cdrPersistQueue(), &blob)", "flashwriter::wake();")

    def test_the_unit_takes_one_snapshot_without_blocking_and_only_once_published(self):
        in_order(self, self.unit, "writerReady().load(std::memory_order_acquire)",
                 "static CdrRingBlob blob;", "xQueueReceive(cdrPersistQueue(), &blob, 0)")
        self.assertEqual(self.unit.count("xQueueReceive("), 1, "one unit a pass")

    def test_the_unit_keeps_the_writer_body_order(self):
        # unchanged from cdr_persist: the erase is not gated, a data write is
        in_order(self, self.unit, "xQueueReceive(", "if (blob.erase)", "resetguard::WriteScope scope;",
                 "scope.allowed()", "nvs_set_blob(")
        self.assertEqual(self.unit.count("resetguard::"), 1, "one WriteScope, and only around the data write")

    def test_start_publishes_last_and_unwinds_only_before_publishing(self):
        in_order(self, self.start, "xQueueCreate", "if (!flashwriter::start())", "writerReady().store(true")
        failed = self.start[self.start.index("if (!flashwriter::start())"):self.start.index("writerReady().store(true")]
        for needed in ("ESP_LOGE(", "persistFailures().fetch_add(1);", "vQueueDeleteWithCaps(cdrPersistQueue());",
                       "vQueueDelete(cdrPersistQueue());", "cdrPersistQueue() = nullptr;", "started = false;", "return;"):
            self.assertIn(needed, failed)
        self.assertEqual(self.src.count("writerReady().store(true"), 1)


class NvsSource(unittest.TestCase):
    def setUp(self):
        self.src = code(NVS)
        self.start = body(NVS, r"void start\(\)")

    def test_the_unit_reaches_the_stager_only_once_running(self):
        in_order(self, body(NVS, r"unsigned writePending\(\)"),
                 "running().load(std::memory_order_acquire)", "stagerRef().drainOnce(nvsSink)")

    def test_start_builds_the_stager_after_the_task_exists_and_publishes_last(self):
        in_order(self, self.start, "xQueueCreate", "if (!flashwriter::start())", "(void)stagerRef();",
                 "running().store(true")

    def test_a_stage_wakes_the_writer_only_when_it_queued_something(self):
        s = body(NVS, r"StageResult stage\(Key k, FunctionRef<void\(BlobWriter&\)> fill\)")
        self.assertRegex(s, r"if \(r == StageResult::Ok\)\s*\{\s*flashwriter::wake\(\);\s*\}")


class TableStatusAndBuild(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(REPO, "tools", "ci", "task_stacks.json"), encoding="utf-8") as f:
            self.rows = json.load(f)["tasks"]

    def test_the_stack_table_has_the_merged_row_and_not_the_old_two(self):
        names = [r["name"] for r in self.rows]
        self.assertNotIn("cdr_persist", names)
        self.assertNotIn("nvs_writer", names)
        fw = [r for r in self.rows if r["name"] == "flash_writer"]
        self.assertEqual(len(fw), 1)
        self.assertEqual((fw[0]["file"], fw[0]["bytes"]), ("src/Helpers/FlashWriter.cpp", 6144))
        self.assertRegex("void flashwriter::{anonymous}::flashWriterTask(void*)", fw[0]["entry"],
                         "the GCC label the gate walks")
        self.assertEqual([r["file"] for r in self.rows if r["name"] == "cdr_archive"], ["src/SIP/CdrArchive.cpp"])

    def test_status_reports_the_merged_task_under_its_tcb_name(self):
        http = raw("Helpers/HttpServer.cpp")
        self.assertIn('pdAppendHwmField(json, "stackHwm_flash_writer", pdStackHwmBytes("flash_writer"));', http)
        self.assertIn('\\"stackHwm_flash_writer\\":null', http, "the host arm keeps the same key set")

    def test_the_esp_build_compiles_the_task(self):
        with open(os.path.join(REPO, "main", "CMakeLists.txt"), encoding="utf-8") as f:
            self.assertIn('"../src/Helpers/FlashWriter.cpp"', f.read())


if __name__ == "__main__":
    unittest.main()

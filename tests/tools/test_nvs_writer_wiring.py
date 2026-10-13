"""#986 slice 2: pin the parts of the NVS writer no host test reaches.

Host tests (NvsWriter_test.cpp) run the policy and the two callers on the host's
queues. What they cannot see is (a) that the callers no longer touch NVS under
RequestsHandler::_mutex, and (b) the FreeRTOS half: per-key queues written with
xQueueOverwrite, a task woken by notification, created pinned at the cdr_persist
size. This checks both at the source level.
"""
import json
import os
import re
import unittest

REPO = os.path.join(os.path.dirname(__file__), "..", "..")
SRC = os.path.join(REPO, "src")


def code(path):
    """Source with // and /* */ comments removed, so a comment can't satisfy a pin."""
    with open(os.path.join(SRC, path), encoding="utf-8") as f:
        text = f.read()
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def body(path, signature):
    m = re.search(signature + r"\s*\{(.*?)\n\}", code(path), re.S)
    assert m, signature + " not found in " + path
    return m.group(1)


def indented_body(path, signature):
    """Body of a function nested one tab deep (inside a namespace): up to its closing tab-brace."""
    m = re.search(signature + r"\s*\{(.*?)\n\t\}", code(path), re.S)
    assert m, signature + " not found in " + path
    return m.group(1)


NVS_CALLS = ("nvs_commit", "nvs_open", "nvs_set_str", "nvs_set_blob", "nvs_set_u8")


class CallersStageInsteadOfWriting(unittest.TestCase):
    def test_persist_devices_stages_and_never_touches_nvs(self):
        b = body("SIP/Registrar.cpp", r"bool Registrar::persistDevices\(\)")
        self.assertIn("nvswriter::stage(", b)
        self.assertIn("nvswriter::Key::Devices", b)
        for bad in NVS_CALLS + ("std::string blob", "std::to_string"):
            self.assertNotIn(bad, b, "persistDevices() runs under _mutex: " + bad)

    def test_persist_forwards_stages_and_never_touches_nvs(self):
        b = body("SIP/PbxFeatureConfig.cpp", r"void PbxFeatureConfig::persistForwards\(\)")
        self.assertIn("nvswriter::stage(", b)
        self.assertIn("nvswriter::Key::Forwards", b)
        for bad in NVS_CALLS + ("std::string blob",):
            self.assertNotIn(bad, b, "persistForwards() runs under _mutex: " + bad)

    def test_the_only_nvs_commit_left_in_registrar_is_the_mode_byte(self):
        src = code("SIP/Registrar.cpp")
        mode = body("SIP/Registrar.cpp", r"bool Registrar::persistMode\(\)")
        self.assertEqual(src.count("nvs_commit"), mode.count("nvs_commit"),
                         "Registrar.cpp commits NVS outside persistMode()")

    def test_the_dtmf_codes_reach_persist_forwards_through_the_one_setter(self):
        d = code("SIP/DtmfFeatureCodes.cpp")
        self.assertEqual(d.count('_cfg.setForwardLocked(callerExt, "always"'), 2, "the *72 and *73 sites")
        self.assertNotIn('"forwards"', d, "the DTMF codes must not write the key themselves")
        b = body("SIP/PbxFeatureConfig.cpp",
                 r"void PbxFeatureConfig::setForwardLocked\(const std::string& extension, "
                 r"const std::string& trigger, const std::string& target\)")
        self.assertIn("persistForwards()", b)
        for bad in NVS_CALLS:
            self.assertNotIn(bad, b)

    def test_the_boot_loaders_start_the_writer(self):
        self.assertIn("nvswriter::start()", body("SIP/Registrar.cpp", r"void Registrar::loadDevices\(\)"))
        self.assertIn("nvswriter::start()", body("SIP/PbxFeatureConfig.cpp", r"void PbxFeatureConfig::loadPbxConfig\(\)"))


class PolicyOrder(unittest.TestCase):
    def test_stage_refuses_a_reset_and_an_oversize_blob_before_it_overwrites(self):
        b = body("Helpers/NvsWriterLogic.hpp", r"StageResult stage\(Key k, Fill&& fill\)")
        over = b.index("_t.overwrite(")
        self.assertLess(b.index("resetguard::inProgress()"), over)
        self.assertLess(b.index("finish()"), over)

    def test_drain_registers_as_a_writer_before_it_takes_the_item(self):
        b = body("Helpers/NvsWriterLogic.hpp", r"unsigned drainOnce\(Sink&& sink\)")
        self.assertLess(b.index("resetguard::WriteScope scope"), b.index("_t.receive("))
        self.assertLess(b.index("_t.receive("), b.index("scope.allowed()"),
                        "a refused item must still be taken, so it is not kept for later")


class BoardWiring(unittest.TestCase):
    def setUp(self):
        self.src = code("Helpers/NvsWriter.cpp")

    def test_queues_are_written_with_overwrite_never_send(self):
        self.assertIn("xQueueOverwrite(", self.src)
        self.assertNotIn("xQueueSend(", self.src)
        self.assertIn("xQueueCreateWithCaps(1,", self.src)
        self.assertIn("xQueueCreate(1,", self.src)

    def test_nothing_on_the_stage_path_can_block(self):
        self.assertRegex(self.src, r"xQueueReceive\(q\[indexOf\(k\)\], item, 0\)")
        self.assertEqual(self.src.count("portMAX_DELAY"), 1, "only the writer's idle wait may block")
        self.assertIn("ulTaskNotifyTake(pdTRUE, portMAX_DELAY)", self.src)
        self.assertIn("xTaskNotifyGive(", self.src)

    def test_the_task_is_the_cdr_persist_shape(self):
        self.assertRegex(self.src, r'xTaskCreatePinnedToCore\(nvsWriterTask, "nvs_writer", 6144, nullptr, 1, &handle, 0\)')
        self.assertIn("PD_ASSERT_NOT_PSRAM_STACK();", self.src)
        self.assertIn("vQueueDeleteWithCaps(", self.src)
        self.assertIn("vQueueDelete(", self.src)

    def test_the_writer_never_reaches_back_into_the_engine(self):
        self.assertNotIn("_env", self.src)
        self.assertNotIn("Registrar", self.src)
        self.assertNotIn("PbxFeatureConfig", self.src)

    def test_the_task_is_in_the_stack_budget_table(self):
        with open(os.path.join(REPO, "tools", "ci", "task_stacks.json"), encoding="utf-8") as f:
            rows = [r for r in json.load(f)["tasks"] if r.get("file") == "src/Helpers/NvsWriter.cpp"]
        self.assertEqual([(r["name"], r["bytes"]) for r in rows], [("nvs_writer", 6144)])


class StagingSlotsAndStackPlacement(unittest.TestCase):
    """The board reserves the three staging slots in PSRAM at init (the DID table's joined in
    slice 4); the scratch the flash write reads and the task's stack stay internal
    (PsramTask.hpp, the #277 rule)."""

    def setUp(self):
        self.src = code("Helpers/NvsWriter.cpp")
        self.start = body("Helpers/NvsWriter.cpp", r"void start\(\)")

    def test_the_staging_slots_come_from_psram_in_start_and_the_scratch_does_not(self):
        self.assertRegex(self.start, r"s_devices = allocSlot<Slot<kDevicesCap>>\(\);")
        self.assertRegex(self.start, r"s_forwards = allocSlot<Slot<kForwardsCap>>\(\);")
        self.assertRegex(self.start, r"s_didmap = allocSlot<Slot<kDidMapCap>>\(\);")
        helper = indented_body("Helpers/NvsWriter.cpp", r"T\* allocSlot\(\)")
        self.assertIn("psram::allocPreferPsram(sizeof(T))", helper)
        self.assertEqual(self.src.count("allocPreferPsram("), 1, "the one allocation site is allocSlot()")
        self.assertRegex(self.src, r"(?m)^	Slot<kScratchCap> s_scratch;", "the scratch is a static: internal RAM")
        self.assertNotIn("allocSlot<Slot<kScratchCap>>", self.src)
        self.assertNotIn("s_scratch =", self.src)
        self.assertRegex(self.src, r"#else\s+Slot<kDevicesCap> s_devices;\s+Slot<kForwardsCap> s_forwards;\s+Slot<kDidMapCap> s_didmap;",
                         "the host keeps static slots")

    def test_the_writer_task_keeps_a_plain_internal_stack(self):
        for bad in ("PD_TASK_STACK_CAPS", "createTaskPreferPsram", "xTaskCreatePinnedToCoreWithCaps",
                    "xTaskCreateWithCaps", "xTaskCreateStaticPinnedToCore", "WithCaps(nvsWriterTask"):
            self.assertNotIn(bad, self.src)
        self.assertEqual(len(re.findall(r"xTaskCreate\w*\(", self.src)), 1, "one task, one plain create")
        self.assertIn("xTaskCreatePinnedToCore(nvsWriterTask", self.src)
        task = indented_body("Helpers/NvsWriter.cpp", r"void nvsWriterTask\(void\*\)")
        self.assertIn("PD_ASSERT_NOT_PSRAM_STACK();", task)

    def test_a_failed_slot_allocation_leaves_the_writer_not_running(self):
        b = self.start
        order = [b.index(m) for m in ("s_devices = allocSlot",
                                      "if (s_devices == nullptr || s_forwards == nullptr || s_didmap == nullptr || s_telephony == nullptr)",
                                      "xQueueCreate", "xTaskCreatePinnedToCore(", "running().store(true")]
        self.assertEqual(order, sorted(order), "allocate, check, queues, task, and only then running")
        failed = b[order[1]:order[2]]
        for needed in ("freeSlots();", "started = false;", "return;"):
            self.assertIn(needed, failed)
        self.assertNotIn("running().store(true", failed)
        self.assertEqual(self.src.count("running().store(true"), 1)
        # the later failures give the slots back too, like the queues
        for marker in ("queue create failed", "xTaskCreate nvs_writer failed"):
            seg = b[b.index(marker):]
            self.assertIn("freeSlots();", seg[:seg.index("return;")])
        # nothing reaches a slot unless the writer is running
        stage = body("Helpers/NvsWriter.cpp", r"StageResult stage\(Key k, FunctionRef<void\(BlobWriter&\)> fill\)")
        self.assertLess(stage.index("!running().load"), stage.index("stagerRef()"))
        stats = body("Helpers/NvsWriter.cpp", r"Stats stats\(\)")
        self.assertLess(stats.index("!running().load"), stats.index("stagerRef()"))


if __name__ == "__main__":
    unittest.main()

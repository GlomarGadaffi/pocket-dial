"""#997: pin the parts of the telephony config's staged write that no host test reaches.

Host tests (TelephonyStaging_test.cpp, ConfigExportImport_test.cpp) play the writer task and
check what TelephonyApiConfig stages, what the writer walk emits and how often a secret is
written. What they cannot see:

  (a) that the secret never enters the snapshot (fillSnapshot / emitSnapshot / writeSnapshot do
      not mention it, and no `sec` key is built on the writer's side),
  (b) the synchronous secret write: the live std::string's c_str() goes straight into
      nvs_set_str, inside a resetguard WriteScope, one open and one commit, and only for slots
      whose pending flag is set; the flag is set only by a changed value or a clear, and cleared
      only by a write that succeeded,
  (c) the order: stage first (a refused stage writes nothing), then the secret,
  (d) that the factory reset's clearAll() is one synchronous write of every key, and that the
      single-producer rule holds (every caller of the table holds RequestsHandler::_mutex),
  (e) the board half: the fourth slot in PSRAM, the sink handing Key::Telephony to its module
      before the pbxcfg string path, the memory budget static_asserts, the boot loader starting
      the writer,
  (f) that docs/API.md says a 200 from the telephony setters means staged.

This checks all of it at the source level.
"""
import os
import re
import unittest

from test_didmap_staging_wiring import SRC, REPO, bodies, body, code, indented_body

NVS_CALLS = ("nvs_commit", "nvs_open", "nvs_set_str", "nvs_set_blob", "nvs_set_u8")
TEL = "SIP/TelephonyApiConfig.cpp"
RH = "SIP/RequestsHandler.cpp"
HTTP = "Helpers/HttpServer.cpp"
WRITER = "Helpers/NvsWriter.cpp"

EMIT = (r"bool TelephonyApiConfig::emitSnapshot\(.*?"
        r"FunctionRef<bool\(const char\* key, const char\* value\)> putStr\)")


class TheSecretIsNeverStaged(unittest.TestCase):
    def test_the_snapshot_builder_does_not_mention_the_secret(self):
        fill = body(TEL, r"void TelephonyApiConfig::fillSnapshot\(nvswriter::BlobWriter& w\) const")
        self.assertNotIn("secret", fill.lower())
        self.assertNotIn('"sec"', fill)
        self.assertIn("w.fail()", fill, "a value longer than its cell is refused, not truncated")
        self.assertNotRegex(fill, r"std::string(?!_view)|std::vector|\bnew\b", "no heap on the stage path")
        for bad in NVS_CALLS:
            self.assertNotIn(bad, fill)

    def test_the_writer_walk_never_builds_a_secret_key(self):
        walk = body(TEL, EMIT)
        self.assertNotIn("secret", walk.lower())
        self.assertNotIn('"sec"', walk)
        self.assertEqual(walk.count("slotKey("), 6, "type, en, url, id, dn, acc (#1073)")
        order = [walk.index('"%s")' % f) for f in ("type", "en", "url", "id", "dn", "acc")]
        self.assertEqual(order, sorted(order), "the keys go out in the old persist() order, minus sec")
        self.assertIn('putU8("active"', walk)
        # the snapshot is checked whole before the first put
        self.assertLess(walk.index("len != kSnapshotLen"), walk.index("putU8("))
        self.assertLess(walk.index("!= '\\0'"), walk.index("putU8("))

    def test_writeSnapshot_sets_the_walk_then_commits_once_and_only_if_all_worked(self):
        b = body(TEL, r"bool TelephonyApiConfig::writeSnapshot\(const char\* blob, size_t len\)")
        self.assertEqual(b.count("nvs_set_u8("), 1, "one call site, inside the walk")
        self.assertEqual(b.count("nvs_set_str("), 1)
        self.assertEqual(b.count("nvs_commit("), 1)
        self.assertEqual(b.count("nvs_open("), 1)
        self.assertEqual(b.count("nvs_close("), 1)
        self.assertRegex(b, r"ok = ok && nvs_commit\(h\) == ESP_OK;")
        self.assertLess(b.index("emitSnapshot(blob, len,"), b.index("nvs_commit("))
        self.assertLess(b.index("nvs_commit("), b.index("nvs_close("))
        self.assertIn("kNvsNamespace", b)
        # it reads the snapshot it was handed (the writer's internal scratch), never the table
        for bad in ("_slots", "_secretPending", "secret", "sec"):
            self.assertNotIn(bad, b)

    def test_the_cell_layout_and_the_slot_cap_come_from_one_place(self):
        hdr = code("SIP/TelephonyApiConfig.hpp")
        for needle in ("kCellLen = kMaxUrlLen + 1",
                       "kSlotSnapshotLen = 2 + 3 * kCellLen + kAcceptCellLen",
                       "kSnapshotLen = kSlots * kSlotSnapshotLen + 1",
                       "kSnapshotCap = kSnapshotLen + 1"):
            self.assertIn(needle, hdr)
        w = code("Helpers/NvsWriter.hpp")
        self.assertIn("kTelephonyCap = TelephonyApiConfig::kSnapshotCap", w)
        self.assertRegex(w, r"kScratchCap = maxOf\(maxOf\(maxOf\(kDevicesCap, kForwardsCap\), kDidMapCap\), kTelephonyCap\)")
        # the memory cost, checked by the compiler: the numbers in the PR body
        self.assertIn('static_assert(sizeof(Slot<kTelephonyCap>) == 1676', w)
        self.assertIn("static_assert(kScratchCap == kForwardsCap", w)


class StageFirstThenTheSecret(unittest.TestCase):
    def test_persist_stages_first_and_a_refusal_writes_nothing(self):
        b = body(TEL, r"std::string TelephonyApiConfig::persist\(\)")
        self.assertIn("nvswriter::stage(", b)
        self.assertIn("nvswriter::Key::Telephony", b)
        for bad in NVS_CALLS + ("std::string blob", "nvs_"):
            self.assertNotIn(bad, b, "persist() runs under _mutex and does no NVS itself: " + bad)
        for r in ("Reset", "TooBig", "NotRunning"):
            self.assertRegex(b, r"case nvswriter::StageResult::" + r + r":\s+return \"Telephony config not persisted")
        last_refusal = b.rindex('return "Telephony config not persisted')
        self.assertLess(last_refusal, b.index("writeSecretsNow()"), "every refusal returns before the secret write")
        self.assertLess(b.index("nvswriter::stage("), b.index("anySecretPending()"))

    def test_the_secret_write_is_conditional_and_bookkept_in_the_shared_code(self):
        b = body(TEL, r"std::string TelephonyApiConfig::persist\(\)")
        self.assertIn("const bool secrets = anySecretPending();", b, "the only gate on writing a secret")
        self.assertIn("secrets ? writeSecretsNow() : std::string()", b, "board: no secret pending, no secret write")
        self.assertRegex(b, r"if \(err\.empty\(\) && secrets\)\s*\{[^}]*_secretPending[^}]*false[^}]*\+\+_secretWrites",
                         "the flags clear and the count moves only after a write that succeeded")

    def test_setSlot_marks_a_secret_pending_only_when_it_changed(self):
        b = body(TEL, r"std::string TelephonyApiConfig::setSlot\(size_t idx, const Slot& s, bool keepSecret, const Acceptance\* accept\)")
        self.assertRegex(b, r"if \(s\.secret != dst\.secret\)\s*\{\s*_secretPending\[idx\] = true;")
        self.assertLess(b.index("_secretPending[idx] = true"), b.index("scrub(dst.secret)"),
                        "compared before the live value is replaced")
        self.assertTrue(b.rstrip().endswith("return persist();"))
        wipe = body(TEL, r"void TelephonyApiConfig::wipeSlot\(size_t idx\)")
        self.assertRegex(wipe, r"if \(!s\.secret\.empty\(\)\)\s*\{\s*_secretPending\[idx\] = true;")
        self.assertLess(wipe.index("_secretPending[idx] = true"), wipe.index("scrub(s.secret)"))

    def test_the_other_setters_stage(self):
        for sig in (r"std::string TelephonyApiConfig::clearSlot\(size_t idx\)",
                    r"std::string TelephonyApiConfig::setActiveSlot\(size_t idx\)"):
            b = body(TEL, sig)
            self.assertTrue(b.rstrip().endswith("return persist();"), sig)
            self.assertNotIn("persistNow", b, sig)

    def test_load_starts_the_writer_and_clears_the_flags_on_both_arms(self):
        loads = bodies(TEL, r"void TelephonyApiConfig::load\(\)")
        self.assertEqual(len(loads), 2)
        for b in loads:
            self.assertIn("nvswriter::start()", b)
            self.assertIn("_secretPending", b)


class TheSynchronousSecretWrite(unittest.TestCase):
    def test_the_board_arm_passes_the_live_string_straight_in_inside_a_reset_scope(self):
        esp, host = bodies(TEL, r"std::string TelephonyApiConfig::writeSecretsNow\(\)")
        self.assertIn("nvs_set_str(h, key, _slots[i].secret.c_str())", esp, "no copy of the secret")
        self.assertEqual(esp.count("nvs_set_str("), 1)
        self.assertEqual(esp.count("nvs_commit("), 1)
        self.assertEqual(esp.count("nvs_open("), 1)
        self.assertEqual(esp.count("nvs_close("), 1)
        self.assertRegex(esp, r"ok = ok && nvs_commit\(h\) == ESP_OK;")
        self.assertIn("if (!_secretPending[i]) continue;", esp, "only the slots whose secret changed")
        self.assertIn("resetguard::WriteScope scope;", esp, "a data write is a resetguard writer")
        self.assertIn("scope.allowed()", esp)
        self.assertLess(esp.index("resetguard::WriteScope scope;"), esp.index("nvs_open("))
        self.assertLess(esp.index("scope.allowed()"), esp.index("nvs_open("))
        for bad in ("std::string", "memcpy", ".assign(", "char buf", "std::vector", "snprintf("):
            self.assertNotIn(bad, esp, "a copy of the secret: " + bad)
        # the host has one file: the secret goes with the table
        self.assertEqual(host.strip(), "return persistNow();")

    def test_persistNow_is_the_factory_resets_erase_and_nothing_else(self):
        src = code(TEL)
        self.assertEqual(len(re.findall(r"std::string TelephonyApiConfig::persistNow\(\)", src)), 2, "one per platform arm")
        self.assertEqual(src.count("persistNow()"), 2 + 1 + 1, "definitions, clearAll(), and the host's writeSecretsNow()")
        clear_all = body(TEL, r"std::string TelephonyApiConfig::clearAll\(\)")
        self.assertIn("const std::string err = persistNow();", clear_all)
        self.assertNotIn("persist()", clear_all)
        self.assertNotIn("clearSlot(", clear_all, "four persists were four writes; a staged one is refused during a reset")
        self.assertNotIn("nvswriter", clear_all)
        esp_now = bodies(TEL, r"std::string TelephonyApiConfig::persistNow\(\)")[0]
        self.assertIn("nvs_set_str(h, key, s.secret.c_str())", esp_now)
        self.assertNotIn("WriteScope", esp_now, "an erase is not gated by the reset guard")


class SingleProducerAndTheCallers(unittest.TestCase):
    def test_every_caller_of_the_table_holds_mutex(self):
        src = code(RH)
        wrappers = re.findall(
            r"RequestsHandler::(setTelephonyConfigSlot|setTelephonyConfigActiveSlot|clearTelephonyConfigSlot|"
            r"clearAllTelephonyConfig)\([^)]*\)\s*\{\s*std::lock_guard<pd::TimedMutex> lock\(_mutex\);\s*"
            r"return _tapiConfig\.(setSlot|activateSlot|clearSlot|clearAll)\(", src)
        self.assertEqual(sorted(wrappers), sorted([
            ("setTelephonyConfigSlot", "setSlot"), ("setTelephonyConfigActiveSlot", "activateSlot"),
            ("clearTelephonyConfigSlot", "clearSlot"), ("clearAllTelephonyConfig", "clearAll")]))
        # the fifth caller is the SBC route, inside its own lock scope
        self.assertEqual(len(re.findall(r"_tapiConfig\.(setSlot|clearSlot|clearAll|setActiveSlot|activateSlot)\(", src)), 6,
                         "a sixth writer of the table would be a second producer for the slot")
        sbc = body(RH, r"std::string RequestsHandler::setSbcMode\(bool enabled, size_t route, const TelephonyApiConfig::Acceptance\* accept\)")
        self.assertRegex(sbc, r"std::lock_guard<pd::TimedMutex> lock\(_mutex\);\s*if \(enabled\)\s*\{\s*"
                              r"err = \(route == _tapiConfig\.activeSlot\(\)\) \? _tapiConfig\.setActiveSlot\(route\)\s*"
                              r": _tapiConfig\.activateSlot\(route, accept\);")
        # and no other file reaches the instance at all
        for root, _, files in os.walk(SRC):
            for name in files:
                if name.endswith((".cpp", ".hpp", ".h")):
                    rel = os.path.relpath(os.path.join(root, name), SRC).replace(os.sep, "/")
                    if rel in (RH, "SIP/RequestsHandler.hpp"):
                        continue
                    self.assertNotIn("_tapiConfig", code(rel), rel)

    def test_the_factory_reset_clears_synchronously_after_the_guard_opens(self):
        reset = body(HTTP, r"void HttpServer::sendApiFactoryReset\(int sock, const std::string& body\)")
        self.assertEqual(reset.count("clearAllTelephonyConfig()"), 1)
        self.assertLess(reset.index("resetguard::begin()"), reset.index("clearAllTelephonyConfig()"),
                        "the reset's erase runs inside the guard, which is why it cannot be staged")

    def test_the_import_can_only_keep_the_secret(self):
        imp = body(HTTP, r"void HttpServer::sendApiConfigImport\(int sock, const std::string& body\)")
        self.assertEqual(len(re.findall(r"setTelephonyConfigSlot\(idx, s, true\)", imp)), 3,
                         "the two passes, and #1073's retry that imports a slot it may not enable disabled")
        self.assertEqual(len(re.findall(r"setTelephonyConfigSlot\(", imp)), 3)
        self.assertNotIn("clearAllTelephonyConfig", imp)
        self.assertNotIn("resetguard::begin", imp, "an import never opens the reset guard: its stages would be refused")


class BoardWiringForTheFourthKey(unittest.TestCase):
    def setUp(self):
        self.src = code(WRITER)
        self.start = body(WRITER, r"void start\(\)")

    def test_the_sink_hands_telephony_to_its_module_before_the_string_path(self):
        sink = indented_body(WRITER, r"bool nvsSink\(Key k, const char\* blob, size_t len\)")
        self.assertRegex(sink, r"if \(k == Key::Telephony\)\s*\{[^}]*TelephonyApiConfig::writeSnapshot\(blob, len\)",
                         "an unconditional (or disabled) dispatch is not a dispatch")
        self.assertLess(sink.index("TelephonyApiConfig::writeSnapshot("), sink.index("nvs_open("),
                        "else the table would be written to pbxcfg under another key")
        self.assertNotIn("tapicfg", self.src, "the namespace lives in TelephonyApiConfig.cpp only")
        names = indented_body(WRITER, r"const char\* nvsKeyName\(Key k\)")
        self.assertIn("case Key::Telephony", names)
        self.assertNotIn("default", names)

    def test_the_fourth_slot_is_psram_at_init_and_freed_on_every_failure_path(self):
        self.assertRegex(self.start, r"s_telephony = allocSlot<Slot<kTelephonyCap>>\(\);")
        self.assertIn("|| s_telephony == nullptr)", self.start)
        free = indented_body(WRITER, r"void freeSlots\(\)")
        self.assertIn("psram::freePreferPsram(s_telephony);", free)
        self.assertIn("s_telephony = nullptr;", free)
        self.assertEqual(self.src.count("allocPreferPsram("), 1, "the one allocation site is allocSlot()")
        refs = indented_body(WRITER, r"std::array<SlotRef, kKeyCount> slotRefs\(\)")
        self.assertIn("refOf(*s_didmap), refOf(*s_telephony)", refs, "index order == Key")
        self.assertIn("refOf(s_didmap), refOf(s_telephony)", refs)
        self.assertRegex(self.src, r"#else\s+Slot<kDevicesCap> s_devices;\s+Slot<kForwardsCap> s_forwards;\s+"
                                   r"Slot<kDidMapCap> s_didmap;\s+Slot<kTelephonyCap> s_telephony;",
                         "the host keeps static slots")
        self.assertRegex(self.src, r"(?m)^	Slot<kScratchCap> s_scratch;", "the scratch stays an internal static")


class DocsSayTheWriteIsStaged(unittest.TestCase):
    def test_the_api_doc_says_a_telephony_200_means_staged(self):
        with open(os.path.join(REPO, "docs", "API.md"), encoding="utf-8") as f:
            api = f.read()
        lines = api.splitlines()
        for start in ("| [`/api/telephony-config/<slot>`](#put-apitelephony-configslot)",
                      "| [`/api/telephony-config/<slot>/activate`]",
                      "| [`/api/telephony-config/<slot>`](#delete-apitelephony-configslot)",
                      "| `/api/sbc-mode` | `PUT`"):
            rows = [l for l in lines if l.startswith(start)]
            self.assertEqual(len(rows), 1, start)
            self.assertIn("staged", rows[0], start)
            self.assertIn("#997", rows[0], start)
        self.assertIn("`forwards`, `didMappings` and `telephonyConfig`, `applied` means accepted and staged", api)
        self.assertIn("An import never carries or changes a telephony client secret", api)
        self.assertIn("**The client secret is not staged.**", api)


if __name__ == "__main__":
    unittest.main()

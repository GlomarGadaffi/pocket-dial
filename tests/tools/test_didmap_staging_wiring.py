"""#986 slice 4: pin the parts of the DID table's staged write that no host test reaches.

Host tests (DidMapStaging_test.cpp, ConfigExportImport_test.cpp) play the writer task
and check what DidMapping stages and what the writer walk emits. What they cannot see:

  (a) that the HTTP setters and the import no longer touch NVS under
      RequestsHandler::_mutex, and that the ONE synchronous clear left is the factory
      reset's (a staged clear there would be refused after resetguard::begin() and the
      reset would report the PII table erased while flash still held it),
  (b) the single-producer rule for the Key::DidMap slot (every writer of the table holds
      _mutex),
  (c) the board half: the third slot in PSRAM, the sink handing DidMap to DidMapping
      before the string path (whose key name would be "forwards"), and the nvs_* calls
      writeSnapshot() makes: every slot's two sets, one commit, only if all sets worked.

This checks all of it at the source level.
"""
import os
import re
import unittest

REPO = os.path.join(os.path.dirname(__file__), "..", "..")
SRC = os.path.join(REPO, "src")


def strip_comments(text):
    """Remove // and /* */ comments, leaving string, char and raw-string literals alone.

    A regex pass is not enough here: HttpServer.cpp has "http://..." and "image/*" inside
    literals, and a comment stripper that reads those as comments eats whole functions."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif c == "R" and text.startswith('R"', i) and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            k = text.find("(", i + 2)
            end = ")" + text[i + 2:k] + '"'
            j = text.find(end, k)
            j = n if j < 0 else j + len(end)
            out.append(text[i:j])
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def code(path):
    """Source with comments removed, so a comment can't satisfy a pin."""
    with open(os.path.join(SRC, path), encoding="utf-8") as f:
        return strip_comments(f.read())


def bodies(path, signature):
    """Every function body matching `signature` (a definition outside any namespace)."""
    found = [m.group(1) for m in re.finditer(signature + r"\s*\{(.*?)\n\}", code(path), re.S)]
    assert found, signature + " not found in " + path
    return found


def body(path, signature):
    return bodies(path, signature)[0]


def indented_body(path, signature):
    """Body of a function nested one tab deep (inside a namespace): up to its closing tab-brace."""
    m = re.search(signature + r"\s*\{(.*?)\n\t\}", code(path), re.S)
    assert m, signature + " not found in " + path
    return m.group(1)


NVS_CALLS = ("nvs_commit", "nvs_open", "nvs_set_str", "nvs_set_blob", "nvs_set_u8")
DID = "SIP/DidMapping.cpp"
RH = "SIP/RequestsHandler.cpp"
HTTP = "Helpers/HttpServer.cpp"
WRITER = "Helpers/NvsWriter.cpp"


class SettersStageAndTheResetClearStaysSynchronous(unittest.TestCase):
    def test_persist_stages_and_never_touches_nvs(self):
        b = body(DID, r"std::string DidMapping::persist\(\)")
        self.assertIn("nvswriter::stage(", b)
        self.assertIn("nvswriter::Key::DidMap", b)
        for bad in NVS_CALLS + ("std::string blob",):
            self.assertNotIn(bad, b, "persist() runs under _mutex: " + bad)
        # every refusal is an error the HTTP setter can report; none is a quiet ""
        for r in ("Reset", "TooBig", "NotRunning"):
            self.assertRegex(b, r"case nvswriter::StageResult::" + r + r":\s+return \"DID table not persisted")
        # the host has no writer task: its file is written only after the stage was accepted
        host = b.index("#if !(defined(ESP_PLATFORM)")
        self.assertGreater(b.index("persistNow()"), host, "persistNow() belongs to the host arm only")
        self.assertLess(b.index("nvswriter::stage("), host)

    def test_the_setters_stage_and_clearAll_alone_writes_now(self):
        for sig in (r"std::string DidMapping::setMapping\(const std::string& did, const std::string& extension\)",
                    r"std::string DidMapping::removeMapping\(const std::string& did\)",
                    r"std::string DidMapping::clearAllStaged\(\)"):
            b = body(DID, sig)
            self.assertIn("persist()", b, sig)
            self.assertNotIn("persistNow()", b, sig)
        # the update-in-place and the new-row paths both end in persist(): no early exit skips the stage
        self.assertEqual(body(DID, r"std::string DidMapping::setMapping\(const std::string& did, const std::string& extension\)")
                         .count("return persist();"), 2)
        clear_all = body(DID, r"std::string DidMapping::clearAll\(\)")
        self.assertIn("persistNow()", clear_all)
        self.assertNotIn("persist()", clear_all)
        self.assertNotIn("Staged", clear_all)

    def test_persistNow_has_exactly_two_callers_clearAll_and_the_host_arm(self):
        src = code(DID)
        self.assertEqual(len(re.findall(r"return persistNow\(\);", src)), 2)
        self.assertEqual(len(re.findall(r"std::string DidMapping::persistNow\(\)", src)), 2, "one per platform arm")
        self.assertEqual(src.count("persistNow()"), 2 + 2, "calls plus definitions")

    def test_the_factory_reset_clears_synchronously_and_the_import_stages(self):
        reset = body(HTTP, r"void HttpServer::sendApiFactoryReset\(int sock, const std::string& body\)")
        self.assertEqual(reset.count("clearAllDidMappings()"), 1)
        self.assertNotIn("clearAllDidMappingsStaged", reset)
        self.assertLess(reset.index("resetguard::begin()"), reset.index("clearAllDidMappings()"),
                        "the reset's erase runs inside the guard, which is why it cannot be staged")
        imp = body(HTTP, r"void HttpServer::sendApiConfigImport\(int sock, const std::string& body\)")
        self.assertEqual(imp.count("clearAllDidMappingsStaged()"), 1)
        self.assertNotIn("clearAllDidMappings()", imp)
        self.assertNotIn("resetguard::begin", imp, "an import never opens the reset guard: its stages would be refused")
        # nothing else in the tree clears the table synchronously
        files_with = []
        for root, _, files in os.walk(SRC):
            for name in files:
                if name.endswith((".cpp", ".hpp", ".h")):
                    rel = os.path.relpath(os.path.join(root, name), SRC).replace(os.sep, "/")
                    files_with += [rel] * len(re.findall(r"\bclearAllDidMappings\(\)", code(rel)))
        self.assertEqual(sorted(files_with), sorted([
            "SIP/RequestsHandler.hpp", "SIP/RequestsHandler.cpp", "Helpers/HttpServer.cpp"]),
            "the declaration, the definition, and the factory reset's one call")

    def test_single_producer_every_writer_of_the_table_holds_mutex(self):
        src = code(RH)
        wrappers = re.findall(
            r"RequestsHandler::(setDidMapping|removeDidMapping|clearAllDidMappings|clearAllDidMappingsStaged)"
            r"\([^)]*\)\s*\{\s*std::lock_guard<pd::TimedMutex> lock\(_mutex\);\s*"
            r"return _didMapping\.(setMapping|removeMapping|clearAll|clearAllStaged)\(", src)
        self.assertEqual(sorted(wrappers), sorted([
            ("setDidMapping", "setMapping"), ("removeDidMapping", "removeMapping"),
            ("clearAllDidMappings", "clearAll"), ("clearAllDidMappingsStaged", "clearAllStaged")]))
        self.assertEqual(len(re.findall(r"_didMapping\.(setMapping|removeMapping|clearAll|clearAllStaged)\(", src)), 4,
                         "a fifth writer of the table would be a second producer for the slot")
        # and no other file reaches the instance at all
        for root, _, files in os.walk(SRC):
            for name in files:
                if name.endswith((".cpp", ".hpp", ".h")):
                    rel = os.path.relpath(os.path.join(root, name), SRC).replace(os.sep, "/")
                    if rel in (RH, "SIP/RequestsHandler.hpp"):
                        continue
                    self.assertNotIn("_didMapping", code(rel), rel)

    def test_load_starts_the_writer_on_both_arms(self):
        loads = bodies(DID, r"void DidMapping::load\(\)")
        self.assertEqual(len(loads), 2)
        for b in loads:
            self.assertIn("nvswriter::start()", b)


class SnapshotLayoutAndTheWriterHalf(unittest.TestCase):
    def test_one_definition_of_the_stored_form(self):
        src = code(DID)
        self.assertEqual(len(re.findall(r"bool emitSlots\(", src)), 1)
        emit = indented_body(DID, r"bool emitSlots\(ValueAt&& valueAt, Put&& put\)")
        self.assertLess(emit.index('"did"'), emit.index('"ext"'), "m<i>did is written before m<i>ext, as persist() always did")
        self.assertIn("return false", emit, "a failed put ends the walk")
        for bad in NVS_CALLS + ("nvs_",):
            self.assertNotIn(bad, emit)
        # the snapshot walk and the table write share it; neither spells the keys itself
        self.assertEqual(src.count("emitSlots("), 1 + 2 + 1, "definition, snapshot walk, ESP persistNow, host persistNow")
        self.assertEqual(src.count("slotKey("), 1 + 2 + 2, "definition, emitSlots' two, and load()'s two reads")

    def test_the_snapshot_is_checked_whole_before_the_first_put(self):
        b = body(DID, r"bool DidMapping::emitSnapshot\(const char\* blob, size_t len,\s*FunctionRef<bool\(const char\* key, const char\* value\)> put\)")
        self.assertIn("len != kSnapshotLen", b)
        self.assertIn("kMaxFieldLen", b)
        self.assertLess(b.index("len != kSnapshotLen"), b.index("emitSlots("))
        self.assertLess(b.index("kMaxFieldLen"), b.index("emitSlots("))

    def test_the_snapshot_is_built_in_the_slot_one_cell_per_field_and_never_cut_short(self):
        b = body(DID, r"void DidMapping::fillSnapshot\(nvswriter::BlobWriter& w\) const")
        self.assertIn("w.fail()", b, "a field longer than its cell is refused, not truncated")
        self.assertIn("c_str()", b, "a value is its C string, what nvs_set_str(value.c_str()) stored")
        self.assertNotRegex(b, r"std::string(?!_view)|std::vector|\bnew\b", "no heap on the stage path")
        for bad in NVS_CALLS:
            self.assertNotIn(bad, b)

    def test_writeSnapshot_sets_every_slot_then_commits_once_and_only_if_all_worked(self):
        b = body(DID, r"bool DidMapping::writeSnapshot\(const char\* blob, size_t len\)")
        self.assertEqual(b.count("nvs_set_str("), 1, "one call site, inside the walk")
        self.assertEqual(b.count("nvs_commit("), 1)
        self.assertEqual(b.count("nvs_open("), 1)
        self.assertEqual(b.count("nvs_close("), 1)
        self.assertIn("emitSnapshot(blob, len,", b)
        self.assertRegex(b, r"ok = ok && nvs_commit\(h\) == ESP_OK;")
        self.assertLess(b.index("emitSnapshot("), b.index("nvs_commit("))
        self.assertLess(b.index("nvs_commit("), b.index("nvs_close("))
        self.assertIn("kNvsNamespace", b)
        # it reads the snapshot it was handed (the writer's internal scratch), never the table
        for bad in ("_entries", "_count", "s_didmap"):
            self.assertNotIn(bad, b)

    def test_the_synchronous_write_uses_the_same_walk_and_namespace(self):
        b = bodies(DID, r"std::string DidMapping::persistNow\(\)")[0]
        self.assertIn("kNvsNamespace", b)
        self.assertIn("emitSlots(", b)
        self.assertEqual(b.count("nvs_set_str("), 1)
        self.assertRegex(b, r"ok = ok && nvs_commit\(h\) == ESP_OK;")
        self.assertEqual(code(DID).count('"didmap"'), 1, "the namespace is spelled once, in this file")

    def test_the_cell_layout_and_the_slot_cap_come_from_one_place(self):
        hdr = code("SIP/DidMapping.hpp")
        self.assertIn("kSlotCellLen = kMaxFieldLen + 1", hdr)
        self.assertIn("kSnapshotLen = 2 * kMaxMappings * kSlotCellLen", hdr)
        self.assertIn("kSnapshotCap = kSnapshotLen + 1", hdr)
        w = code("Helpers/NvsWriter.hpp")
        self.assertIn("kDidMapCap = DidMapping::kSnapshotCap", w)
        self.assertRegex(w, r"kScratchCap = maxOf\(maxOf\(maxOf\(kDevicesCap, kForwardsCap\), kDidMapCap\), kTelephonyCap\)")


class BoardWiringForTheThirdKey(unittest.TestCase):
    def setUp(self):
        self.src = code(WRITER)
        self.start = body(WRITER, r"void start\(\)")

    def test_the_sink_hands_didmap_to_didmapping_before_the_string_path(self):
        sink = indented_body(WRITER, r"bool nvsSink\(Key k, const char\* blob, size_t len\)")
        self.assertRegex(sink, r"if \(k == Key::DidMap\)\s*\{[^}]*DidMapping::writeSnapshot\(blob, len\)",
                         "an unconditional (or disabled) dispatch is not a dispatch")
        self.assertIn("DidMapping::writeSnapshot(blob, len)", sink)
        self.assertLess(sink.index("DidMapping::writeSnapshot("), sink.index("nvs_open("),
                        "else the DID bytes would be written to pbxcfg under another key")
        self.assertLess(sink.index("k == Key::DidMap"), sink.index("nvs_open("))
        self.assertNotIn("didmap", self.src.replace("s_didmap", "").replace("DidMap", ""),
                         "the namespace lives in DidMapping.cpp only")

    def test_the_key_name_switch_names_every_key_without_a_default(self):
        names = indented_body(WRITER, r"const char\* nvsKeyName\(Key k\)")
        self.assertNotIn("default", names, "a new Key must be a compile warning here, not a quiet 'forwards'")
        for k in ("Devices", "Forwards", "DidMap", "Telephony"):
            self.assertIn("case Key::" + k, names)

    def test_the_third_slot_is_psram_at_init_and_freed_on_every_failure_path(self):
        self.assertRegex(self.start, r"s_didmap = allocSlot<Slot<kDidMapCap>>\(\);")
        self.assertIn("if (s_devices == nullptr || s_forwards == nullptr || s_didmap == nullptr || s_telephony == nullptr)", self.start)
        self.assertEqual(self.src.count("allocPreferPsram("), 1, "the one allocation site is allocSlot()")
        free = indented_body(WRITER, r"void freeSlots\(\)")
        self.assertIn("psram::freePreferPsram(s_didmap);", free)
        self.assertIn("s_didmap = nullptr;", free)
        self.assertRegex(self.src, r"#else\s+Slot<kDevicesCap> s_devices;\s+Slot<kForwardsCap> s_forwards;\s+Slot<kDidMapCap> s_didmap;",
                         "the host keeps static slots")
        refs = indented_body(WRITER, r"std::array<SlotRef, kKeyCount> slotRefs\(\)")
        self.assertIn("refOf(*s_devices), refOf(*s_forwards), refOf(*s_didmap)", refs, "index order == Key")
        self.assertIn("refOf(s_devices), refOf(s_forwards), refOf(s_didmap)", refs)

    def test_the_writer_scratch_stays_internal_and_the_task_is_unchanged(self):
        self.assertRegex(self.src, r"(?m)^	Slot<kScratchCap> s_scratch;")
        self.assertRegex(self.src, r'xTaskCreatePinnedToCore\(nvsWriterTask, "nvs_writer", 6144, nullptr, 1, &handle, 0\)')
        self.assertEqual(len(re.findall(r"xTaskCreate\w*\(", self.src)), 1)

    def test_the_third_queue_is_made_like_the_others(self):
        self.assertIn("for (size_t i = 0; i < kKeyCount; ++i)", self.start)
        self.assertIn("refs[i].itemBytes", self.start)


class DocsSayTheWriteIsStaged(unittest.TestCase):
    def test_the_api_doc_says_a_did_200_means_staged(self):
        with open(os.path.join(REPO, "docs", "API.md"), encoding="utf-8") as f:
            api = f.read()
        rows = [l for l in api.splitlines()
                if l.startswith("| [`/api/did-mapping`]") and ("`PUT`" in l or "`DELETE`" in l)]
        self.assertEqual(len(rows), 2, "the PUT and DELETE rows")
        for l in rows:
            self.assertIn("staged", l)
            self.assertIn("#986", l)
        self.assertIn("`didMappings`", api, "the import note names the DID table")


if __name__ == "__main__":
    unittest.main()

"""Self-test for tools/ci/task_stack_gate.py (#457) on fixture .ci inputs.

The fixture graph is Xtensa-shaped by hand; no compiler runs here.
"""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

GATE = os.path.join(os.path.dirname(__file__), "..", "..", "tools", "ci", "task_stack_gate.py")
sys.path.insert(0, os.path.dirname(GATE))
import task_stack_gate as g  # noqa: E402


def node(title, name, size):
    return (f'node: {{ title: "{title}" label: "{name}\\n/w/src/SIP/X.cpp:1:1\\n'
            f'{size} bytes (static)\\n0 dynamic objects" }}\n')


def edge(a, b):
    return f'edge: {{ sourcename: "{a}" targetname: "{b}" }}\n'


# Labels start with the return type, as GCC writes them ("void f(void*)", #457).
# small_task -> leaf (200 + 300 = 500 B).
# big_task -> mid -> GenerateID (400 + 600 + 900 = 1900 B), with a mid <-> helper
# cycle whose cut must not be cached. The mangled title is the RequestsHandler
# shape #457 names; matching goes by the demangled label.
CI = (node("small_task", "void small_task(void*)", 200) + node("leaf", "void leaf()", 300)
      + node("big_task", "void big_task(void*)", 400) + node("mid", "void mid()", 600)
      + node("helper", "void helper()", 100)
      + node("_ZN15RequestsHandler16buildOptionsPingEv", "void RequestsHandler::buildOptionsPing()", 900)
      + edge("small_task", "leaf") + edge("big_task", "mid") + edge("mid", "helper")
      + edge("helper", "mid") + edge("mid", "_ZN15RequestsHandler16buildOptionsPingEv"))


class Gate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.ci = os.path.join(d, "ci")
        os.makedirs(self.ci)
        open(os.path.join(self.ci, "x.ci"), "w").write(CI)
        os.makedirs(os.path.join(d, "src", "SIP"))
        os.makedirs(os.path.join(d, "main"))
        open(os.path.join(d, "src", "SIP", "X.cpp"), "w").write(
            'xTaskCreate(small_task, "small", 1024, 0, 1, 0);\n'
            'xTaskCreatePinnedToCore(big_task, "big", 2048, 0, 1, 0, 0);\n'
            '// xTaskCreate(commented_out, ...) is not a site\n')
        self.table = {"margin_bytes": 512, "frame_ceiling_bytes": 1024, "frame_allowlist": {},
                      "tasks": [
                          {"name": "small", "entry": r"\bsmall_task\(", "bytes": 1024, "file": "src/SIP/X.cpp", "line": 1},
                          {"name": "big", "entry": r"\bbig_task\(", "bytes": 4096, "file": "src/SIP/X.cpp", "line": 2}]}

    def tearDown(self):
        self.tmp.cleanup()

    def run_gate(self, main="main/esp_main_eth.cpp", features=()):
        p = os.path.join(self.tmp.name, "t.json")
        json.dump(self.table, open(p, "w"))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = g.run(self.ci, p, self.tmp.name, main, features)
        return rc, out.getvalue()

    def test_under_budget_passes_and_names_the_chain(self):
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("ok   big: 1900 B", out)          # cycle cut, not double-counted
        self.assertIn("RequestsHandler::buildOptionsPing()", out)
        self.assertIn("ok   small: 500 B", out)

    def test_over_budget_fails(self):
        self.table["tasks"][1]["bytes"] = 2048          # 1900 + 512 > 2048
        rc, out = self.run_gate()
        self.assertEqual(rc, 1)
        self.assertIn("FAIL big: 1900 B + 512 margin > 2048 B", out)

    def test_task_missing_from_table_fails(self):
        del self.table["tasks"][0]
        rc, out = self.run_gate()
        self.assertEqual(rc, 1)
        self.assertIn("FAIL table: src/SIP/X.cpp has 2 task-creation site(s), task_stacks.json lists 1", out)

    def test_entry_missing_from_graph_fails(self):
        self.table["tasks"][0]["entry"] = r"\brenamed_task\("
        rc, out = self.run_gate()
        self.assertEqual(rc, 1)
        self.assertIn("not in call graph", out)

    def test_frame_over_ceiling_fails_unless_allowlisted(self):
        self.table["frame_ceiling_bytes"] = 800
        rc, out = self.run_gate()
        self.assertEqual(rc, 1)
        self.assertIn("FAIL frame: 900 B > 800 B", out)
        self.table["frame_allowlist"] = {"RequestsHandler::buildOptionsPing": "fixture reason"}
        self.assertEqual(self.run_gate()[0], 0)

    def add_ci(self, text):
        open(os.path.join(self.ci, "x.ci"), "a").write(text)

    def test_std_thread_site_without_a_row_fails(self):
        open(os.path.join(self.tmp.name, "src", "SIP", "X.cpp"), "a").write(
            "_t = std::thread(&X::loop, this);\n"
            "xTaskCreateStaticPinnedToCore(f, \"s\", 1024, 0, 1, stk, &tcb, 0);\n")
        rc, out = self.run_gate()
        self.assertEqual(rc, 1)
        self.assertIn("src/SIP/X.cpp has 4 task-creation site(s), task_stacks.json lists 2", out)

    def test_project_node_without_frame_data_fails(self):
        # A partial --ci-dir: leaf's TU is missing, only the call edge remains.
        self.add_ci('node: { title: "orphan" label: "orphan()\\n/w/src/SIP/Y.cpp:1:1" }\n'
                    + edge("leaf", "orphan"))
        rc, out = self.run_gate()
        self.assertEqual(rc, 1)
        self.assertIn("FAIL frame: project function with no frame data", out)

    def test_library_callee_needs_a_default_or_allowlist(self):
        self.add_ci(edge("leaf", "snprintf"))
        rc, out = self.run_gate()
        self.assertEqual(rc, 1)
        self.assertIn("FAIL frame: library callee with no frame data", out)
        self.table["library_defaults"] = {r"^v?(s|sn|f|as)?printf\b": 2048}
        rc, out = self.run_gate()
        self.assertEqual(rc, 1)                          # 500 + 2048 + 512 > 1024
        self.assertIn("FAIL small: 2548 B", out)
        self.table["tasks"][0]["bytes"] = 4096
        self.assertEqual(self.run_gate()[0], 0)

    def test_dynamic_frame_fails_unless_allowlisted(self):
        self.add_ci('node: { title: "vla" label: "vla()\\n/w/src/SIP/X.cpp:9:1\\n'
                    '64 bytes (dynamic)" }\n' + edge("leaf", "vla"))
        rc, out = self.run_gate()
        self.assertEqual(rc, 1)
        self.assertIn("FAIL frame: dynamic frame, no allowlist entry: vla()", out)
        self.table["frame_allowlist"] = {"vla()": "fixture reason"}
        self.table["tasks"][0]["bytes"] = 2048          # 564 + 512 now fits
        self.assertEqual(self.run_gate()[0], 0)

    def test_report_is_identical_across_hash_seeds(self):
        p = os.path.join(self.tmp.name, "t.json")
        json.dump(self.table, open(p, "w"))
        outs = set()
        for seed in ("0", "1", "12345"):
            r = subprocess.run([sys.executable, GATE, "--ci-dir", self.ci, "--table", p,
                                "--src-root", self.tmp.name], capture_output=True, text=True,
                               env=dict(os.environ, PYTHONHASHSEED=seed))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            outs.add(r.stdout)
        self.assertEqual(len(outs), 1)

    def test_checked_in_table_matches_the_source_tree(self):
        # Fails closed on a new xTaskCreate/createTaskPreferPsram site nobody budgeted.
        table = json.load(open(os.path.join(os.path.dirname(GATE), "task_stacks.json")))
        want = {}
        for t in table["tasks"]:
            want[t["file"]] = want.get(t["file"], 0) + 1
        self.assertEqual(want, g.count_sites(g.REPO))

    def test_nested_ci_tree_is_walked(self):
        # IDF writes .ci files under build/esp-idf/<component>/CMakeFiles/...
        nested = os.path.join(self.ci, "esp-idf", "main", "CMakeFiles", "__idf_main.dir")
        os.makedirs(nested)
        os.replace(os.path.join(self.ci, "x.ci"), os.path.join(nested, "x.ci"))
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("ok   big: 1900 B", out)

    def test_duplicate_title_charges_the_worst_frame(self):
        # A header-defined function has a frame in each TU that emits it. a/y.ci
        # sorts before x.ci, so last-wins would charge leaf 300 B, not 700 B.
        os.makedirs(os.path.join(self.ci, "a"))
        open(os.path.join(self.ci, "a", "y.ci"), "w").write(node("leaf", "void leaf()", 700))
        rc, out = self.run_gate()
        self.assertIn("FAIL small: 900 B", out)
        self.assertEqual(rc, 1)
        # Size and kind are each kept at their worst: a smaller dynamic frame in
        # one TU neither lowers leaf's 300 B nor loses the dynamic flag.
        open(os.path.join(self.ci, "a", "y.ci"), "w").write(
            node("leaf", "void leaf()", 100).replace("(static)", "(dynamic)"))
        rc, out = self.run_gate()
        self.assertIn("ok   small: 500 B", out)
        self.assertIn("FAIL frame: dynamic frame, no allowlist entry: void leaf()", out)

    def test_variant_only_row_is_skipped_on_other_images(self):
        open(os.path.join(self.tmp.name, "src", "SIP", "X.cpp"), "a").write(
            'xTaskCreate(dns_task, "dns", 4096, 0, 1, 0);\n')
        self.table["tasks"].append({"name": "dns", "entry": r"\bdns_task\(", "bytes": 4096,
                                    "file": "src/SIP/X.cpp", "line": 3,
                                    "variants": ["main/esp_main_display.cpp"]})
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        rc, out = self.run_gate(main="main/esp_main_display.cpp")   # walked on its own image
        self.assertEqual(rc, 1)
        self.assertIn("FAIL dns: entry '\\bdns_task\\(' not in call graph", out)

    def test_only_entry_is_skipped_unless_its_build_feature_is_given(self):
        # heapProbeTask exists only under CONFIG_HEAP_TRACING; a shipping .ci has no such node.
        self.table["tasks"][1]["only"] = "heap_trace"
        self.table["tasks"][1]["entry"] = r"\bheap_trace_only_task\("   # not in this graph
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("skip big: only in a 'heap_trace' build", out)
        rc, out = self.run_gate(features=("heap_trace",))
        self.assertEqual(rc, 1, "given --with heap_trace, the entry must be found (fails closed)")
        self.assertIn("FAIL big: entry", out)

    def test_checked_in_heap_probe_is_gated_on_heap_trace(self):
        table = json.load(open(os.path.join(os.path.dirname(GATE), "task_stacks.json")))
        probe = [t for t in table["tasks"] if t["file"] == "main/HeapLeakProbe.cpp"]
        self.assertEqual([t.get("only") for t in probe], ["heap_trace"])

    def test_checked_in_entries_match_gcc_labels(self):
        # A GCC .ci label starts with the return type, so ^name never matches.
        table = json.load(open(os.path.join(os.path.dirname(GATE), "task_stacks.json")))
        entry = {t["name"]: t["entry"] for t in table["tasks"]}
        for name, label in (("http_dashboard", "void http_server_task(void*)"),
                            ("sip_server", "void sip_server_task(void*)"),
                            ("log_drain", "void log_drain_task(void*)"),
                            ("heap_probe", "void heapProbeTask(void*)")):
            self.assertRegex(label, entry[name])
        self.assertEqual([t["entry"] for t in table["tasks"] if (t["entry"] or "").startswith("^")], [])

    def test_checked_in_allowlist_covers_the_measured_frames(self):
        # Project frames over the ceiling on the Xtensa eth image (#457, #685 @ ebdc919).
        table = json.load(open(os.path.join(os.path.dirname(GATE), "task_stacks.json")))
        big = [("sdp::Verdict sdp::parse(std::string_view, Session&)", 3488),
               ("SmtpDialogue::SendResult SmtpDialogue::run(Transport&, const Config&, const Message&)", 3408),
               ("void UdpServer::receiveLoop()", 2176),
               ("virtual size_t vmarchive::{anonymous}::FatFsSource::listMessages(const char*, "
                "vmarchive::MessageInfo*, size_t) const", 1888),
               ("void RequestsHandler::loadVoicemailGreeting()", 1296),
               ("bool SipTrunk::handleResponse(const std::shared_ptr<SipMessage>&)", 1280),
               ("bool GoogleServiceAuth::signRs256(const std::string&, const std::string&, "
                "std::string&, std::string&)", 1232),
               ("bool SipTrunk::handleBye(const std::shared_ptr<SipMessage>&)", 1184),
               ("virtual bool TelephonyAnchorClient::writeAudio(std::string_view, const int16_t*, size_t)", 1120),
               ("bool HoldMusic::loadClip(const std::string&)", 1088),
               ("void RequestsHandler::onRefer(std::shared_ptr<SipMessage>)", 1056)]
        open(os.path.join(self.ci, "x.ci"), "w").write("".join(node(f"f{i}", n, b) for i, (n, b) in enumerate(big)))
        open(os.path.join(self.tmp.name, "src", "SIP", "X.cpp"), "w").write("")
        self.table = {"margin_bytes": 512, "frame_ceiling_bytes": table["frame_ceiling_bytes"],
                      "frame_allowlist": table["frame_allowlist"], "tasks": []}
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertTrue(all(isinstance(r, str) and r.strip() for r in table["frame_allowlist"].values()))
        self.table["frame_allowlist"] = {}                  # positive control
        rc, out = self.run_gate()
        self.assertEqual(out.count("FAIL frame:"), len(big), out)


if __name__ == "__main__":
    unittest.main()

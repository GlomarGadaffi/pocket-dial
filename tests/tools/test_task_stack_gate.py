"""Self-test for tools/ci/task_stack_gate.py (#457) on fixture .ci inputs.

The fixture graph is Xtensa-shaped by hand; no compiler runs here. Project
locations are written under @ROOT@, which setUp replaces with the fixture
checkout, because the gate tells project code from IDF/toolchain code by that
path (GCC writes the absolute source path into every label).
"""
import contextlib
import io
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import unittest

GATE = os.path.join(os.path.dirname(__file__), "..", "..", "tools", "ci", "task_stack_gate.py")
sys.path.insert(0, os.path.dirname(GATE))
import task_stack_gate as g  # noqa: E402


def node(title, name, size, loc="@ROOT@/src/SIP/X.cpp:1:1", kind="static"):
    return (f'node: {{ title: "{title}" label: "{name}\\n{loc}\\n'
            f'{size} bytes ({kind})\\n0 dynamic objects" }}\n')


def bare(title, name, loc="@ROOT@/src/SIP/X.cpp:7:1"):
    """A node GCC wrote with no stack-usage line: a declaration, or an alias."""
    return f'node: {{ title: "{title}" label: "{name}\\n{loc}" }}\n'


def edge(a, b):
    return f'edge: {{ sourcename: "{a}" targetname: "{b}" }}\n'


# Labels start with the return type, as GCC writes them ("void f(void*)", #457).
# small_task -> leaf (200 + 300 = 500 B).
# big_task -> mid -> GenerateID (400 + 600 + 900 = 1900 B), with a mid -> helper
# leaf beside it. The mangled title is the RequestsHandler shape #457 names;
# matching goes by the demangled label. The tests that need a cycle add the
# helper -> mid back edge (CYCLE below).
CI = (node("small_task", "void small_task(void*)", 200) + node("leaf", "void leaf()", 300)
      + node("big_task", "void big_task(void*)", 400) + node("mid", "void mid()", 600)
      + node("helper", "void helper()", 100)
      + node("_ZN15RequestsHandler16buildOptionsPingEv", "void RequestsHandler::buildOptionsPing()", 900)
      + edge("small_task", "leaf") + edge("big_task", "mid") + edge("mid", "helper")
      + edge("mid", "_ZN15RequestsHandler16buildOptionsPingEv"))
CYCLE = edge("helper", "mid")            # mid <-> helper: 600 + 100 B a round
BOUND = {"depth": 3, "reason": "fixture: bounded by the test"}

# Where IDF and the toolchain keep their sources. lwip's headers sit under .../lwip/src/,
# which the old "/src/ in the path" test took for this repo's src/ (#457).
LWIP_H = "/idf/components/lwip/lwip/src/include/lwip/sockets.h:1:1"
LWIP_C = "/idf/components/lwip/lwip/src/api/sockets.c:1:1"
STL_VECTOR_H = "/tc/include/c++/15.2.0/bits/stl_vector.h:1:1"


class Gate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.ci = os.path.join(d, "ci")
        os.makedirs(self.ci)
        self.put(os.path.join(self.ci, "x.ci"), CI)
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

    def put(self, path, text, mode="w"):
        with open(path, mode) as f:
            f.write(text.replace("@ROOT@", self.tmp.name))

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
        self.assertIn("ok   big: 1900 B", out)
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
        self.put(os.path.join(self.ci, "x.ci"), text, "a")

    def test_std_thread_site_without_a_row_fails(self):
        open(os.path.join(self.tmp.name, "src", "SIP", "X.cpp"), "a").write(
            "_t = std::thread(&X::loop, this);\n"
            "xTaskCreateStaticPinnedToCore(f, \"s\", 1024, 0, 1, stk, &tcb, 0);\n")
        rc, out = self.run_gate()
        self.assertEqual(rc, 1)
        self.assertIn("src/SIP/X.cpp has 4 task-creation site(s), task_stacks.json lists 2", out)

    def test_project_node_without_frame_data_fails(self):
        # A partial --ci-dir: leaf's TU is missing, only the call edge remains.
        self.add_ci(bare("orphan", "orphan()", "@ROOT@/src/SIP/Y.cpp:1:1") + edge("leaf", "orphan"))
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
        self.add_ci(node("vla", "vla()", 64, "@ROOT@/src/SIP/X.cpp:9:1", "dynamic") + edge("leaf", "vla"))
        rc, out = self.run_gate()
        self.assertEqual(rc, 1)
        self.assertIn("FAIL frame: dynamic frame, no allowlist entry: vla()", out)
        self.table["frame_allowlist"] = {"vla()": "fixture reason"}
        self.table["tasks"][0]["bytes"] = 2048          # 564 + 512 now fits
        self.assertEqual(self.run_gate()[0], 0)

    def test_report_is_identical_across_hash_seeds(self):
        self.add_ci(CYCLE)                               # a bounded cycle, so SCC order is exercised too
        self.table["recursion_allowlist"] = {"void mid()": BOUND}
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
        self.put(os.path.join(self.ci, "a", "y.ci"), node("leaf", "void leaf()", 700))
        rc, out = self.run_gate()
        self.assertIn("FAIL small: 900 B", out)
        self.assertEqual(rc, 1)
        # Size and kind are each kept at their worst: a smaller dynamic frame in
        # one TU neither lowers leaf's 300 B nor loses the dynamic flag.
        self.put(os.path.join(self.ci, "a", "y.ci"), node("leaf", "void leaf()", 100, kind="dynamic"))
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
        self.put(os.path.join(self.ci, "x.ci"), "".join(node(f"f{i}", n, b) for i, (n, b) in enumerate(big)))
        open(os.path.join(self.tmp.name, "src", "SIP", "X.cpp"), "w").write("")
        self.table = {"margin_bytes": 512, "frame_ceiling_bytes": table["frame_ceiling_bytes"],
                      "frame_allowlist": table["frame_allowlist"], "tasks": []}
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertTrue(all(isinstance(r, str) and r.strip() for r in table["frame_allowlist"].values()))
        self.table["frame_allowlist"] = {}                  # positive control
        rc, out = self.run_gate()
        self.assertEqual(out.count("FAIL frame:"), len(big), out)

    # --- GCC's C1/C2 and D1/D2 aliases (#457) -------------------------------------------
    # GCC emits one body for the complete- and base-object constructor (C1/C2) or
    # destructor (D1/D2) and reports the C1/D1 name as a node with no stack-usage line
    # and an edge to the body. On main's real Xtensa run, 409 of the 854 callees the
    # gate called "no frame data" were these.

    def test_ctor_alias_is_a_pass_through_to_its_body(self):
        self.add_ci(bare("_ZN3FooC1Ev", "Foo::Foo()") + node("_ZN3FooC2Ev", "Foo::Foo()", 600)
                    + edge("leaf", "_ZN3FooC1Ev") + edge("_ZN3FooC1Ev", "_ZN3FooC2Ev"))
        self.table["tasks"][0]["bytes"] = 4096
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertNotIn("FAIL frame", out)
        # 200 + 300 + alias 0 + body 600: the body is counted, once, not zeroed with its alias.
        self.assertIn("ok   small: 1100 B", out)
        self.assertIn("600  Foo::Foo()", out)

    def test_dtor_alias_in_a_library_and_under_a_file_local_title(self):
        # A local-linkage title carries "<source path>:" before the mangled name, and a
        # library alias (a path outside this repo) is a pass-through just the same.
        local = "@ROOT@/src/SIP/X.cpp:"
        vec = "_ZNSt6vectorIiSaIiEED"
        self.add_ci(bare(local + vec + "1Ev", "std::vector<int>::~vector()", STL_VECTOR_H)
                    + node(local + vec + "2Ev", "std::vector<int>::~vector()", 64, STL_VECTOR_H)
                    + bare("_ZN3FooD1Ev", "Foo::~Foo()") + node("_ZN3FooD2Ev", "Foo::~Foo()", 80)
                    + edge("leaf", local + vec + "1Ev") + edge(local + vec + "1Ev", local + vec + "2Ev")
                    + edge("leaf", "_ZN3FooD1Ev") + edge("_ZN3FooD1Ev", "_ZN3FooD2Ev"))
        self.table["tasks"][0]["bytes"] = 4096
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("ok   small: 580 B", out)             # 200 + 300 + the worse body, 80

    def test_a_frameless_ctor_still_fails_unless_it_calls_its_own_body(self):
        body = node("_ZN3FooC2Ev", "Foo::Foo()", 600)
        cases = {
            # an external function, or a graph that lost the alias's edge: unknown, not zero
            "no edge to the C2 body": bare("_ZN3FooC1Ev", "Foo::Foo()") + body
            + edge("leaf", "_ZN3FooC1Ev"),
            # the body it calls has no frame either
            "body without a frame": bare("_ZN3FooC1Ev", "Foo::Foo()") + bare("_ZN3FooC2Ev", "Foo::Foo()")
            + edge("leaf", "_ZN3FooC1Ev") + edge("_ZN3FooC1Ev", "_ZN3FooC2Ev"),
            # D0, the deleting destructor, is its own function and not an alias of D2
            "D0 is not an alias": bare("_ZN3FooD0Ev", "Foo::~Foo()") + node("_ZN3FooD2Ev", "Foo::~Foo()", 80)
            + edge("leaf", "_ZN3FooD0Ev") + edge("_ZN3FooD0Ev", "_ZN3FooD2Ev"),
        }
        for why, text in cases.items():
            with self.subTest(why):
                self.put(os.path.join(self.ci, "x.ci"), CI)
                self.add_ci(text)
                self.table["tasks"][0]["bytes"] = 4096
                rc, out = self.run_gate()
                self.assertEqual(rc, 1, out)
                self.assertIn("FAIL frame: project function with no frame data (partial --ci-dir?): Foo::", out)
                self.assertNotIn("FAIL small", out)    # the chain is within budget; only the frame is unknown

    # --- which functions are this repo's (#457) -----------------------------------------
    # The ceiling and "no frame data" checks are for src/ and main/. The gate used to take
    # any "/src/" in a label's path for ours, which also matches IDF's lwip/src.

    def test_idf_component_sources_are_not_project_code(self):
        self.add_ci(node("lwip_big", "int lwip_big(int)", 2000, LWIP_C)
                    + bare("lwip_socket", "int lwip_socket(int, int, int)", LWIP_H)
                    + edge("leaf", "lwip_big") + edge("leaf", "lwip_socket"))
        self.table["tasks"][0]["bytes"] = 8192
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL frame: library callee with no frame data, no library_defaults match: "
                      "int lwip_socket", out)
        self.assertNotIn("project function with no frame data", out)
        self.assertNotIn("B ceiling", out)           # lwip's 2000 B frame is not ours to cap...
        self.assertIn("ok   small: 2500 B", out)     # ...but it is in the chain: 200 + 300 + 2000
        self.table["library_defaults"] = {r"\blwip_socket\(": 400}   # now a default can apply to it
        self.assertEqual(self.run_gate()[0], 0)

    def test_main_dir_is_project_code(self):
        # main/esp_main_*.cpp holds the task entry points; its frames are capped like src/'s.
        self.add_ci(node("big_main", "void big_main()", 1500, "@ROOT@/main/esp_main_eth.cpp:1:1")
                    + edge("leaf", "big_main"))
        self.table["tasks"][0]["bytes"] = 8192
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL frame: 1500 B > 1024 B ceiling, no allowlist entry: void big_main()", out)

    def test_a_runtime_hook_labelled_by_its_call_site_takes_a_library_default(self):
        # GCC labels a callee it never saw defined (an ellipse node) with the location of a
        # use, so __cxa_guard_acquire reads as ours when the last .ci to mention it is ours.
        # A library_defaults row has to be able to claim it, or no table edit can clear it.
        self.add_ci(bare("__cxa_guard_acquire", "int __cxa_guard_acquire(long long int*)",
                         "@ROOT@/src/SIP/X.cpp:12:3") + edge("leaf", "__cxa_guard_acquire"))
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("project function with no frame data (partial --ci-dir?): int __cxa_guard_acquire", out)
        self.table["library_defaults"] = {r"\b__cxa_guard_acquire\(": 64}
        self.table["tasks"][0]["bytes"] = 4096
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("ok   small: 564 B", out)      # 200 + 300 + 64

    def test_a_graph_compiled_elsewhere_fails_closed_until_given_its_project_root(self):
        # .ci files built in another checkout: nothing in them is under --src-root. Reading
        # that as "no project code, so nothing to cap" would pass any frame.
        self.put(os.path.join(self.ci, "x.ci"), CI.replace("@ROOT@", "/elsewhere/ck"))
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL project root: no function with frame data is under", out)
        p = os.path.join(self.tmp.name, "t.json")
        json.dump(self.table, open(p, "w"))
        r = subprocess.run([sys.executable, GATE, "--ci-dir", self.ci, "--table", p,
                            "--src-root", self.tmp.name, "--project-root", "/elsewhere/ck"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("ok   big: 1900 B", r.stdout)

    # --- recursion (#457, desmo 2026-10-02) ---------------------------------------------
    # Any cycle reachable from a walked task fails unless recursion_allowlist names it with a
    # bound ("depth": at most that many live activations of each member) and a reason. The
    # bound is charged: depth x the sum of the cycle's frames, once, in the chain total.

    def test_a_reachable_cycle_without_a_row_fails_and_is_named(self):
        self.add_ci(CYCLE)
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        lines = [ln for ln in out.splitlines() if ln.startswith("FAIL recursion")]
        self.assertEqual(len(lines), 1, out)
        for want in ("void mid()", "void helper()", "big", "recursion_allowlist"):
            self.assertIn(want, lines[0])

    def test_a_bounded_cycle_passes_and_the_bound_is_charged(self):
        self.add_ci(CYCLE)
        self.table["recursion_allowlist"] = {"void mid()": dict(BOUND)}
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        # big_task 400 + the cycle 3 x (mid 600 + helper 100) + buildOptionsPing 900
        self.assertIn("ok   big: 3400 B", out)
        self.table["recursion_allowlist"]["void mid()"]["depth"] = 5     # the bound is not ignored
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL big: 4800 B + 512 margin > 4096 B", out)

    def test_self_recursion_is_a_cycle_too(self):
        self.add_ci(node("rec", "void rec(int)", 64) + edge("leaf", "rec") + edge("rec", "rec"))
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL recursion", out)
        self.assertIn("void rec(int)", out)
        self.table["recursion_allowlist"] = {"void rec(int)": {"depth": 4, "reason": "fixture"}}
        self.table["tasks"][0]["bytes"] = 4096
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("ok   small: 756 B", out)             # 200 + 300 + 4 x 64

    def test_a_cycle_through_ctor_dtor_aliases_is_charged_by_its_real_frames(self):
        # The shape of JsonReader::Value::~Value on the real graph: each D1 is a frameless alias
        # with an edge to its D2 body, and the four of them close a loop.
        v, w = "_ZN3ValD", "_ZNSt6vectorI3ValSaIS0_EED"
        self.add_ci(bare(v + "1Ev", "Val::~Val()") + node(v + "2Ev", "Val::~Val()", 32)
                    + bare(w + "1Ev", "std::vector<Val>::~vector()")
                    + node(w + "2Ev", "std::vector<Val>::~vector()", 32)
                    + edge(v + "1Ev", v + "2Ev") + edge(v + "2Ev", w + "1Ev")
                    + edge(w + "1Ev", w + "2Ev") + edge(w + "2Ev", v + "1Ev") + edge("leaf", v + "1Ev"))
        self.table["tasks"][0]["bytes"] = 4096
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL recursion", out)
        self.assertNotIn("no frame data", out)              # the aliases are not the complaint
        self.table["recursion_allowlist"] = {"Val::~Val()": {"depth": 9, "reason": "fixture"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("ok   small: 1076 B", out)            # 200 + 300 + 9 x (32 + 32)

    def test_a_level_costs_the_heaviest_trip_round_the_cycle_not_every_member(self):
        # The shape of the JSON parser: a -> (b | c) -> a. A level goes through a and ONE of b, c,
        # so 4 levels cost 4 x (a 32 + c 144) = 704, not 4 x (32 + 112 + 144).
        self.add_ci(node("a", "void a()", 32) + node("b", "void b()", 112) + node("c", "void c()", 144)
                    + edge("leaf", "a") + edge("a", "b") + edge("a", "c") + edge("b", "a") + edge("c", "a"))
        self.table["recursion_allowlist"] = {"void a()": {"depth": 4, "reason": "fixture"}}
        self.table["tasks"][0]["bytes"] = 4096
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("ok   small: 1204 B", out)            # 200 + 300 + 704

    def test_a_cycle_no_walked_task_reaches_does_not_fail(self):
        self.add_ci(node("u1", "void u1()", 50) + node("u2", "void u2()", 50)
                    + edge("u1", "u2") + edge("u2", "u1"))
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertNotIn("recursion", out)

    def test_a_cycle_only_a_skipped_task_reaches_is_not_walked(self):
        # dns_task is linked into the display image only, so its loop is not in the eth image.
        open(os.path.join(self.tmp.name, "src", "SIP", "X.cpp"), "a").write(
            'xTaskCreate(dns_task, "dns", 4096, 0, 1, 0);\n')
        self.table["tasks"].append({"name": "dns", "entry": r"\bdns_task\(", "bytes": 4096,
                                    "file": "src/SIP/X.cpp", "line": 3,
                                    "variants": ["main/esp_main_display.cpp"]})
        self.add_ci(node("dns_task", "void dns_task(void*)", 50) + node("d1", "void d1()", 50)
                    + node("d2", "void d2()", 50) + edge("dns_task", "d1")
                    + edge("d1", "d2") + edge("d2", "d1"))
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        rc, out = self.run_gate(main="main/esp_main_display.cpp")
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL recursion", out)
        self.assertIn("dns", out)

    def test_a_row_must_state_a_bound_and_a_reason(self):
        self.add_ci(CYCLE)
        bad = {"no depth": {"reason": "r"}, "zero depth": {"depth": 0, "reason": "r"},
               "fractional depth": {"depth": 2.5, "reason": "r"}, "bool depth": {"depth": True, "reason": "r"},
               "no reason": {"depth": 2}, "blank reason": {"depth": 2, "reason": "  "},
               "a bare number": 3}
        for why, row in bad.items():
            with self.subTest(why):
                self.table["recursion_allowlist"] = {"void mid()": row}
                rc, out = self.run_gate()
                self.assertEqual(rc, 1, out)
                self.assertIn("FAIL recursion_allowlist row 'void mid()'", out)

    def test_two_rows_for_one_cycle_are_ambiguous(self):
        self.add_ci(CYCLE)
        self.table["recursion_allowlist"] = {"void mid()": dict(BOUND), "void helper()": dict(BOUND, depth=2)}
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("ambiguous", out)

    def test_checked_in_recursion_rows_state_a_bound_and_a_reason(self):
        table = json.load(open(os.path.join(os.path.dirname(GATE), "task_stacks.json")))
        rows = table["recursion_allowlist"]
        self.assertTrue(rows)
        for key, row in rows.items():
            self.assertIsInstance(row["depth"], int, key)
            self.assertGreaterEqual(row["depth"], 1, key)
            self.assertTrue(row["reason"].strip(), key)

    def test_checked_in_recursion_bounds_follow_the_code(self):
        # Each depth is derived from a constant in the source; raise the constant and this
        # fails, so the row is re-derived instead of going stale.
        table = json.load(open(os.path.join(os.path.dirname(GATE), "task_stacks.json")))
        rows = {k: r["depth"] for k, r in table["recursion_allowlist"].items()}

        def const(path, pattern):
            return int(re.search(pattern, open(os.path.join(g.REPO, path)).read()).group(1), 0)

        def row(fragment):
            hit = [d for k, d in rows.items() if fragment in k]
            self.assertEqual(len(hit), 1, f"{fragment}: one row expected, got {hit}")
            return hit[0]

        max_depth = const("src/Helpers/JsonReader.hpp", r"kMaxDepth\s*=\s*(\d+)")
        max_bytes = const("src/Helpers/JsonReader.hpp", r"kMaxBytes\s*=\s*(\d+)")
        sessions = const("src/SIP/PoolConfig.hpp", r"#define POCKETDIAL_MAX_SESSIONS\s+(\d+)")
        nvs_bytes = const("partitions.csv", r"nvs,\s*data,\s*nvs,\s*0x9000,\s*(0x[0-9a-fA-F]+)")
        # A red-black tree of n nodes is at most 2*log2(n+1) tall, and _M_erase recurses once per level.
        rb = lambda n: math.floor(2 * math.log2(n + 1))
        self.assertGreaterEqual(row("Parser::parseObject("), max_depth + 1)   # kMaxDepth levels + the refused one
        self.assertGreaterEqual(row("JsonReader::Value::~Value()"), max_depth + 1)
        self.assertGreaterEqual(row("_KeyOfValue = std::_Identity"), rb(max_bytes // 4))   # 4 B least per entry
        self.assertGreaterEqual(row("std::shared_ptr<Session>"), rb(sessions))
        self.assertGreaterEqual(row("basic_string<char>, std::__cxx11::basic_string<char> >"),
                                rb(nvs_bytes // 32))     # one 32 B NVS entry at least per cached HA1


if __name__ == "__main__":
    unittest.main()

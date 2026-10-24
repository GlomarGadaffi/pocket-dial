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


def alias_node(title, name, loc="/idf/components/vfs/vfs_calls.c:927:5"):
    """What GCC writes for `int f(void) __attribute__((alias("g")))`: a node with no stack line and
    `shape : triangle` (a declaration is an ellipse), whose one edge goes to the aliased function."""
    return f'node: {{ title: "{title}" label: "{name}\\n{loc}" shape : triangle }}\n'


def edge(a, b, label=None):
    """A call edge. GCC puts the call's file:line:col in `label`, and leaves it off the
    placeholder edge of a block operation it expands to a memset/memcpy libcall."""
    where = f' label: "{label}"' if label else ""
    return f'edge: {{ sourcename: "{a}" targetname: "{b}"{where} }}\n'


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
        self.assertIn("reached from: void leaf()", out)            # the caller on the shortest path
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
        # Project frames over the ceiling on the Xtensa eth image (#457): the first 11 from the
        # run on #685 @ ebdc919 (2026-09-29), the last 7 from the combined-tree run of 2026-10-04
        # (issue comment 5976074325). No .ci was at hand for the 7: their labels are written from
        # the source signatures, which is all the allowlist's `Class::name(` keys match on.
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
               ("void RequestsHandler::onRefer(std::shared_ptr<SipMessage>)", 1056),
               # tick() was 1024 B, the ceiling itself, until #1028 (2993c0dc) added a std::string for the
               # 480's To tag; BigDog's run on that tree measured 1056 B.
               ("void RequestsHandler::tick()", 1056),
               ("void RequestsHandler::relayIntoPeerDialog(const std::shared_ptr<SipMessage>&, "
                "const std::shared_ptr<Session>&)", 1648),
               ("void HttpServer::sendApiConfigExport(int, bool, const std::string&)", 1392),
               ("bool SipTrunk::handleCancel(const std::shared_ptr<SipMessage>&)", 1248),
               ("void SipTrunk::releaseAsTimeout(SipTrunk::Dialog&)", 1152),
               ("void RequestsHandler::onBye(std::shared_ptr<SipMessage>)", 1120),
               ("bool RequestsHandler::handleSpliceResponse(const std::shared_ptr<SipMessage>&)", 1072),
               ("void HttpServer::sendApiConfigImport(int, const std::string&)", 1040)]
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

    # --- template constructors (#457) -----------------------------------------------------
    # A constructor template mangles as C1I<template args>E<params>, not C1E<params>, so the
    # alias rule above did not see it. On the first real CI run that left
    # telephony::SosStatusClaim (SosStatusGet.hpp, a project type) as "project function with no
    # frame data", and the std::pair, std::function, std::thread and shared_ptr constructor
    # templates as library callees with none.

    def test_alias_body_reads_template_ctor_titles(self):
        frames = {"_ZN3FooC2IiEEOT_": (600, "static")}
        edges = {"_ZN3FooC1IiEEOT_": {"_ZN3FooC2IiEEOT_"}, "_ZN3FooC1Ev": {"_ZN3FooC2Ev"}}
        self.assertEqual(g.alias_body("_ZN3FooC1IiEEOT_", edges, frames), "_ZN3FooC2IiEEOT_")
        # not a constructor: "C1I" inside a length-prefixed name derives a body that is not there
        self.assertIsNone(g.alias_body("_ZN5AC1Id3fooEv", {"_ZN5AC1Id3fooEv": {"_ZN3barEv"}}, {"_ZN3barEv": (64, "static")}))
        # and the plain rule is unchanged: no body in frames, or no edge to it, is no alias
        self.assertIsNone(g.alias_body("_ZN3FooC1Ev", edges, frames))
        self.assertIsNone(g.alias_body("_ZN3FooC1IiEEOT_", {}, frames))

    def test_ctor_template_alias_is_a_pass_through_to_its_body(self):
        local = "@ROOT@/src/SIP/X.cpp:"
        pair = "_ZNSt4pairIiiEC"
        cases = {
            "a project constructor template": (
                bare("_ZN3FooC1IiEEOT_", "Foo::Foo(T&&) [with T = int]")
                + node("_ZN3FooC2IiEEOT_", "Foo::Foo(T&&) [with T = int]", 600)
                + edge("leaf", "_ZN3FooC1IiEEOT_") + edge("_ZN3FooC1IiEEOT_", "_ZN3FooC2IiEEOT_"), "1100 B", "600  Foo::Foo"),
            "a library constructor template under a file-local title": (
                bare(local + pair + "1IRiS2_Lb1EEEOT_OT0_", "std::pair<int, int>::pair(U1&&, U2&&)", STL_VECTOR_H)
                + node(local + pair + "2IRiS2_Lb1EEEOT_OT0_", "std::pair<int, int>::pair(U1&&, U2&&)", 80, STL_VECTOR_H)
                + edge("leaf", local + pair + "1IRiS2_Lb1EEEOT_OT0_")
                + edge(local + pair + "1IRiS2_Lb1EEEOT_OT0_", local + pair + "2IRiS2_Lb1EEEOT_OT0_"), "580 B", "80  std::pair"),
        }
        for why, (text, total, shown) in cases.items():
            with self.subTest(why):
                self.put(os.path.join(self.ci, "x.ci"), CI)
                self.add_ci(text)
                self.table["tasks"][0]["bytes"] = 4096
                rc, out = self.run_gate()
                self.assertEqual(rc, 0, out)
                self.assertNotIn("FAIL frame", out)
                self.assertIn("ok   small: " + total, out)       # 200 + 300 + the body, counted once
                self.assertIn(shown, out)

    def test_a_frameless_ctor_template_still_fails_unless_it_calls_its_own_body(self):
        body = node("_ZN3FooC2IiEEOT_", "Foo::Foo(T&&) [with T = int]", 600)
        cases = {
            "no edge to the C2 body": bare("_ZN3FooC1IiEEOT_", "Foo::Foo(T&&) [with T = int]") + body
            + edge("leaf", "_ZN3FooC1IiEEOT_"),
            "body without a frame": bare("_ZN3FooC1IiEEOT_", "Foo::Foo(T&&) [with T = int]")
            + bare("_ZN3FooC2IiEEOT_", "Foo::Foo(T&&) [with T = int]")
            + edge("leaf", "_ZN3FooC1IiEEOT_") + edge("_ZN3FooC1IiEEOT_", "_ZN3FooC2IiEEOT_"),
            "the body is another instantiation's": bare("_ZN3FooC1IiEEOT_", "Foo::Foo(T&&) [with T = int]")
            + node("_ZN3FooC2IlEEOT_", "Foo::Foo(T&&) [with T = long]", 600)
            + edge("leaf", "_ZN3FooC1IiEEOT_") + edge("_ZN3FooC1IiEEOT_", "_ZN3FooC2IlEEOT_"),
        }
        for why, text in cases.items():
            with self.subTest(why):
                self.put(os.path.join(self.ci, "x.ci"), CI)
                self.add_ci(text)
                self.table["tasks"][0]["bytes"] = 4096
                rc, out = self.run_gate()
                self.assertEqual(rc, 1, out)
                self.assertIn("FAIL frame: project function with no frame data (partial --ci-dir?): Foo::Foo(T&&)", out)

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

    def test_checked_in_runtime_hook_rows_claim_only_their_own_names(self):
        # The checked-in rows for errno's TLS init hook and the IDF __cxa_guard_* functions,
        # each labelled with a use site of ours as on the real .ci. The guard is charged.
        table = json.load(open(os.path.join(os.path.dirname(GATE), "task_stacks.json")))
        self.table["library_defaults"] = table["library_defaults"]
        self.table["tasks"][0]["bytes"] = 4096
        for name, label in (("_ZTH5errno", "void _ZTH5errno()"),
                            ("__cxa_guard_acquire", "int __cxa_guard_acquire(long long int*)")):
            self.add_ci(bare(name, label, "@ROOT@/src/SIP/X.cpp:12:3") + edge("leaf", name))
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertNotIn("FAIL frame", out)
        self.assertIn("ok   small: 1876 B", out)     # 200 + 300 + the guard's 1376
        self.add_ci(bare("__cxa_guard_foo_project", "int __cxa_guard_foo_project(long long int*)",
                         "@ROOT@/src/SIP/X.cpp:13:3") + edge("leaf", "__cxa_guard_foo_project"))
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("project function with no frame data (partial --ci-dir?): int __cxa_guard_foo_project", out)
        for row in ("^void _ZTH5errno\\(\\)$", "^int __cxa_guard_acquire\\(long long int\\*\\)$",
                    "^void __cxa_guard_(release|abort)\\(long long int\\*\\)$"):
            self.assertTrue(table["_library_defaults_reasons"].get(row, "").strip(), row + " states no reason")

    def test_the_wifi_blob_row_claims_only_its_own_name(self):
        # esp_wifi_internal_tx lives in Espressif's prebuilt Wi-Fi library, so no .ci has a frame for it.
        # wifi_transmit (esp_wifi/src/wifi_netif.c) calls it, and the indirect_allowlist row for
        # esp_netif_transmit makes that call reachable. Like the other prebuilt callees it takes a stated
        # estimate, and the row must not catch a function of ours.
        table = json.load(open(os.path.join(os.path.dirname(GATE), "task_stacks.json")))
        self.table["library_defaults"] = table["library_defaults"]
        self.table["tasks"][0]["bytes"] = 4096
        self.add_ci(bare("esp_wifi_internal_tx", "esp_err_t esp_wifi_internal_tx(wifi_interface_t, void*, uint16_t)",
                         "/idf/components/esp_wifi/include/esp_private/wifi.h:210:5") + edge("leaf", "esp_wifi_internal_tx"))
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertNotIn("FAIL frame", out)
        self.assertIn("ok   small: 1524 B", out)         # 200 + 300 + the 1024 B estimate
        self.add_ci(bare("esp_wifi_internal_tx_shim", "void esp_wifi_internal_tx_shim()", "@ROOT@/src/SIP/X.cpp:14:3")
                    + edge("leaf", "esp_wifi_internal_tx_shim"))
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("project function with no frame data (partial --ci-dir?): void esp_wifi_internal_tx_shim", out)
        self.assertTrue(table["_library_defaults_reasons"].get(
            r"(?:^|[ *&])esp_wifi_internal_tx(?:\(|$)", "").startswith("1024 B"))

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

    # --- the local gate's relative labels (#457) ----------------------------------------
    # ~/gate/env.sh exports CCACHE_BASEDIR, so ccache hands GCC a build-dir-relative path
    # and every label of ours reads ../src/... or ../main/...; IDF and toolchain labels
    # stay absolute. REAL_CI is two nodes verbatim from the e73c3b1 gate's
    # RequestsHandler.cpp.ci.
    REAL_CI = (
        'node: { title: "../src/SIP/RequestsHandler.cpp:_ZN15RequestsHandler9TelCtlJobD2Ev" label: '
        '"constexpr RequestsHandler::TelCtlJob::~TelCtlJob()\\n../src/SIP/RequestsHandler.hpp:1862:9\\n'
        '32 bytes (static)" }\n'
        'node: { title: "_ZN15RequestsHandler10postTelCtlEPNS_9TelCtlJobENS_7TelLaneE" label: '
        '"bool RequestsHandler::postTelCtl(TelCtlJob*, TelLane)\\n../src/SIP/RequestsHandler.cpp:5054:6\\n'
        '48 bytes (static)" }\n')

    def test_relative_labels_from_the_local_gate_are_project_code(self):
        for f in ("RequestsHandler.cpp", "RequestsHandler.hpp"):
            open(os.path.join(self.tmp.name, "src", "SIP", f), "w").close()
        self.put(os.path.join(self.ci, "x.ci"), CI.replace("@ROOT@/", "../") + self.REAL_CI)
        rc, out = self.run_gate()
        self.assertNotIn("FAIL project root", out)
        self.assertEqual(rc, 0, out)
        self.assertIn("ok   big: 1900 B", out)
        self.table["frame_ceiling_bytes"] = 800      # the ceiling caps project frames only
        rc, out = self.run_gate()
        self.assertIn("FAIL frame: 900 B > 800 B", out)

    def test_which_locations_are_project_code(self):
        root = self.tmp.name
        open(os.path.join(root, "main", "esp_main_eth.cpp"), "w").close()
        roots = g.project_roots(root)
        cases = {
            "../src/SIP/X.cpp:1:1": True,
            "../main/esp_main_eth.cpp:3:5": True,
            root + "/src/SIP/X.cpp:1:1": True,
            "../src/SIP/Missing.cpp:1:1": False,       # not in this checkout: a wrong root
            "../../other/src/SIP/X.cpp:1:1": False,    # outside the checkout
            "esp-idf/main/generated.c:1:1": False,     # under build/, not src/ or main/
            "/opt/esp/esp-idf/components/lwip/lwip/src/core/ipv4/etharp.c:12:1": False,
            STL_VECTOR_H: False,
        }
        for loc, want in cases.items():
            with self.subTest(loc):
                self.assertEqual(g.is_project("f()\\n" + loc + "\\n8 bytes (static)", roots), want)

    def test_relative_labels_under_a_wrong_root_still_fail_closed(self):
        self.put(os.path.join(self.ci, "x.ci"), CI.replace("@ROOT@/", "../"))
        p = os.path.join(self.tmp.name, "t.json")
        json.dump(self.table, open(p, "w"))
        with tempfile.TemporaryDirectory() as empty:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = g.run(self.ci, p, self.tmp.name, "main/esp_main_eth.cpp", project_root=empty)
        self.assertEqual(rc, 1, out.getvalue())
        self.assertIn("FAIL project root: no function with frame data is under", out.getvalue())

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

    # --- what the first real CI run printed (#457) ----------------------------------------
    # tests/tools/fixtures/task_stack_gate_run_39346846761.json holds the names the gate printed
    # in the stack-depth-gate job (PR #1031): 195 library callees with no frame data, 8 cycles
    # with no recursion row, 2 dynamic frames. A red job is meant to mean a project problem, so
    # each of those needs a row that says why it is modelled the way it is.

    def first_run(self):
        path = os.path.join(os.path.dirname(__file__), "fixtures", "task_stack_gate_run_39346846761.json")
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def checked_in(self):
        with open(os.path.join(os.path.dirname(GATE), "task_stacks.json"), encoding="utf-8") as f:
            return json.load(f)

    def test_checked_in_library_defaults_cover_the_first_ci_run(self):
        run, table = self.first_run(), self.checked_in()
        self.assertEqual(len(run["library_callees"]), 195)
        # Each name as a frameless callee of a library file, walked by the gate itself with the
        # checked-in rows: no "library callee with no frame data" is left.
        lib = "/tc/include/c++/15.2.0/bits/stl_vector.h:1:1"
        text = "".join(bare(f"lib{i}", name, lib) + edge("leaf", f"lib{i}")
                       for i, name in enumerate(run["library_callees"]))
        self.add_ci(text)
        self.table["library_defaults"] = table["library_defaults"]
        self.table["tasks"][0]["bytes"] = 1 << 20          # the budget is not what is under test
        rc, out = self.run_gate()
        left = [ln for ln in out.splitlines() if "library callee with no frame data" in ln]
        self.assertEqual(left, [], "\n".join(left[:10]))
        self.assertEqual(rc, 0, out[:600])

    def test_each_first_run_callee_matches_exactly_one_library_default(self):
        # The gate takes the first match in sorted key order; one match per name keeps the table
        # free of an order nobody can see.
        run, table = self.first_run(), self.checked_in()
        rows = list(table["library_defaults"])
        for name in run["library_callees"]:
            hits = [k for k in rows if re.search(k, name)]
            self.assertEqual(len(hits), 1, f"{name[:90]!r} matches {hits}")

    def test_every_library_default_states_its_figure_and_reason(self):
        table = self.checked_in()
        reasons = table["_library_defaults_reasons"]
        for rx, b in table["library_defaults"].items():
            with self.subTest(rx):
                why = reasons.get(rx, "")
                self.assertTrue(why.startswith(f"{b} B"), f"reason must open with its figure, '{b} B': {why[:60]!r}")
                self.assertGreater(len(why), 60, "a figure needs its provenance")
        self.assertEqual(sorted(set(reasons) - set(table["library_defaults"])), [], "a reason for a row that is gone")

    def test_library_defaults_still_fail_closed_on_an_unclassified_name(self):
        # A table of rows is not a blanket: a library function nobody looked at is still a FAIL.
        table = self.checked_in()
        for name in ("qsort_r", "void vendor::mystery(int)", "int pvPortMallocCaps(unsigned int)",
                     "esp_http_client_perform", "mbedtls_ssl_handshake", "std::string std::to_string(long)"):
            with self.subTest(name):
                self.assertEqual([k for k in table["library_defaults"] if re.search(k, name)], [])

    def test_checked_in_recursion_rows_cover_the_first_ci_run_cycles(self):
        run, rows = self.first_run(), self.checked_in()["recursion_allowlist"]
        self.assertEqual(len(run["cycles"]), 8)
        claimed = {}
        for cycle in run["cycles"]:
            hits = [k for k in rows if any(k in name for name in cycle["shown_members"])]
            self.assertEqual(len(hits), 1, f"{cycle['shown_members']}: rows {hits}")
            self.assertNotIn(hits[0], claimed, f"'{hits[0]}' names two cycles")
            claimed[hits[0]] = cycle["size"]

    def cjson_nesting_limit(self):
        """CJSON_NESTING_LIMIT as the firmware build gives it to the cjson component (top-level
        CMakeLists.txt, after project()), or None when nothing does."""
        with open(os.path.join(g.REPO, "CMakeLists.txt"), encoding="utf-8") as f:
            text = f.read()
        lib = re.search(r"idf_component_get_property\(\s*(\w+)\s+espressif__cjson\s+COMPONENT_LIB\s*\)", text)
        m = lib and re.search(r"set_property\(\s*TARGET\s+\$\{" + lib.group(1) +
                              r"\}\s+PROPERTY\s+COMPILE_DEFINITIONS\s+\$\{\w+\}\s+\"CJSON_NESTING_LIMIT=(\d+)\"\s*\)", text)
        # The component defines CJSON_NESTING_LIMIT=1000 itself: a second -D is a -Werror redefinition,
        # so the build must drop the component's value first (run 39355912998 failed on exactly this).
        self.assertFalse(m and "EXCLUDE REGEX \"^CJSON_NESTING_LIMIT=\"" not in text,
                         "appending a second CJSON_NESTING_LIMIT -D fails -Werror; replace the component's")
        if m:
            self.assertLess(text.index('project("SipServer")'), m.start(), "the cjson target exists only after project()")
        return int(m.group(1)) if m else None

    def test_cjson_nesting_limit_is_a_compile_definition_of_the_cjson_component(self):
        # cJSON parses and deletes recursively and refuses nesting only past CJSON_NESTING_LIMIT,
        # 1000 by default: no task stack here holds that. desmo's decision (#457): 16, as a
        # compile definition of the cjson component (only cJSON.c reads it).
        self.assertEqual(self.cjson_nesting_limit(), 16)

    def test_cjson_recursion_rows_are_the_nesting_limit_not_a_guess(self):
        # Every tree in this firmware comes from cJSON_Parse*, and cJSON checks its depth counter on
        # entry to parse_array and parse_object, so at most `limit` containers are open at once. The
        # gate's depth counts live activations of one member: parse_value is live once per open
        # container plus once for the innermost value, and cJSON_Delete once per tree level likewise.
        # That is limit + 1, as the JsonReader rows are kMaxDepth + 1. The rows follow the define.
        rows = self.checked_in()["recursion_allowlist"]
        limit = self.cjson_nesting_limit()
        self.assertIsNotNone(limit, "no CJSON_NESTING_LIMIT define: cJSON would accept 1000 levels")
        for key in ("parse_value", "cJSON_Delete("):
            with self.subTest(key):
                self.assertEqual(rows[key]["depth"], limit + 1)
                self.assertIn("CJSON_NESTING_LIMIT", rows[key]["reason"])
                self.assertIn("CMakeLists.txt", rows[key]["reason"])

    def test_checked_in_dynamic_frames_of_the_first_run_are_allowlisted(self):
        run, table = self.first_run(), self.checked_in()
        self.assertEqual(len(run["dynamic_frames"]), 2)
        ext = "/managed_components/espressif__mdns/mdns.c:1:1"
        self.add_ci("".join(node(f"dyn{i}", name, 96, ext, "dynamic") + edge("leaf", f"dyn{i}")
                            for i, name in enumerate(run["dynamic_frames"])))
        self.table["tasks"][0]["bytes"] = 4096
        rc, out = self.run_gate()
        self.assertEqual(out.count("dynamic frame, no allowlist entry"), 2, out)      # positive control
        self.table["frame_allowlist"] = table["frame_allowlist"]
        rc, out = self.run_gate()
        self.assertNotIn("dynamic frame", out)
        self.assertEqual(rc, 0, out)
        self.assertTrue(all(table["frame_allowlist"][k].strip() for k in table["frame_allowlist"]))

    def test_http_conn_keeps_its_budget(self):
        # http_conn is the one real red the stack-depth-gate job reports until its stack is fixed
        # (4768 B + 512 > 4096 B in the first run). Nothing in the table loosens it away.
        table = self.checked_in()
        row = [t for t in table["tasks"] if t["name"] == "http_conn"]
        self.assertEqual([(t["bytes"], t["file"]) for t in row], [(4096, "src/Helpers/HttpServer.cpp")])
        self.assertEqual((table["margin_bytes"], table["frame_ceiling_bytes"]), (512, 1024))

    def test_indirect_call_sites_are_reported_per_task_not_silently_zero(self):
        # An indirect site is charged 0 B (the walk cannot follow it), so the task line must say
        # how many the task reaches and who makes them: a fit is a fit for direct calls only.
        self.add_ci(node("ind", "Indirect Call Placeholder", 0, kind="static") + edge("mid", "ind", "X.cpp:10:5"))
        self.table["library_defaults"] = {"^Indirect Call Placeholder$": 0}
        rc, out = self.run_gate()
        self.assertIn("indirect call sites: 1 function(s) reachable", out)
        small = out.split("small:")[1].split("big:")[0]
        self.assertIn("indirect call sites: 0 function(s) reachable", small)
        self.assertIn("big:", out)
        self.assertRegex(out.split("big:")[1], r"indirect call sites: 1 function\(s\) reachable make one, 1 of them on the worst chain.*mid")

    # #1031 review: an indirect call is charged 0 B, so a task that carries a 911 path must not
    # pass on that. Such a task is marked "indirect": "bounded" in the table; every function it
    # reaches that makes an indirect call then needs an indirect_allowlist row naming the
    # possible targets, and the walk charges the heaviest of them.
    def indirect_fixture(self, flag=True):
        self.add_ci(node("ind", "Indirect Call Placeholder", 0)
                    + node("slow", "void SlowSink::write()", 1000) + edge("mid", "ind", "X.cpp:10:5"))
        self.table["library_defaults"] = {"^Indirect Call Placeholder$": 0}
        if flag:
            for t in self.table["tasks"]:
                if t["name"] == "big":
                    t["indirect"] = "bounded"

    def test_an_unbounded_indirect_site_on_a_911_task_fails_the_gate(self):
        self.indirect_fixture()
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertRegex(out, r"(?s)FAIL big: .*FAIL big: .*indirect_allowlist.*void mid\(\)")

    def test_a_bounded_indirect_site_passes_and_the_heaviest_target_is_charged(self):
        self.indirect_fixture()
        self.table["indirect_allowlist"] = {r"void mid\(\)": {
            "targets": [r"SlowSink::write\("], "reason": "fixture: the one sink installed at boot"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("big: 2000 B", out)         # 400 + 600 (mid) + 1000 (SlowSink::write) beats helper and buildOptionsPing
        self.assertIn("SlowSink::write", out)

    def test_a_target_that_matches_no_function_bounds_nothing_and_fails(self):
        self.indirect_fixture()
        self.table["indirect_allowlist"] = {r"void mid\(\)": {
            "targets": [r"NoSuchSink::write\("], "reason": "fixture"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("matches no function", out)

    def test_a_row_must_name_targets_and_a_reason(self):
        self.indirect_fixture()
        for row in ({"reason": "x"}, {"targets": "SlowSink", "reason": "x"}, {"targets": ["SlowSink"], "reason": " "}):
            self.table["indirect_allowlist"] = {r"void mid()": row}
            rc, out = self.run_gate()
            self.assertEqual(rc, 1, out)
            self.assertIn("indirect_allowlist row 'void mid", out)

    def test_a_row_with_no_targets_bounds_a_site_that_can_call_nothing(self):
        self.indirect_fixture()
        self.table["indirect_allowlist"] = {r"void mid\(\)": {"targets": [], "reason": "fixture: pointer never installed"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("big: 1900 B", out)

    # A thread body is not on the caller's stack, and a label's "[with ...]" tail names template
    # arguments, not the function: a target pattern is matched against the name before it, so
    # the _M_run of a thread whose lambda sits in Thing::run is not a target of Thing::run.
    def test_a_target_pattern_does_not_match_a_template_argument_annotation(self):
        self.indirect_fixture()
        self.add_ci(node("run", "void Thing::run(int)", 950)
                    + node("mrun", "void std::thread::_State_impl<_C>::_M_run() "
                           "[with _C = Thing::run(int)::<lambda()>]", 1000))
        self.table["indirect_allowlist"] = {r"void mid\(\)": {
            "targets": [r"Thing::run\("], "reason": "fixture: the one sink"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("big: 1950 B", out)         # 400 + 600 + 950; the 1000 B _M_run would make it 2000
        self.assertNotIn("_M_run", out)
        self.table["indirect_allowlist"][r"void mid\(\)"]["targets"] = [r"_C = Thing::run"]
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)              # nothing is named like that before the "[with"
        self.assertIn("matches no function", out)
        # A pattern that spells out "[with " asks for the note on purpose (one instantiation of
        # a std::function manager, say), and is matched against the whole label.
        self.table["indirect_allowlist"][r"void mid\(\)"]["targets"] = [r"_M_run\(\) \[with _C = Thing::run"]
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("big: 2000 B", out)         # 400 + 600 + the 1000 B _M_run

    def test_the_chain_says_which_edge_an_allowlist_row_added(self):
        self.indirect_fixture()
        self.table["indirect_allowlist"] = {r"void mid\(\)": {
            "targets": [r"SlowSink::write\("], "reason": "fixture"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        line = [ln for ln in out.splitlines() if "void SlowSink::write()" in ln][0]
        self.assertIn(r"via indirect_allowlist row 'void mid\(\)'", line)
        self.assertNotIn("via indirect_allowlist", [ln for ln in out.splitlines() if "void mid()" in ln][0])

    def test_an_unbounded_site_names_the_function_that_reaches_it(self):
        self.indirect_fixture()
        self.add_ci(node("deep", "void Deep::call()", 10) + node("ind2", "Indirect Call Placeholder", 0)
                    + edge("mid", "deep") + edge("deep", "ind2", "X.cpp:20:7"))
        self.table["indirect_allowlist"] = {r"void mid\(\)": {"targets": [], "reason": "fixture"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertRegex(out, r"void Deep::call\(\)\s+at: X\.cpp:20:7\s+<- void mid\(\)")

    def test_an_unbounded_task_lists_where_project_code_enters_a_library(self):
        # 146 library sites are no use as a list; the few calls from our code into the library
        # that reach them are what one reads to decide whether the walk is right.
        self.indirect_fixture()
        self.add_ci(node("lib", "void lib_entry()", 10, loc="/idf/components/x/x.c:1:1")
                    + node("ind2", "Indirect Call Placeholder", 0)
                    + edge("mid", "lib") + edge("lib", "ind2", "X.cpp:30:9"))
        self.table["indirect_allowlist"] = {r"void mid\(\)": {"targets": [], "reason": "fixture"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertRegex(out, r"library entered from project code: void mid\(\) -> void lib_entry\(\)")
        self.assertNotIn("void lib_entry() -> ", out)

    def test_an_unbounded_site_lists_what_else_it_calls(self):
        # What a function with an indirect call also calls is the evidence for reading its source
        # for the pointer: a site that calls only memcpy and a logger has its pointer in one of them.
        self.indirect_fixture()
        self.add_ci(node("deep", "void Deep::call()", 10) + node("ind2", "Indirect Call Placeholder", 0)
                    + node("cp", "void* memcpy_like(void*)", 5) + edge("mid", "deep") + edge("deep", "ind2", "X.cpp:20:7")
                    + edge("deep", "cp"))
        self.table["indirect_allowlist"] = {r"void mid\(\)": {"targets": [], "reason": "fixture"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertRegex(out, r"void Deep::call\(\)\n\s+at: [^\n]+\n\s+<- void mid\(\)\n\s+calls: .*void\* memcpy_like\(void\*\)")
        self.assertNotRegex(out, r"calls: .*Indirect Call Placeholder")

    # GCC puts a call's file:line:col on its placeholder edge. A function that zero-fills or copies an
    # aggregate (`char b[64] = {0}`, `struct S s{}`) gets a placeholder edge with NO label, for the
    # memset/memcpy libcall the expansion makes: that is a block operation, not a call through a
    # pointer, so it needs no indirect_allowlist row, and it is charged as the libc mem* leaf.
    def test_an_unlabelled_placeholder_is_a_block_operation_not_an_indirect_site(self):
        self.add_ci(node("ind", "Indirect Call Placeholder", 0) + node("memcpy", "memcpy", 1000)
                    + edge("mid", "ind"))
        self.table["library_defaults"] = {"^Indirect Call Placeholder$": 0}
        for t in self.table["tasks"]:
            if t["name"] == "big":
                t["indirect"] = "bounded"
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("indirect call sites: 0 function(s) reachable make one", out.split("big:")[1])
        self.assertIn("big: 2000 B", out)         # 400 + 600 + the 1000 B memcpy leaf the block operation calls
        self.assertIn("memcpy", out.split("big:")[1])

    def test_a_block_operation_is_charged_even_when_no_memcpy_node_exists(self):
        self.add_ci(node("ind", "Indirect Call Placeholder", 0) + edge("mid", "ind"))
        self.table["library_defaults"] = {"^Indirect Call Placeholder$": 0, "^memcpy$": 950}
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("big: 1950 B", out)         # 400 + 600 + 950

    def test_a_labelled_and_an_unlabelled_placeholder_on_one_function_still_needs_a_row(self):
        self.add_ci(node("ind", "Indirect Call Placeholder", 0) + node("memcpy", "memcpy", 10)
                    + edge("mid", "ind") + edge("mid", "ind", "X.cpp:10:5"))
        self.table["library_defaults"] = {"^Indirect Call Placeholder$": 0}
        for t in self.table["tasks"]:
            if t["name"] == "big":
                t["indirect"] = "bounded"
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("1 reachable indirect call site(s) have no indirect_allowlist row", out)

    def test_an_unbounded_site_names_where_in_the_source_it_calls(self):
        self.indirect_fixture()
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertRegex(out, r"void mid\(\)\n\s+at: X\.cpp:10:5")

    def test_an_unbounded_site_shows_the_whole_path_from_the_entry(self):
        self.indirect_fixture()
        self.add_ci(node("deep", "void Deep::call(int)", 10) + node("ind2", "Indirect Call Placeholder", 0)
                    + edge("mid", "deep") + edge("deep", "ind2", "X.cpp:20:7"))
        self.table["indirect_allowlist"] = {r"void mid\(\)": {"targets": [], "reason": "fixture"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("path: void big_task > void mid > void Deep::call", out)

    def test_call_positions_are_shown_without_the_build_machines_prefix(self):
        for label, want in (
                ("/opt/esp/idf/components/tcp_transport/transport_ws.c:341:13", "components/tcp_transport/transport_ws.c:341:13"),
                ("/__w/p/p/src/SIP/RequestsHandler.cpp:5:5", "src/SIP/RequestsHandler.cpp:5:5"),
                ("/__w/p/p/build/managed_components/espressif__x/x.c:1:1", "managed_components/espressif__x/x.c:1:1"),
                ("/tc/include/c++/15.2.0/bits/std_function.h:591:9", "15.2.0/bits/std_function.h:591:9"),
                ("X.cpp:10:5", "X.cpp:10:5")):
            self.assertEqual(g.short_site(label), want)

    # __attribute__((alias)): vfs_calls.c makes _close_r, closedir, select and the rest aliases of esp_vfs_*.
    # GCC marks such a node `shape : triangle`, gives it no frame and one edge to the aliased function, whose
    # own frame is charged. Charging the alias a library default as well counts the same call twice.
    def test_an_alias_node_is_a_pass_through_to_the_function_it_aliases(self):
        self.add_ci(alias_node("_close_r", "_close_r") + node("esp_vfs_close", "esp_vfs_close", 32)
                    + edge("leaf", "_close_r") + edge("_close_r", "esp_vfs_close", "/idf/vfs_calls.c:927:5"))
        self.table["library_defaults"] = {"^_close_r$": 1536}      # the estimate that used to be charged for it
        self.table["tasks"][0]["bytes"] = 4096
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("ok   small: 532 B", out)                    # 200 + 300 + alias 0 + esp_vfs_close 32
        self.assertIn("32  esp_vfs_close", out)

    def test_an_alias_of_a_function_with_no_frame_is_still_unknown(self):
        self.add_ci(alias_node("_close_r", "_close_r") + bare("esp_vfs_close", "esp_vfs_close", loc="/idf/vfs_calls.c:1:1")
                    + edge("leaf", "_close_r") + edge("_close_r", "esp_vfs_close"))
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL frame: library callee with no frame data", out)

    def test_an_alias_with_two_edges_is_not_taken_for_a_pass_through(self):
        self.add_ci(alias_node("_close_r", "_close_r") + node("a", "void a()", 32) + node("b", "void b()", 32)
                    + edge("leaf", "_close_r") + edge("_close_r", "a") + edge("_close_r", "b"))
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL frame: library callee with no frame data", out)

    # A target pattern of the form `X::(?:a|b)\(` names several functions: each alternative is checked on
    # its own, so one that is not in the image fails the gate instead of riding on its siblings.
    def test_every_alternative_of_a_target_pattern_must_match_a_function(self):
        self.indirect_fixture()
        self.table["indirect_allowlist"] = {r"void mid\(\)": {
            "targets": [r"SlowSink::(?:write|gone)\("], "reason": "fixture"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("alternative 'gone'", out)
        self.assertNotIn("alternative 'write'", out)
        self.add_ci(node("gone", "void SlowSink::gone()", 10))
        self.assertEqual(self.run_gate()[0], 0)

    # A row whose targets matched nothing bounds nothing, so its caller is not counted as bounded.
    def test_a_row_that_resolved_no_target_does_not_count_its_caller_as_bounded(self):
        self.indirect_fixture()
        self.table["indirect_allowlist"] = {r"void mid\(\)": {
            "targets": [r"NoSuchSink::write\("], "reason": "fixture"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("1 function(s) reachable make one, 0 bounded", out)
        self.assertIn("1 reachable indirect call site(s) have no indirect_allowlist row", out)
        self.table["indirect_allowlist"][r"void mid\(\)"]["targets"] = []
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("1 function(s) reachable make one, 1 bounded", out)

    def test_the_report_counts_the_block_operations_a_task_reaches(self):
        self.add_ci(node("ind", "Indirect Call Placeholder", 0) + node("memcpy", "memcpy", 10)
                    + edge("mid", "ind") + edge("helper", "ind"))
        self.table["library_defaults"] = {"^Indirect Call Placeholder$": 0}
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("block operations (unlabelled placeholder edges, charged as memcpy): 2 function(s) reachable", out.split("big:")[1])
        self.assertIn("block operations (unlabelled placeholder edges, charged as memcpy): 0 function(s) reachable", out.split("small:")[1].split("big:")[0])

    def test_a_cycle_member_with_no_name_is_shown_by_its_title(self):
        self.add_ci(node("_ZL3foov", ")", 8) + node("other", "void other()", 8)
                    + edge("mid", "_ZL3foov") + edge("_ZL3foov", "other") + edge("other", "_ZL3foov"))
        self.table["recursion_allowlist"] = {"void other()": {"depth": 1, "reason": "fixture"}}
        rc, out = self.run_gate()
        self.assertIn("nameless member: title _ZL3foov", out)

    # GCC can lose a function's name (a node whose whole label is ")"); the .ci title survives. A key
    # written `title:REGEX` is searched in the title, so such a function can still carry a row.
    def test_a_row_can_be_keyed_on_the_title_of_a_nameless_function(self):
        self.add_ci(node("esp_log", ")", 40) + node("ind", "Indirect Call Placeholder", 0)
                    + node("sink", "void Sink::emit()", 1000) + edge("mid", "esp_log") + edge("esp_log", "ind", "log.c:9:3"))
        self.table["library_defaults"] = {"^Indirect Call Placeholder$": 0}
        for t in self.table["tasks"]:
            if t["name"] == "big":
                t["indirect"] = "bounded"
        self.table["indirect_allowlist"] = {r"title:^esp_log$": {"targets": [r"Sink::emit\("], "reason": "fixture log.c:9"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("big: 2040 B", out)         # 400 + 600 + esp_log 40 + Sink::emit 1000
        self.table["indirect_allowlist"] = {r"title:^nothing$": {"targets": [], "reason": "fixture log.c:9"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("matches no function that makes an indirect call", out)

    def test_every_alternation_group_of_a_target_is_checked_not_only_the_first(self):
        self.indirect_fixture()
        self.add_ci(node("zed", "void Other::write()", 5))
        self.table["indirect_allowlist"] = {r"void mid\(\)": {
            "targets": [r"(?:SlowSink|Other)::(?:write|gone)\("], "reason": "fixture"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("alternative 'gone'", out)
        self.assertNotIn("alternative 'SlowSink'", out)
        self.assertNotIn("alternative 'Other'", out)
        self.table["indirect_allowlist"][r"void mid\(\)"]["targets"] = [r"(?:SlowSink|Missing)::(?:write)\("]
        self.table["indirect_allowlist"][r"void mid\(\)"]["targets"] = [r"(?:SlowSink|Missing)::write\("]
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("alternative 'Missing'", out)

    # A row can rest on a build setting (which log implementation is linked). The gate reads the CI build's
    # build/config/sdkconfig.h and fails when the setting is not what the row assumed, or the file is missing.
    def test_a_row_that_rests_on_a_build_setting_fails_when_the_build_differs(self):
        self.table["sdkconfig_asserts"] = [{"present": ["CONFIG_LOG_VERSION_1"], "absent": ["CONFIG_LOG_VERSION_2"],
                                            "reason": "the esp_log row reads the version 1 path"}]
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("sdkconfig_asserts: build/config/sdkconfig.h is missing", out)
        cfg = os.path.join(self.tmp.name, "build", "config")
        os.makedirs(cfg)
        h = os.path.join(cfg, "sdkconfig.h")
        with open(h, "w") as f:
            f.write("#define CONFIG_LOG_VERSION_1 1\n")
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        with open(h, "w") as f:
            f.write("#define CONFIG_LOG_VERSION_2 1\n")
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("CONFIG_LOG_VERSION_1 is not defined", out)
        self.assertIn("CONFIG_LOG_VERSION_2 is defined", out)

    # Known findings for the 911 tasks (#1116 tracks the bench measurement); tel_sweep has none, its stack was raised to fit. The cap is the exact current
    # total: the gate passes at it and fails one byte over, and a known row hides nothing else.
    def test_checked_in_known_findings_cap_the_two_911_tasks_at_their_totals(self):
        table = json.load(open(os.path.join(os.path.dirname(GATE), "task_stacks.json")))
        kf = table["known_findings"]
        for name, cap in (("sip_server", 9616), ("tel_ctl", 12944)):
            with self.subTest(name):
                self.assertEqual(kf.get(name, {}).get("max_total"), cap)
                self.assertIn("#1116", kf[name]["reason"])

    def test_a_known_cap_passes_at_its_total_fails_one_byte_over_and_hides_no_unbounded_site(self):
        self.indirect_fixture()
        self.table["indirect_allowlist"] = {r"void mid\(\)": {"targets": [], "reason": "fixture"}}
        for t in self.table["tasks"]:
            if t["name"] == "big":
                t["bytes"] = 2000                         # 1900 + 512 > 2000
        self.table["known_findings"] = {"big": {"max_total": 1900, "bytes": 2000, "reason": "#1116"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("KNOWN big: 1900 B", out)
        self.table["known_findings"]["big"]["max_total"] = 1899
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("a new finding", out)
        self.table["known_findings"]["big"]["max_total"] = 1900
        del self.table["indirect_allowlist"]                 # an unbounded site is a different failure
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL big: 1900 B", out)
        self.assertIn("have no indirect_allowlist row", out)

    # A known row is a ratchet: it fails when the task fits again (remove it) and when the total has come
    # down but the cap has not (lower it), and it holds only for the budget and the site it was written for.
    def test_a_known_row_for_a_task_that_fits_again_fails_and_asks_for_its_removal(self):
        self.table["known_findings"] = {"big": {"max_total": 1900, "bytes": 4096, "reason": "#1116"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL big: known finding is stale, the task fits its 4096 B again: remove the row", out)

    def test_a_known_cap_above_the_current_total_fails_and_asks_for_it_to_come_down(self):
        for t in self.table["tasks"]:
            if t["name"] == "big":
                t["bytes"] = 2000
        self.table["known_findings"] = {"big": {"max_total": 2500, "bytes": 2000, "reason": "#1116"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL big: known finding cap 2500 B is above the total 1900 B: lower max_total to 1900", out)

    def test_a_smaller_budget_than_the_known_row_recorded_fails(self):
        for t in self.table["tasks"]:
            if t["name"] == "big":
                t["bytes"] = 1500                         # shrunk from the 2000 the row was written for
        self.table["known_findings"] = {"big": {"max_total": 1900, "bytes": 2000, "reason": "#1116"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL big: known finding was written for a 2000 B stack, the site now has 1500 B", out)

    def test_a_known_row_for_another_source_file_does_not_cover_the_task(self):
        for t in self.table["tasks"]:
            if t["name"] == "big":
                t["bytes"] = 2000
        self.table["known_findings"] = {"big": {"max_total": 1900, "bytes": 2000, "file": "main/esp_main_eth.cpp", "reason": "#1116"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)                     # the task is at src/SIP/X.cpp: not covered
        self.assertIn("FAIL big: 1900 B", out)

    def test_a_known_row_without_a_recorded_budget_is_refused(self):
        self.table["known_findings"] = {"big": {"max_total": 1900, "reason": "#1116"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("known_findings row 'big': needs", out)

    def test_a_known_row_for_a_task_that_is_not_in_the_table_fails(self):
        self.table["known_findings"] = {"renamed": {"max_total": 1900, "bytes": 4096, "reason": "#1116"}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL known_findings row 'renamed': no task of that name in the table", out)

    def test_a_failing_cycle_lists_every_member(self):
        names = [f"void Ring{i}()" for i in range(7)]
        self.add_ci("".join(node(f"r{i}", n, 8) for i, n in enumerate(names))
                    + "".join(edge(f"r{i}", f"r{(i + 1) % 7}") for i in range(7)) + edge("mid", "r0"))
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        for n in names:
            self.assertIn("        member " + n, out)

    def test_checked_in_table_has_no_duplicate_keys(self):
        # json.load keeps the last of two equal keys, so a second, empty indirect_allowlist once
        # silently replaced the filled one.
        def no_dups(pairs):
            keys = [k for k, _ in pairs]
            self.assertEqual(len(keys), len(set(keys)), sorted(k for k in keys if keys.count(k) > 1))
            return dict(pairs)
        with open(os.path.join(os.path.dirname(GATE), "task_stacks.json"), encoding="utf-8") as f:
            json.load(f, object_pairs_hook=no_dups)

    def test_checked_in_indirect_rows_cite_a_source_position(self):
        # A row is a claim about who installs a pointer; a reader checks it against the source, so each
        # reason carries a file:line (a header of the toolchain's libstdc++ counts).
        with open(os.path.join(os.path.dirname(GATE), "task_stacks.json"), encoding="utf-8") as f:
            rows = json.load(f)["indirect_allowlist"]
        bare = sorted(k for k, v in rows.items() if not re.search(r"\.\w{1,4}:\d+", v["reason"]))
        self.assertEqual(bare, [], "indirect_allowlist reasons with no file:line")

    def test_a_task_not_marked_bounded_stays_report_only(self):
        self.indirect_fixture(flag=False)
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("indirect call sites: 1 function(s) reachable", out)

    def test_known_finding_is_reported_but_only_while_it_does_not_get_worse(self):
        for t in self.table["tasks"]:
            if t["name"] == "big":
                t["bytes"] = 2000                        # 1900 + 512 margin > 2000: over budget
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)                      # control: red without a known_findings row
        self.table["known_findings"] = {"big": {"max_total": 1900, "reason": "pending measurement", "bytes": 2000}}
        rc, out = self.run_gate()
        self.assertEqual(rc, 0, out)
        self.assertIn("KNOWN big: 1900 B", out)
        self.assertIn("pending measurement", out)
        self.table["known_findings"]["big"]["max_total"] = 1800     # deeper than recorded: new
        rc, out = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertIn("a new finding", out)


if __name__ == "__main__":
    unittest.main()

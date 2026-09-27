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


# small_task -> leaf (200 + 300 = 500 B).
# big_task -> mid -> GenerateID (400 + 600 + 900 = 1900 B), with a mid <-> helper
# cycle whose cut must not be cached. The mangled title is the RequestsHandler
# shape #457 names; matching goes by the demangled label.
CI = (node("small_task", "small_task(void*)", 200) + node("leaf", "leaf()", 300)
      + node("big_task", "big_task(void*)", 400) + node("mid", "mid()", 600)
      + node("helper", "helper()", 100)
      + node("_ZN15RequestsHandler16buildOptionsPingEv", "RequestsHandler::buildOptionsPing()", 900)
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
                          {"name": "small", "entry": r"^small_task\(", "bytes": 1024, "file": "src/SIP/X.cpp", "line": 1},
                          {"name": "big", "entry": r"^big_task\(", "bytes": 4096, "file": "src/SIP/X.cpp", "line": 2}]}

    def tearDown(self):
        self.tmp.cleanup()

    def run_gate(self):
        p = os.path.join(self.tmp.name, "t.json")
        json.dump(self.table, open(p, "w"))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = g.run(self.ci, p, self.tmp.name, "main/esp_main_eth.cpp")
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
        self.table["tasks"][0]["entry"] = r"^renamed_task\("
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
            if t.get("counted", True):
                want[t["file"]] = want.get(t["file"], 0) + 1
        self.assertEqual(want, g.count_sites(g.REPO))


if __name__ == "__main__":
    unittest.main()

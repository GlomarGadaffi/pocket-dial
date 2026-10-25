"""#1117: the stack depth gate runs on every esp_main variant CI builds.

The gate (tools/ci/task_stack_gate.py) walks one image per run. A variant that no
job runs it on can overflow a task stack with CI green. This pins, at the
workflow-text level, that the stack-depth-gate job has a matrix leg for every
main/esp_main*.cpp, that each leg hands the gate its own --main, and that the gate
itself refuses a --main that is not a variant file.
"""
import glob
import os
import re
import sys
import unittest

REPO = os.path.join(os.path.dirname(__file__), "..", "..")
CI = os.path.join(REPO, ".github", "workflows", "ci.yml")
sys.path.insert(0, os.path.join(REPO, "tools", "ci"))
import task_stack_gate  # noqa: E402


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def gate_job(text):
    m = re.search(r"^  stack-depth-gate:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n)", text, re.S | re.M)
    assert m, "no stack-depth-gate job in ci.yml"
    return m.group(1)


def legs(job):
    return set(re.findall(r"^\s+main:\s*(main/esp_main\w*\.cpp)\s*$", job, re.M))


def variants():
    return {"main/" + os.path.basename(p) for p in glob.glob(os.path.join(REPO, "main", "esp_main*.cpp"))}


class AllVariantsGated(unittest.TestCase):
    def test_every_variant_has_a_leg(self):
        self.assertEqual(legs(gate_job(read(CI))), variants())

    def test_variant_left_out_is_caught(self):
        job = gate_job(read(CI))
        for v in sorted(variants()):
            cut = re.sub(r"^\s+main:\s*" + re.escape(v) + r"\s*$", "", job, flags=re.M)
            self.assertNotEqual(legs(cut), variants(), f"dropping {v} went unnoticed")

    def test_gate_step_uses_the_leg_main(self):
        job = gate_job(read(CI))
        self.assertRegex(job, r"task_stack_gate\.py[^\n]*--main \$\{\{ matrix\.main \}\}")

    def test_matrix_does_not_fail_fast(self):
        self.assertRegex(gate_job(read(CI)), r"fail-fast:\s*false")

    def test_gate_rejects_unknown_main(self):
        self.assertEqual(task_stack_gate.run(os.devnull, os.path.join(REPO, "tools", "ci", "task_stacks.json"),
                                             REPO, "main/esp_main_nope.cpp"), 1)


if __name__ == "__main__":
    unittest.main()

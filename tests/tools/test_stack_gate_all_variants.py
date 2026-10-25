"""#1117: the stack depth gate runs on every firmware image CI builds.

The gate (tools/ci/task_stack_gate.py) walks one image per run. An image that no
job runs it on can overflow a task stack with CI green. This pins, at the
workflow-text level, that the stack-depth-gate job has a matrix leg for every
main/esp_main*.cpp and for every build profile another CI job builds apart from
the default image (a job that passes -D SIP_CONSTRAINED=1 builds the constrained
profile of its transport's esp_main file), that each leg hands the gate its own
--main (and --profile), and that the gate itself refuses a --main that is not a
variant file.
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


def entries(job):
    """(text before the first matrix entry, [one text per `- chip:` entry])."""
    parts = re.split(r"(?m)^(?=\s+- chip:)", job)
    return parts[0], parts[1:]


def legs(job):
    """The images the job's matrix gates: "<main file>" or "<main file>@<profile>"."""
    out = set()
    for entry in entries(job)[1]:
        m = re.search(r"(?m)^\s+main:\s*(main/esp_main\w*\.cpp)\s*$", entry)
        p = re.search(r"(?m)^\s+profile:\s*(\w+)\s*$", entry)
        if m:
            out.add(m.group(1) + ("@" + p.group(1) if p else ""))
    return out


def variants():
    """Every esp_main file, plus the constrained profile of each transport a job builds with it."""
    out = {"main/" + os.path.basename(p) for p in glob.glob(os.path.join(REPO, "main", "esp_main*.cpp"))}
    cmake = read(os.path.join(REPO, "main", "CMakeLists.txt"))
    main_of = {t: m for t, m in re.findall(
        r'SIP_TRANSPORT STREQUAL "(\w+)"\)(?:(?!elseif|else\()[\s\S])*?set\(MAIN_SRC "(\w+\.cpp)"', cmake)}
    for job in re.split(r"(?m)^  (?=[A-Za-z0-9_-]+:\n)", read(CI)):
        if job.startswith("stack-depth-gate:"):
            continue
        if "-D SIP_CONSTRAINED=1" in job:
            t = re.search(r"-D SIP_TRANSPORT=(\w+)", job)
            out.add("main/" + main_of[t.group(1)] + "@constrained")
    return out


def without(job, image):
    """The job with the matrix entry for `image` removed."""
    head, ents = entries(job)
    main, _, prof = image.partition("@")

    def is_it(e):
        has_p = re.search(r"(?m)^\s+profile:\s*" + re.escape(prof) + r"\s*$", e) if prof else not re.search(
            r"(?m)^\s+profile:", e)
        return f"main: {main}\n" in e and has_p
    kept = [e for e in ents if not is_it(e)]
    assert len(kept) == len(ents) - 1, image
    return head + "".join(kept)


class AllVariantsGated(unittest.TestCase):
    def test_every_image_has_a_leg(self):
        self.assertEqual(legs(gate_job(read(CI))), variants())

    def test_the_constrained_profile_is_an_image(self):
        self.assertIn("main/esp_main_eth_lan8720.cpp@constrained", variants())

    def test_an_image_left_out_is_caught(self):
        job = gate_job(read(CI))
        for v in sorted(variants()):
            self.assertNotEqual(legs(without(job, v)), variants(), f"dropping {v} went unnoticed")

    def test_a_profile_left_out_is_caught(self):
        job = gate_job(read(CI))
        cut = without(job, "main/esp_main_eth_lan8720.cpp@constrained")
        self.assertNotIn("main/esp_main_eth_lan8720.cpp@constrained", legs(cut))
        self.assertIn("main/esp_main_eth_lan8720.cpp", legs(cut))      # the default lan8720 leg alone is not enough
        self.assertNotEqual(legs(cut), variants())

    def test_gate_step_uses_the_leg_main_and_profile(self):
        job = gate_job(read(CI))
        self.assertRegex(job, r"task_stack_gate\.py[^\n]*--main \$\{\{ matrix\.main \}\} \$\{\{ matrix\.gate-args \}\}")
        self.assertRegex(job, r"gate-args: --profile constrained")

    def test_matrix_does_not_fail_fast(self):
        self.assertRegex(gate_job(read(CI)), r"fail-fast:\s*false")

    def test_gate_rejects_unknown_main(self):
        self.assertEqual(task_stack_gate.run(os.devnull, os.path.join(REPO, "tools", "ci", "task_stacks.json"),
                                             REPO, "main/esp_main_nope.cpp"), 1)


if __name__ == "__main__":
    unittest.main()

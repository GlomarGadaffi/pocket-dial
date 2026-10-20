"""#457: pin where the per-task stack depth gate runs in CI.

tools/ci/task_stack_gate.py is tested on fixtures by test_task_stack_gate.py; what no
fixture can see is whether the workflow actually builds the ESP eth image with GCC's
call-graph flags and feeds its .ci files to the gate. The YAML never runs on the host, so
this reads ci.yml as text, like the other tests/tools wiring gates. Whole-line YAML
comments are dropped first: ci.yml's comments name the flags and the script too, and a
comment must not satisfy a pin.

What it pins, for the stack-depth-gate job of ci.yml:
  * it is a leaf job like the other build jobs (`needs: site-gate` only, the same `if:`,
    the matrix's IDF container), and nothing waits for it: a red gate must not skip
    hil-244, which needs build-esp-idf, and build-esp-idf itself is left as it was;
  * EXTRA_CFLAGS/EXTRA_CXXFLAGS carry the two flags in this job's build step and nowhere
    else, so no other image is built differently; that step sets the target and builds
    the eth image, so its first configure already reads them (IDF reads them only when
    CMake configures);
  * the gate runs after that build, reads build/esp-idf (not build/, which also holds the
    bootloader's .ci files) with the checkout as --project-root, and takes the default
    --main image;
  * its build cache has a key of its own, never one the shipping build restores;
  * nothing hides its red (no continue-on-error) and nothing is uploaded.
"""
import glob
import os
import re
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
JOB = "stack-depth-gate"
FLAGS = "-fcallgraph-info=su -fstack-usage"
IF = "${{ !cancelled() && needs.site-gate.outputs.code != 'false' }}"
GATE_CMD = 'python3 tools/ci/task_stack_gate.py --ci-dir build/esp-idf --project-root "$GITHUB_WORKSPACE"'


def code(path):
    """A file's text with whole-line `#` comments removed."""
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return re.sub(r"(?m)^[ \t]*#.*$", "", f.read())


def job_text(text, job):
    """One top-level job's text, from its key to the next job's."""
    head = "\n  " + job + ":\n"
    assert head in text, job + " not found in ci.yml"
    rest = text[text.index(head):]
    nxt = re.search(r"\n  [a-z][a-z0-9-]*:\n", rest[len(head) - 1:])
    return rest[:len(head) - 1 + nxt.start()] if nxt else rest


def split_job(body):
    """(job-level keys, [step text]): a step starts at `      - ` (6 spaces)."""
    header, steps = body.split("\n    steps:\n", 1)
    return header, re.split(r"\n      - ", "\n" + steps)[1:]


def step_named(steps, fragment):
    hits = [s for s in steps if re.match(r"name: .*" + re.escape(fragment), s)]
    assert len(hits) == 1, f"{len(hits)} steps named like {fragment!r}"
    return hits[0]


def expand(s):
    """A cache key as it reads on the one esp32s3/eth runner of the shipping build."""
    for k, v in (("runner.os", "Linux"), ("matrix.idf-version", "v6.0.1"), ("matrix.target-chip", "esp32s3"),
                 ("matrix.sip-transport", "eth"), ("github.sha", "0123abc")):
        s = s.replace("${{ " + k + " }}", v)
    return s


def cache_keys(step):
    key = re.search(r"(?m)^          key: (.+)$", step).group(1)
    restore = re.search(r"restore-keys: \|\n\s+(.+)", step).group(1)
    return expand(key), expand(restore)


class StackGateWiring(unittest.TestCase):
    def setUp(self):
        self.ci = code(".github/workflows/ci.yml")
        self.job = job_text(self.ci, JOB)
        self.head, self.steps = split_job(self.job)
        self.build = step_named(self.steps, "Build Firmware with call-graph flags")
        self.gate = step_named(self.steps, "Per-task stack depth gate (#457)")
        self.matrix = job_text(self.ci, "build-esp-idf")

    def test_the_job_is_a_leaf_gated_like_the_other_build_jobs(self):
        self.assertEqual(re.findall(r"(?m)^    needs: (.+)$", self.head), ["site-gate"])
        self.assertEqual(re.findall(r"(?m)^    if: (.+)$", self.head), [IF])
        self.assertEqual(re.findall(r"(?m)^    if: (.+)$", job_text(self.ci, "build-heap-poisoning")), [IF])
        self.assertIn("\n    runs-on: ubuntu-latest\n", self.head + "\n")
        # The matrix's one IDF version is this job's container.
        version = re.search(r"idf-version: \[ '([^']+)' \]", self.matrix).group(1)
        self.assertIn("\n      image: espressif/idf:" + version + "\n", self.head + "\n")

    def test_nothing_waits_for_it_and_the_matrix_job_is_untouched(self):
        # hil-244 needs build-esp-idf; a red gate must reach neither of them.
        for f in sorted(glob.glob(os.path.join(ROOT, ".github", "workflows", "*.yml"))):
            text = code(os.path.relpath(f, ROOT))
            for line in re.findall(r"(?m)^\s*needs:.*$", text):
                self.assertNotIn(JOB, line, f)
        for gone in ("EXTRA_C", "task_stack_gate", "callgraph", "stack-usage"):
            self.assertNotIn(gone, self.matrix)

    def test_the_call_graph_flags_are_set_in_this_jobs_build_step_only(self):
        # A flag set anywhere else would put it on another image.
        for var in ("EXTRA_CFLAGS", "EXTRA_CXXFLAGS"):
            with self.subTest(var=var):
                self.assertIn(f'{var}: "{FLAGS}"', self.build)
                for f in sorted(glob.glob(os.path.join(ROOT, ".github", "workflows", "*.yml"))):
                    text = code(os.path.relpath(f, ROOT))
                    self.assertEqual(text.count(var), 1 if f.endswith("ci.yml") else 0, f)
        self.assertEqual(self.ci.count("-fcallgraph-info"), 2, "one per variable, both in the build step")
        self.assertEqual(self.ci.count("-fstack-usage"), 2)
        self.assertEqual(self.build.count("-fcallgraph-info"), 2)
        self.assertNotIn("\n    env:", "\n" + self.head, "step-level env, not job-level")

    def test_the_build_sets_the_eth_target_with_the_flags_already_in_place(self):
        # IDF reads EXTRA_C*FLAGS in project.cmake when CMake configures, and set-target is the
        # first configure of this job's build dir (also with a restored cache: it always reruns CMake).
        run = self.build[self.build.index("run: |"):] + "\n"
        lines = ["          . $IDF_PATH/export.sh", "          idf.py set-target esp32s3",
                 "          idf.py -D SIP_TRANSPORT=eth build"]
        at = [run.find("\n" + ln + "\n") for ln in lines]
        self.assertNotIn(-1, at, "export.sh, set-target esp32s3 and the eth build, each on a line of its own")
        self.assertEqual(at, sorted(at))

    def test_the_gate_follows_the_build_and_reads_the_app_image_with_the_checkout_as_project_root(self):
        self.assertEqual(self.ci.count("tools/ci/task_stack_gate.py"), 1, "one run of the gate in ci.yml")
        self.assertLess(self.steps.index(self.build), self.steps.index(self.gate))
        self.assertIs(self.steps[-1], self.gate)
        self.assertIn("\n        run: " + GATE_CMD + "\n", self.gate + "\n")
        # build/ would also hold the bootloader's .ci files, which are not in the app image.
        self.assertNotRegex(self.gate, r"--ci-dir build(\s|$)")
        self.assertNotIn("env:", self.gate)

    def test_the_gate_takes_the_eth_image_by_default(self):
        # The job builds esp32s3/eth and the step passes no --main, so the default must be the eth image.
        self.assertNotIn("--main", self.gate)
        with open(os.path.join(ROOT, "tools", "ci", "task_stack_gate.py"), encoding="utf-8") as f:
            m = re.search(r'"--main",\s*default="([^"]+)"', f.read())
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "main/esp_main_eth.cpp")

    def test_the_cache_key_is_its_own_and_the_shipping_build_never_restores_it(self):
        mine, mine_restore = cache_keys(step_named(self.steps, "Cache ESP-IDF Build Artifacts"))
        ship, ship_restore = cache_keys(step_named(split_job(self.matrix)[1], "Cache ESP-IDF Build Artifacts"))
        self.assertIn("callgraph-su", mine, "the key names the flags")
        self.assertTrue(mine.startswith(mine_restore), "restore-keys is a prefix of the key")
        self.assertNotIn("callgraph", ship)
        # Neither restores the other's cache: restore-keys match by prefix.
        self.assertFalse(mine.startswith(ship_restore), (mine, ship_restore))
        self.assertFalse(ship.startswith(mine_restore), (ship, mine_restore))
        self.assertNotEqual(mine, ship)

    def test_nothing_hides_the_red_and_nothing_is_uploaded(self):
        self.assertNotIn("continue-on-error", self.job)
        self.assertNotIn("upload-artifact", self.job)


if __name__ == "__main__":
    unittest.main()

"""cmake/FirmwareVersion.cmake, driven for real in a throwaway git repo (#461 review).

Run: python3 -m unittest discover -s tests/tools -p "test_*.py"

Pins the three things a code read cannot prove:
  * a -DPOCKETDIAL_FW_VERSION override lands in the generated header and does
    NOT stay in CMakeCache.txt (it used to stick and stamp every later build);
  * after a new commit, the next build reconfigures and the header follows git;
  * a stamp outside [A-Za-z0-9._+-] fails the configure, because /api/status
    streams the version into JSON raw, with no per-request escaping.
Skipped when cmake or git is not on PATH.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))

PROJECT = """cmake_minimum_required(VERSION 3.16)
project(fwver_probe NONE)
include(${CMAKE_SOURCE_DIR}/cmake/FirmwareVersion.cmake)
pocketdial_firmware_version(V)
pocketdial_write_fw_version_header("${V}")
add_custom_target(probe ALL)
"""


def have(tool):
    return shutil.which(tool) is not None


@unittest.skipUnless(have("cmake") and have("git"), "needs cmake and git")
class FirmwareVersionCmakeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fwver-")
        self.src = os.path.join(self.tmp, "src")
        self.build = os.path.join(self.tmp, "build")
        os.makedirs(os.path.join(self.src, "cmake"))
        for f in ("FirmwareVersion.cmake", "FirmwareVersionMaxLen.txt"):
            shutil.copy(os.path.join(REPO, "cmake", f), os.path.join(self.src, "cmake", f))
        with open(os.path.join(self.src, "CMakeLists.txt"), "w") as fh:
            fh.write(PROJECT)
        self.git("init", "-q")
        self.git("add", "-A")
        self.commit("first")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def git(self, *args):
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
        return subprocess.check_output(["git", "-C", self.src, *args], text=True, env=env).strip()

    def commit(self, msg):
        self.git("commit", "-q", "--allow-empty", "-m", msg)

    def cmake(self, *args, check=True):
        return subprocess.run(["cmake", "-S", self.src, "-B", self.build, *args],
                              capture_output=True, text=True, check=check)

    def header(self):
        with open(os.path.join(self.build, "generated", "pocketdial_fw_version.h")) as fh:
            m = re.search(r'#define POCKETDIAL_FW_VERSION "([^"]*)"', fh.read())
        return m.group(1) if m else None

    def cache_has_override(self):
        with open(os.path.join(self.build, "CMakeCache.txt")) as fh:
            return any(line.startswith("POCKETDIAL_FW_VERSION:") for line in fh)

    def test_an_override_is_stamped_once_and_never_cached(self):
        self.cmake("-DPOCKETDIAL_FW_VERSION=v9.9.9")
        self.assertEqual(self.header(), "v9.9.9")
        self.assertFalse(self.cache_has_override(),
                         "a -D override must not stay in CMakeCache.txt and stamp later builds")

    def test_after_a_commit_the_next_build_restamps_from_git(self):
        self.cmake("-DPOCKETDIAL_FW_VERSION=v9.9.9")
        self.commit("second")
        head = self.git("rev-parse", "--short=7", "HEAD")
        subprocess.run(["cmake", "--build", self.build], capture_output=True, text=True, check=True)
        stamp = self.header()
        self.assertNotEqual(stamp, "v9.9.9", "the override must not survive a commit")
        self.assertTrue(stamp.startswith(head), f"header {stamp!r} does not name HEAD {head}")

    def test_a_stamp_that_is_not_json_safe_fails_the_configure(self):
        for bad in ('v1"x', "v1 x", "v1\\x", "v1<x>"):
            with self.subTest(stamp=bad):
                shutil.rmtree(self.build, ignore_errors=True)
                r = self.cmake("-DPOCKETDIAL_FW_VERSION=" + bad, check=False)
                self.assertNotEqual(r.returncode, 0, f"{bad!r} was accepted:\n{r.stdout}{r.stderr}")

    # #384 (H1): the bench probe image passes a "-probe" suffix (top-level
    # CMakeLists.txt), so its stamp never equals this checkout's release stamp.
    def use_suffix(self, suffix):
        with open(os.path.join(self.src, "CMakeLists.txt"), "w") as fh:
            fh.write(PROJECT.replace("pocketdial_firmware_version(V)",
                                     f'pocketdial_firmware_version(V "{suffix}")'))
        self.git("add", "-A")
        self.commit("suffix")

    def test_a_probe_suffix_is_stamped_ahead_of_dirty(self):
        self.use_suffix("-probe")
        self.git("tag", "v1.5.0")
        self.cmake()
        self.assertEqual(self.header(), "v1.5.0-probe")
        with open(os.path.join(self.src, "CMakeLists.txt"), "a") as fh:
            fh.write("# dirty\n")
        shutil.rmtree(self.build, ignore_errors=True)
        self.cmake()
        self.assertEqual(self.header(), "v1.5.0-probe-dirty",
                         "-dirty stays last, where every dirty check looks for it")

    def test_a_probe_suffix_that_would_overflow_falls_back_to_the_hash(self):
        self.use_suffix("-probe")
        tag = "v1.5.0-beta.22-" + "x" * 13   # 28 chars: fits alone, not with -probe
        self.git("tag", tag)
        head = self.git("rev-parse", "--short=7", "HEAD")
        self.cmake()
        self.assertEqual(self.header(), head + "-probe")


class NoDirectoryWideDefineTest(unittest.TestCase):
    # #461 fix 3: the stamp reaches host code only through the generated
    # header. A directory-wide define would put it on every compile line and
    # rebuild the world on each commit.
    def test_no_cmakelists_adds_the_version_as_a_compile_definition(self):
        hits = []
        for root, dirs, files in os.walk(REPO):
            dirs[:] = [d for d in dirs if not d.startswith((".", "build"))]
            if "CMakeLists.txt" in files:
                path = os.path.join(root, "CMakeLists.txt")
                with open(path, encoding="utf-8", errors="replace") as fh:
                    if re.search(r"add_compile_definitions\([^)]*POCKETDIAL_FW_VERSION", fh.read()):
                        hits.append(path)
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()

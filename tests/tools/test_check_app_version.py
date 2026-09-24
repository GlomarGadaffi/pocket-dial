"""Tests for tools/ci/check_app_version.py (issue #411).

Run: python3 -m unittest discover -s tests/tools -p "test_*.py"

Every case builds a real throwaway git repository and a synthetic ESP app image
(image magic 0xE9, esp_app_desc_t magic at offset 32, version char[32] at +16),
so the gate runs its actual git calls and its actual descriptor parse. Nothing
is mocked.

The over-length cases matter most. ESP-IDF truncates a long PROJECT_VER from
the END, which is where "-dirty" lives, so a stamp can silently lose the one
flag that says the build was not a clean commit. The gate must accept the
<hash>[-dirty] fallback, and must REJECT the truncated form IDF would produce.
"""

import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools", "ci"))
import check_app_version as gate  # noqa: E402

MAX_LEN = gate.read_max_len()  # the shared definition, not a copy of the number
LONG_TAG = "v1.5.0-beta.2-an-extremely-long-release-tag"


def run(repo, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
    return subprocess.run(["git", "-C", repo, *args], check=True, text=True,
                          capture_output=True, env=env).stdout.strip()


def make_image(path, version):
    raw = version.encode("ascii")
    if len(raw) > 31:
        raise ValueError("a real app descriptor cannot hold more than 31 chars")
    img = bytearray(512)
    img[0] = gate.IMAGE_MAGIC
    struct.pack_into("<I", img, gate.APP_DESC_OFFSET, gate.APP_DESC_MAGIC)
    img[gate.APP_DESC_OFFSET + 16:gate.APP_DESC_OFFSET + 16 + len(raw)] = raw
    img[gate.APP_DESC_OFFSET + 48:gate.APP_DESC_OFFSET + 48 + 9] = b"SipServer"
    with open(path, "wb") as f:
        f.write(img)


class GateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pd411-")
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.repo)
        run(self.repo, "init", "-q")
        with open(os.path.join(self.repo, "f.txt"), "w") as f:
            f.write("one\n")
        run(self.repo, "add", "f.txt")
        run(self.repo, "commit", "-qm", "one")
        self.img = os.path.join(self.tmp, "SipServer.bin")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def commit(self, msg):
        with open(os.path.join(self.repo, "f.txt"), "a") as f:
            f.write(msg + "\n")
        run(self.repo, "commit", "-qam", msg)

    def dirty(self):
        with open(os.path.join(self.repo, "f.txt"), "a") as f:
            f.write("uncommitted\n")

    def stamp(self):
        return gate.expected_version(self.repo, MAX_LEN)

    def assertGatePasses(self, version, **kw):
        make_image(self.img, version)
        gate.check(self.img, repo=self.repo, **kw)

    def assertGateFails(self, version, needle, **kw):
        make_image(self.img, version)
        with self.assertRaises(gate.GateFailure) as ctx:
            gate.check(self.img, repo=self.repo, **kw)
        self.assertIn(needle, str(ctx.exception))

    # ── the shared definition ────────────────────────────────────────────────

    def test_shared_limit_is_the_descriptor_field_minus_the_nul(self):
        self.assertEqual(MAX_LEN, gate.APP_DESC_VERSION_FIELD - 1)

    def test_a_limit_file_that_disagrees_with_the_struct_is_refused(self):
        bad = os.path.join(self.tmp, "len.txt")
        with open(bad, "w") as f:
            f.write("30\n")
        with self.assertRaises(gate.GateFailure):
            gate.read_max_len(bad)

    # ── ordinary stamps ──────────────────────────────────────────────────────

    def test_short_tag_describe_passes_when_it_is_exactly_this_commit(self):
        run(self.repo, "tag", "v1.5.0")
        self.commit("two")
        s = self.stamp()
        self.assertRegex(s, r"^v1\.5\.0-1-g[0-9a-f]{7,}$")
        self.assertGatePasses(s)

    def test_fallbacks_fail(self):
        for v in ("1", "unknown"):
            with self.subTest(version=v):
                self.assertGateFails(v, "a fallback")

    def test_a_stamp_from_an_older_commit_fails(self):
        run(self.repo, "tag", "v1.5.0")
        self.commit("two")
        old = self.stamp()
        self.commit("three")
        self.assertGateFails(old, "stamps as")

    def test_a_stamp_that_never_reached_the_image_fails(self):
        chosen = os.path.join(self.tmp, "chosen.txt")
        with open(chosen, "w") as f:
            f.write("v9.9.9-1-gabcdef0")
        make_image(self.img, "v1.0.0-1-g1234567")
        with self.assertRaises(gate.GateFailure) as ctx:
            gate.check(self.img, chosen_path=chosen)
        self.assertIn("did not reach the binary", str(ctx.exception))

    # ── over-length: the reason the fallback exists ─────────────────────────

    def test_over_length_describe_expects_the_hash_fallback(self):
        run(self.repo, "tag", LONG_TAG)
        self.commit("two")
        full = run(self.repo, "describe", "--tags", "--always", "--dirty")
        self.assertGreater(len(full), MAX_LEN, "precondition: describe really is over-length")
        s = self.stamp()
        self.assertRegex(s, r"^[0-9a-f]{7,}$")
        self.assertIn("g" + s, full, "the hash fallback must be a prefix of describe's -g<hash>")
        self.assertGatePasses(s)

    def test_over_length_dirty_keeps_the_flag_in_the_fallback(self):
        run(self.repo, "tag", LONG_TAG)
        self.commit("two")
        self.dirty()
        s = self.stamp()
        self.assertTrue(s.endswith("-dirty"), s)
        self.assertLessEqual(len(s), MAX_LEN)
        self.assertGatePasses(s)

    def test_the_truncated_stamp_IDF_would_produce_is_rejected(self):
        # What ESP-IDF itself would do with an over-length PROJECT_VER: keep the
        # first 31 characters. Here that CUTS OFF "-dirty" -- a dirty build that
        # would read as a clean one. The gate must refuse it.
        run(self.repo, "tag", LONG_TAG)
        self.commit("two")
        self.dirty()
        full = run(self.repo, "describe", "--tags", "--always", "--dirty")
        self.assertTrue(full.endswith("-dirty"))
        truncated = full[:MAX_LEN]
        self.assertFalse(truncated.endswith("-dirty"), "precondition: truncation drops the flag")
        self.assertGateFails(truncated, "stamps as")

    def test_a_short_describe_padded_past_the_limit_by_dirty_uses_the_fallback(self):
        # Clean describe fits, but "-dirty" pushes it over: the rule must switch
        # to the fallback in exactly that case, as CMake does.
        tag = "v" + "1" * (MAX_LEN - len("-1-g1234567") - 2)
        run(self.repo, "tag", tag)
        self.commit("two")
        clean = run(self.repo, "describe", "--tags", "--always")
        self.dirty()
        dirty_full = run(self.repo, "describe", "--tags", "--always", "--dirty")
        if len(clean) > MAX_LEN or len(dirty_full) <= MAX_LEN:
            self.skipTest(f"could not construct the boundary case ({len(clean)}, {len(dirty_full)})")
        s = self.stamp()
        self.assertRegex(s, r"^[0-9a-f]{7,}-dirty$")
        self.assertGatePasses(s)
        self.assertGateFails(dirty_full[:MAX_LEN], "stamps as")

    # ── the exact boundary (an off-by-one here is silent) ───────────────────

    def _tag_giving_describe_length(self, n):
        # describe one commit past a tag = <tag> + "-1-g" + <7 hex> = tag + 11.
        return "v" + "x" * (n - 11 - 1)

    def test_a_describe_of_exactly_the_limit_is_kept_whole(self):
        run(self.repo, "tag", self._tag_giving_describe_length(MAX_LEN))
        self.commit("two")
        full = run(self.repo, "describe", "--tags", "--always", "--dirty")
        self.assertEqual(len(full), MAX_LEN, "precondition: exactly at the limit")
        self.assertEqual(self.stamp(), full)
        self.assertGatePasses(full)

    def test_a_describe_one_past_the_limit_falls_back(self):
        run(self.repo, "tag", self._tag_giving_describe_length(MAX_LEN + 1))
        self.commit("two")
        full = run(self.repo, "describe", "--tags", "--always", "--dirty")
        self.assertEqual(len(full), MAX_LEN + 1, "precondition: one past the limit")
        s = self.stamp()
        self.assertRegex(s, r"^[0-9a-f]{7,}$")
        self.assertGatePasses(s)

    # ── equality, not containment ───────────────────────────────────────────

    def test_an_image_claiming_clean_from_a_dirty_checkout_fails(self):
        # The case a "one string contains the other" rule lets through: the
        # checkout stamps as "<x>-dirty", the image says "<x>". A build that
        # modified a tracked file -- or a stale clean image -- must not pass.
        run(self.repo, "tag", "v1.5.0")
        self.commit("two")
        clean = self.stamp()
        self.dirty()
        self.assertEqual(self.stamp(), clean + "-dirty", "precondition")
        self.assertGateFails(clean, "stamps as")

    # ── release builds ───────────────────────────────────────────────────────

    def test_a_clean_build_on_a_release_tag_passes(self):
        run(self.repo, "tag", "v1.6.0")
        self.assertEqual(self.stamp(), "v1.6.0")
        self.assertGatePasses("v1.6.0")

    def test_a_dirty_build_on_a_release_tag_fails(self):
        run(self.repo, "tag", "v1.6.0")
        self.dirty()
        s = self.stamp()
        self.assertEqual(s, "v1.6.0-dirty")
        self.assertGateFails(s, "a release image must be clean")

    def test_a_dirty_build_past_a_release_tag_is_only_a_normal_build(self):
        # Not ON the tag: an ordinary development build, which may be dirty.
        run(self.repo, "tag", "v1.6.0")
        self.commit("two")
        self.dirty()
        self.assertGatePasses(self.stamp())


if __name__ == "__main__":
    unittest.main()

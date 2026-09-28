#!/usr/bin/env python3
"""Fail the build unless the firmware image identifies the commit it was built from.

Issue #411. Every image used to carry version "1", ESP-IDF's fallback when
nothing sets PROJECT_VER, because `git describe` failed inside CI's build
container ("dubious ownership"). cmake/FirmwareVersion.cmake now decides the
stamp. This checks that it really reached the IMAGE, and that it is exactly the
stamp this checkout should produce:

  1. The image's esp_app_desc_t.version is not a fallback ("", "1", "unknown").
  2. It equals what CMake chose (<build>/pocketdial_fw_version.txt). Otherwise
     the stamp was decided but never reached the binary.
  3. It EQUALS the stamp this checkout produces under the SAME rule CMake
     applies (expected_version() below): the full `git describe --tags
     --always --dirty` when it fits, else `<hash>[-dirty]`. The length limit
     is read from cmake/FirmwareVersionMaxLen.txt, the one file CMake reads
     too, so the two cannot disagree about when the fallback applies.
     Equality rather than "contains": this job restores a cached build/, and
     a plausible stamp from a stale build would pass a looser test.
  4. A build sitting exactly on a release tag must not be -dirty. A release
     image that says "v1.6.0-dirty" is not v1.6.0.

The descriptor is read straight from the image, not from an ELF or a log:
24-byte image header + 8-byte first-segment header puts esp_app_desc_t at
offset 32, magic 0xABCD5432, with version as char[32] at +16.
"""

import argparse
import os
import struct
import subprocess
import sys

IMAGE_MAGIC = 0xE9
APP_DESC_OFFSET = 32
APP_DESC_MAGIC = 0xABCD5432
APP_DESC_VERSION_FIELD = 32          # esp_app_desc_t.version is char[32]
FALLBACKS = {"", "1", "unknown"}

MAX_LEN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "..", "cmake", "FirmwareVersionMaxLen.txt")


class GateFailure(Exception):
    pass


def fail(msg):
    raise GateFailure(msg)


def read_max_len(path=MAX_LEN_FILE):
    with open(path, encoding="utf-8") as f:
        text = f.read().strip()
    if not text.isdigit():
        fail(f"{path} must hold a single number, got {text!r}")
    n = int(text)
    # The shared number must also agree with the struct it exists to fit.
    if n != APP_DESC_VERSION_FIELD - 1:
        fail(f"{path} says {n}, but esp_app_desc_t.version is char[{APP_DESC_VERSION_FIELD}] "
             f"(room for {APP_DESC_VERSION_FIELD - 1})")
    return n


def cstr(buf, off, size):
    return buf[off:off + size].split(b"\0", 1)[0].decode("ascii", "replace")


def read_app_desc(path):
    with open(path, "rb") as f:
        data = f.read(APP_DESC_OFFSET + 256)
    if len(data) < APP_DESC_OFFSET + 176:
        fail(f"{path} is too short to be an ESP app image ({len(data)} bytes)")
    if data[0] != IMAGE_MAGIC:
        fail(f"{path} is not an ESP app image (first byte {data[0]:#04x}, expected {IMAGE_MAGIC:#04x})")
    (magic,) = struct.unpack_from("<I", data, APP_DESC_OFFSET)
    if magic != APP_DESC_MAGIC:
        fail(f"no app descriptor at offset {APP_DESC_OFFSET} of {path} "
             f"(magic {magic:#010x}, expected {APP_DESC_MAGIC:#010x})")
    d = APP_DESC_OFFSET
    return {
        "version": cstr(data, d + 16, 32),
        "project": cstr(data, d + 48, 32),
        "time":    cstr(data, d + 80, 16),
        "date":    cstr(data, d + 96, 16),
        "idf":     cstr(data, d + 112, 32),
    }


def git(repo, *args):
    # Same scoping as cmake/FirmwareVersion.cmake: safe.directory on THIS
    # command only (this runs in the same root-owned container), fsmonitor off.
    cmd = ["git", "-c", f"safe.directory={repo}", "-c", "core.fsmonitor=false",
           "-C", repo, *args]
    return subprocess.run(cmd, text=True, capture_output=True)


def expected_version(repo, max_len):
    """The stamp cmake/FirmwareVersion.cmake produces for this checkout -- same rule."""
    full = git(repo, "describe", "--tags", "--always", "--dirty")
    if full.returncode != 0 or not full.stdout.strip():
        fail(f"cannot describe this checkout to compare against: {full.stderr.strip()}")
    full = full.stdout.strip()
    if len(full) <= max_len:
        return full
    short = git(repo, "describe", "--always", "--dirty", "--abbrev=7", "--exclude=*")
    if short.returncode != 0 or not short.stdout.strip():
        fail(f"cannot describe this checkout (hash form): {short.stderr.strip()}")
    return short.stdout.strip()


def exact_release_tag(repo):
    """The v* tag HEAD sits exactly on, or None."""
    r = git(repo, "describe", "--tags", "--exact-match", "HEAD")
    tag = r.stdout.strip() if r.returncode == 0 else ""
    return tag if tag.startswith("v") else None


def check(bin_path, chosen_path=None, repo=None, max_len_path=MAX_LEN_FILE):
    """Run every check; return the list of 'ok' lines. Raises GateFailure."""
    oks = []
    max_len = read_max_len(max_len_path)
    desc = read_app_desc(bin_path)
    v = desc["version"]
    oks.append(f"image: version='{v}' project='{desc['project']}' idf='{desc['idf']}' "
               f"built='{desc['date']} {desc['time']}'")

    if v in FALLBACKS:
        fail(f"the image's version is '{v}', a fallback: no build can be identified from "
             f"a board running it. Was PROJECT_VER set before project()? (#411)")

    if chosen_path:
        with open(chosen_path, encoding="utf-8") as f:
            chosen = f.read().strip()
        if v != chosen:
            fail(f"CMake chose '{chosen}' but the image carries '{v}': the stamp did not reach the binary")
        oks.append(f"ok: image version matches CMake's choice ('{chosen}')")

    if repo:
        want = expected_version(repo, max_len)
        if v != want:
            fail(f"the image says '{v}' but this checkout stamps as '{want}' "
                 f"(limit {max_len} chars): a stale build directory, a build of a different "
                 f"commit, or a build that modified a tracked file")
        oks.append(f"ok: image carries exactly this checkout's stamp ('{want}')")

        tag = exact_release_tag(repo)
        if tag and v.endswith("-dirty"):
            fail(f"release build on tag '{tag}' is stamped '{v}': a release image must be clean")
        if tag:
            oks.append(f"ok: release tag '{tag}', clean")
    return oks


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bin", required=True, help="the built app image, e.g. build/SipServer.bin")
    ap.add_argument("--chosen", help="build/pocketdial_fw_version.txt (what CMake chose)")
    ap.add_argument("--repo", help="the checkout, to derive the expected stamp from")
    args = ap.parse_args()
    try:
        for line in check(args.bin, args.chosen, args.repo):
            print(line)
    except GateFailure as e:
        print(f"::error title=firmware version (#411)::{e}")
        print(f"FAIL: {e}", file=sys.stderr)
        sys.exit(1)
    print("PASS: the firmware identifies its build")


if __name__ == "__main__":
    main()

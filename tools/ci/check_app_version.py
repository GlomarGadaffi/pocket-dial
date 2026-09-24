#!/usr/bin/env python3
"""Fail the build unless the firmware image identifies the commit it was built from.

Issue #411. Every image used to carry version "1", ESP-IDF's fallback when
nothing sets PROJECT_VER, because `git describe` failed inside CI's build
container ("dubious ownership"). cmake/FirmwareVersion.cmake now decides the
stamp. This checks that it really reached the IMAGE, and that it names THIS
checkout's commit:

  1. The image's esp_app_desc_t.version is not a fallback ("", "1", "unknown").
  2. It equals what CMake chose (<build>/pocketdial_fw_version.txt). Otherwise
     the stamp was decided but never reached the binary.
  3. It names this checkout's commit, by the same substring test
     tests/run.py's board-provenance check applies. "Not 1" alone would pass a
     plausible-looking stamp from a stale build directory or the wrong commit.

A "-dirty" stamp is reported as a warning, not a failure. CI's checkout should
be clean, so a dirty stamp means the build modified a tracked file. That is
worth seeing, but it is not this gate's question.

The descriptor is read straight from the image, not from an ELF or a log:
24-byte image header + 8-byte first-segment header puts esp_app_desc_t at
offset 32, magic 0xABCD5432, with version as char[32] at +16.
"""

import argparse
import struct
import subprocess
import sys

IMAGE_MAGIC = 0xE9
APP_DESC_OFFSET = 32
APP_DESC_MAGIC = 0xABCD5432
FALLBACKS = {"", "1", "unknown"}


def fail(msg):
    print(f"::error title=firmware version (#411)::{msg}")
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


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


def checkout_describe(repo):
    # Same scoping as cmake/FirmwareVersion.cmake: safe.directory on THIS
    # command only (this runs in the same root-owned container), fsmonitor off.
    cmd = ["git", "-c", f"safe.directory={repo}", "-c", "core.fsmonitor=false",
           "-C", repo, "describe", "--tags", "--always"]
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE).strip()
    except (OSError, subprocess.CalledProcessError) as e:
        err = getattr(e, "stderr", "") or str(e)
        fail(f"cannot read this checkout's commit to compare against: {err.strip()}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bin", required=True, help="the built app image, e.g. build/SipServer.bin")
    ap.add_argument("--chosen", help="build/pocketdial_fw_version.txt (what CMake chose)")
    ap.add_argument("--repo", help="the checkout, to compare the commit against")
    args = ap.parse_args()

    desc = read_app_desc(args.bin)
    v = desc["version"]
    print(f"image: version='{v}' project='{desc['project']}' idf='{desc['idf']}' "
          f"built='{desc['date']} {desc['time']}'")

    if v in FALLBACKS:
        fail(f"the image's version is '{v}', a fallback: no build can be identified from "
             f"a board running it. Was PROJECT_VER set before project()? (#411)")

    if args.chosen:
        with open(args.chosen, encoding="utf-8") as f:
            chosen = f.read().strip()
        if v != chosen:
            fail(f"CMake chose '{chosen}' but the image carries '{v}': the stamp did not reach the binary")
        print(f"ok: image version matches CMake's choice ('{chosen}')")

    if args.repo:
        head = checkout_describe(args.repo)
        bare = v[:-len("-dirty")] if v.endswith("-dirty") else v
        # tests/run.py's rule: either string contains the other. A bare-hash
        # stamp (describe too long for the descriptor) is a prefix of describe's
        # -g<hash>, so it matches too.
        if not (head in bare or bare in head):
            fail(f"the image says '{v}' but this checkout is '{head}': "
                 f"a stale build directory, or a build of a different commit")
        print(f"ok: image names this checkout's commit ('{head}')")
        if v.endswith("-dirty"):
            print(f"::warning title=firmware version (#411)::the image is stamped '{v}': "
                  f"the build modified a tracked file")

    print("PASS: the firmware identifies its build")


if __name__ == "__main__":
    main()

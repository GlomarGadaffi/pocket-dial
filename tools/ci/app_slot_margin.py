#!/usr/bin/env python3
"""App-slot margin check (issue #489).

    python3 tools/ci/app_slot_margin.py <build_dir>

Reads the partition table the build actually produced
(<build_dir>/partition_table/partition-table.bin, decoded with ESP-IDF's
gen_esp32part.py) and compares its smallest app partition with
<build_dir>/SipServer.bin. So the constrained 4 MB layout (partitions_4mb.csv,
0x1E0000 slots) and the 16 MB one (0x600000) are each checked against their
own slots.

Fails (exit 1) below FAIL_BELOW bytes free -- a fix-forward OTA may no longer
fit -- and warns below WARN_BELOW. Both thresholds live here and nowhere else.
Every error path fails closed: a missing image, an undecodable table, or a
table with no app partition is an error, never a pass.
"""
import os
import subprocess
import sys

FAIL_BELOW = 32 * 1024   # fail: a fix-forward OTA may no longer fit
WARN_BELOW = 64 * 1024   # warn: time to trim or change the layout


def parse_size(text):
    """gen_esp32part's size column: '6M', '1920K', '0x1e0000' or decimal."""
    s = text.strip()
    mult = 1
    if s[-1:] in ("K", "k"):
        mult, s = 1024, s[:-1]
    elif s[-1:] in ("M", "m"):
        mult, s = 1024 * 1024, s[:-1]
    return int(s, 0) * mult


def app_slots(csv_text):
    """(name, size) for every 'app' partition in gen_esp32part's CSV output."""
    slots = []
    for line in csv_text.splitlines():
        fields = [f.strip() for f in line.split(",")]
        if len(fields) >= 5 and fields[0] and not fields[0].startswith("#") and fields[1] == "app":
            slots.append((fields[0], parse_size(fields[4])))
    return slots


def verdict(app_bytes, slot_bytes):
    """'fail' | 'warn' | 'ok' for an image of app_bytes in a slot of slot_bytes."""
    free = slot_bytes - app_bytes
    if free < FAIL_BELOW:
        return "fail"
    if free < WARN_BELOW:
        return "warn"
    return "ok"


def main(argv):
    if len(argv) != 2:
        print("usage: app_slot_margin.py <build_dir>", file=sys.stderr)
        return 2
    build = argv[1]
    app = os.path.getsize(os.path.join(build, "SipServer.bin"))
    gen = os.path.join(os.environ["IDF_PATH"], "components", "partition_table", "gen_esp32part.py")
    csv_text = subprocess.run(
        [sys.executable, gen, os.path.join(build, "partition_table", "partition-table.bin")],
        capture_output=True, text=True, check=True).stdout
    slots = app_slots(csv_text)
    if not slots:
        print("::error::no app partition found in the built partition table (issue #489)")
        return 1
    name, slot = min(slots, key=lambda s: s[1])
    free = slot - app
    line = ("app slot [%s]: SipServer.bin %d B in %s (%d B): %d B free (%.1f %%)"
            % (build, app, name, slot, free, 100.0 * free / slot))
    print(line)
    with open(os.environ.get("GITHUB_STEP_SUMMARY", os.devnull), "a") as summary:
        summary.write("- " + line + "\n")
    v = verdict(app, slot)
    if v == "fail":
        print("::error::app slot margin %d B is below the %d B floor (issue #489)" % (free, FAIL_BELOW))
        return 1
    if v == "warn":
        print("::warning::app slot margin %d B is below %d B: trim or change the layout (issue #489)"
              % (free, WARN_BELOW))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

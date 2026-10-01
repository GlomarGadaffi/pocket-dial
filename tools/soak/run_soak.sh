#!/usr/bin/env bash
# tools/soak/run_soak.sh -- the #401 release smoke / soak run (item 0.2).
#
#   run_soak.sh --profile post-ota|smoke|soak --host <rig-ip> --holder <name>
#               --image <app.bin> --image-sha256 <hex> [--ota | --full-flash]
#               --checkout-url <#428 comment link> --checkout-expiry <ISO-8601>
#               --exts <4 test extensions> --owner-ext <owner extensions>
#               [--duration <s>] [--uhubctl-loc <hub> --uhubctl-port <n>]
#               [--full-flash: --serial-port <by-id path> --skip-flash-backup --boot-cmd "<cmd>"]
#               [--out <dir>] [--dry-run]
#
# Runs on the rig host (glolab), next to the logger and the load. The OTA path
# never opens serial; only --full-flash backs up nvs and coredump over serial.
# Claim the rig first (tools/soak/rig_checkout.sh claim) and post the CHECK-OUT;
# this run always releases it with the verdict, also on SIGINT/SIGTERM.
# Exit: 0 PASS, 1 FAIL, 2 refused, 3 INVALID, 4 ABORTED, 5 NEEDS-HUMAN.
# Everything else is in run_soak.py.
exec python3 "$(cd "$(dirname "$0")" && pwd)/run_soak.py" "$@"

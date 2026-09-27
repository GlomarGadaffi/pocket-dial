#!/usr/bin/env bash
# #401 soak: poll /api/status about once a second and append one JSON object
# per line:
#     {"t":<unix seconds>,"s":<the status body, or null if the poll failed>}
# tools/soak/soak_verdict.py reads that file and prints the verdict.
#
# Unauthenticated on purpose: every field the verdict judges (uptime,
# resetReason, heap, stackHwm_*, sessions, parkedCalls, coredump) is on the
# public route, so no credential is ever on this command line or in the log.
# One connection at a time, so it never competes for the HTTP slots (#534).
#
# Usage: tools/soak/status_logger.sh <board-ip> <out.jsonl>     (Ctrl-C stops)
set -u
host="${1:?usage: status_logger.sh <board-ip> <out.jsonl>}"
out="${2:?usage: status_logger.sh <board-ip> <out.jsonl>}"
while :; do
    t=$(date -u +%s)
    body=$(curl -s -m 2 "http://${host}/api/status" | tr -d '\r\n')
    case "$body" in
        \{*\}) printf '{"t":%s,"s":%s}\n' "$t" "$body" >> "$out" ;;
        *)     printf '{"t":%s,"s":null}\n' "$t" >> "$out" ;;
    esac
    sleep 1
done

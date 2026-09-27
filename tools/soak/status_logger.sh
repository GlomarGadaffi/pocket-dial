#!/usr/bin/env bash
# #401 soak: poll /api/status about once a second and append one JSON object
# per line:
#     {"t":<unix seconds>,"s":<the status body, or null if the poll failed>}
# A failed poll also records the HTTP code when there was one ("code"): a 503
# busy refusal (#368/#534) or a 429 is a JSON object too, and must count as a
# failed poll, never as a status sample (#537 review).
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
nl='
'
while :; do
    t=$(date -u +%s)
    # The status code goes on its own last line, after the body.
    resp=$(curl -s -m 2 -w "${nl}%{http_code}" "http://${host}/api/status")
    code=${resp##*"$nl"}
    body=$(printf '%s' "${resp%"$nl"*}" | tr -d '\r\n')
    case "$code" in
        ''|*[!0-9]*) code=0 ;;
        *) code=$((10#$code)) ;;   # curl prints 000 when nothing answered; keep the JSON valid
    esac
    if [ "$code" = "200" ]; then
        case "$body" in
            \{*\}) printf '{"t":%s,"s":%s}\n' "$t" "$body" >> "$out" ;;
            *)     printf '{"t":%s,"s":null,"code":200}\n' "$t" >> "$out" ;;
        esac
    else
        printf '{"t":%s,"s":null,"code":%s}\n' "$t" "$code" >> "$out"
    fi
    sleep 1
done

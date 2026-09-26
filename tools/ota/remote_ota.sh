#!/usr/bin/env bash
# tools/ota/remote_ota.sh -- a remote OTA of one pocket-dial board over the LAN,
# stage by stage, with a STOP rule at every step (issue #395).
#
# Written for the first real OTA of a board NOBODY CAN PHYSICALLY RESET: every
# stage checks the board's state before and after, and anything unexpected
# stops the run and leaves the board exactly as it is. Nothing retries.
#
#   remote_ota.sh [--dry-run] --host <ip> --stage <0|2|3> [--image <app.bin>]
#                 [--wrong-chip <other-chip.bin>] [--expect-version <str>]
#                 [--timeout <s>]
#
#   0  precheck (read-only): /api/ota/status + /api/status baseline. No login.
#   2  safe refusals: a truncated image and a wrong-chip image must be REFUSED,
#      with no reboot (uptime keeps rising) and boot == running unchanged.
#   3  the real OTA: upload -> 200 "staged" -> POST /api/ota/reboot -> poll
#      until back (timeout) -> version == --expect-version -> pendingVerify
#      seen, then cleared by the health gate. `pendingVerify=true` seen right
#      after boot is the ONLY remote proof the bootloader has rollback.
#   (4, the rollback test, needs a self-restarting probe image; not here yet.)
#
# Credentials: the OWNER admin login, from PD_OTA_USER / PD_OTA_PASS, or typed
# at a hidden prompt. They go to curl on STDIN only -- never argv (visible in
# ps), never a URL, never a log line. The session cookie lives in a 0600 temp
# dir deleted on exit; the session is logged out at the end.
#
# --dry-run: performs only the read-only GETs and prints what each stage would
# send. Upload ONLY esp32s3-eth images to an eth board: a wifi image passes the
# chip check but boots with no network, and there is no remote way back.

set -u
DRY=0; HOST=""; STAGE=""; IMAGE=""; WRONG=""; EXPECT=""; TIMEOUT=300
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --host) HOST="$2"; shift ;;
    --stage) STAGE="$2"; shift ;;
    --image) IMAGE="$2"; shift ;;
    --wrong-chip) WRONG="$2"; shift ;;
    --expect-version) EXPECT="$2"; shift ;;
    --timeout) TIMEOUT="$2"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
[ -n "$HOST" ] && [ -n "$STAGE" ] || { sed -n '2,32p' "$0"; exit 2; }
BASE="http://$HOST"
TMP=$(mktemp -d); chmod 700 "$TMP"; JAR="$TMP/jar"; CSRF=""
cleanup() {
  if [ -n "$CSRF" ] && [ "$DRY" = 0 ]; then
    curl -s -m 5 -o /dev/null -b "$JAR" -X POST "$BASE/api/admin/logout" || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }   # stderr: never captured into a value
stop() { log "STOP: $*"; log "The board is left as it is. Do not retry; report it (#395)."; exit 1; }

# json_get <json> <key>: top-level scalar only (python3 is on every host we use).
json_get() { python3 -c 'import json,sys; d=json.loads(sys.argv[1]); v=d.get(sys.argv[2]); print("" if v is None else (str(v).lower() if isinstance(v,bool) else v))' "$1" "$2" 2>/dev/null; }

ota_status() { curl -s -m 5 "$BASE/api/ota/status"; }
status()     { curl -s -m 5 "$BASE/api/status"; }

snapshot() {   # prints: uptime running boot next pendingVerify inProgress version
  local o s
  o=$(ota_status) || return 1
  s=$(status) || return 1
  [ -n "$o" ] && [ -n "$s" ] || return 1
  echo "$(json_get "$s" uptime) $(json_get "$o" running) $(json_get "$o" boot) $(json_get "$o" next) $(json_get "$o" pendingVerify) $(json_get "$o" inProgress) $(json_get "$s" version)"
}

login() {
  [ "$DRY" = 1 ] && { log "dry-run: would POST /api/admin/login (owner credential via stdin)"; return 0; }
  local u="${PD_OTA_USER:-}" p="${PD_OTA_PASS:-}" resp role
  [ -n "$u" ] || { read -r -p "owner username: " u; }
  [ -n "$p" ] || { read -r -s -p "owner password: " p; echo; }
  # Form body built and url-encoded off the command line, fed on stdin.
  resp=$(PD_U="$u" PD_P="$p" python3 -c 'import os,urllib.parse; print(urllib.parse.urlencode({"username":os.environ["PD_U"],"password":os.environ["PD_P"]}),end="")' \
         | curl -s -m 10 -c "$JAR" -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @- "$BASE/api/admin/login")
  unset p PD_OTA_PASS
  role=$(json_get "$resp" role); CSRF=$(json_get "$resp" csrf)
  [ "$(json_get "$resp" authenticated)" = "true" ] || stop "login refused ($(json_get "$resp" error))"
  [ "$role" = "owner" ] || stop "logged in as '$role'; OTA needs the OWNER"
  log "logged in (owner)"
}

# upload <file> -> prints the HTTP code; body saved to $TMP/up.json
upload() {
  if [ "$DRY" = 1 ]; then log "dry-run: would POST /api/ota/upload ($(stat -c %s "$1") B, octet-stream, X-CSRF)"; echo DRY; return; fi
  curl -s -m 180 -o "$TMP/up.json" -w '%{http_code}' -b "$JAR" -H "X-CSRF: $CSRF" \
       -H 'Content-Type: application/octet-stream' --data-binary @"$1" "$BASE/api/ota/upload"
}

need_idle() {   # the precondition every stage shares
  local snap; snap=$(snapshot) || stop "board not answering /api/status + /api/ota/status"
  set -- $snap
  log "state: uptime=$1 running=$2 boot=$3 next=$4 pendingVerify=$5 inProgress=$6 version=${7:-<none>}"
  [ "$2" = "$3" ] || stop "boot ($3) != running ($2): an image is already staged"
  [ "$5" = "false" ] || stop "pendingVerify=true: the running image is not yet valid"
  [ "$6" = "false" ] || stop "an OTA is already in progress"
  UPTIME0=$1; RUN0=$2; NEXT0=$4
}

stage0() {
  log "== stage 0: read-only precheck of $HOST"
  local o; o=$(ota_status); [ -n "$o" ] || stop "no /api/ota/status (firmware without OTA?)"
  echo "   /api/ota/status: $o"
  [ "$(json_get "$o" otaSupported)" = "true" ] || stop "otaSupported != true"
  need_idle
  log "stage 0 OK. NOT checkable remotely: the on-flash partition OFFSETS and the bootloader's rollback support (#395)."
}

stage2() {
  [ -f "$IMAGE" ] || stop "--image required (the real image; its first 64 KiB make the truncated one)"
  [ -f "$WRONG" ] || stop "--wrong-chip required (e.g. an esp32 lan8720 image)"
  log "== stage 2: safe refusals (nothing may reboot)"
  need_idle; login
  head -c 65536 "$IMAGE" > "$TMP/trunc.bin"
  local name f code snap
  for name in truncated wrong-chip; do
    f="$TMP/trunc.bin"; [ "$name" = wrong-chip ] && f="$WRONG"
    code=$(upload "$f")
    [ "$code" = DRY ] && continue
    log "$name upload -> HTTP $code $(cat "$TMP/up.json" 2>/dev/null | head -c 200)"
    case "$code" in 400|422|500) ;; 200) stop "$name image was ACCEPTED -- boot slot may now point at it";; *) stop "$name: unexpected HTTP $code";; esac
    sleep 2
    snap=$(snapshot) || stop "board stopped answering after the $name refusal"
    set -- $snap
    [ "$1" -gt "$UPTIME0" ] || stop "uptime went $UPTIME0 -> $1: the board REBOOTED"
    [ "$2" = "$RUN0" ] && [ "$3" = "$RUN0" ] || stop "running/boot changed ($2/$3) after a refused upload"
    UPTIME0=$1
    log "$name refused; no reboot (uptime $1), boot == running == $2"
  done
  [ "$DRY" = 1 ] && log "stage 2 dry-run complete (nothing sent)" || log "stage 2 OK"
}

stage3() {
  [ -f "$IMAGE" ] || stop "--image required"
  [ -n "$EXPECT" ] || stop "--expect-version required (the app-desc version of --image)"
  log "== stage 3: real OTA of $(basename "$IMAGE") ($(stat -c %s "$IMAGE") B), expecting version $EXPECT"
  need_idle; login
  local code o snap t0 seenPV=0 back=0
  code=$(upload "$IMAGE")
  [ "$code" = DRY ] && { log "dry-run: would then POST /api/ota/reboot and poll up to ${TIMEOUT}s"; return; }
  log "upload -> HTTP $code $(head -c 200 "$TMP/up.json")"
  [ "$code" = 200 ] || stop "upload not accepted (HTTP $code)"
  o=$(ota_status); log "after upload: $o"
  [ "$(json_get "$o" boot)" = "$NEXT0" ] || stop "boot slot is not $NEXT0 after upload"
  code=$(curl -s -m 10 -o "$TMP/rb.json" -w '%{http_code}' -b "$JAR" -H "X-CSRF: $CSRF" -X POST "$BASE/api/ota/reboot")
  log "reboot -> HTTP $code $(head -c 200 "$TMP/rb.json")"
  [ "$code" = 200 ] || stop "reboot refused (HTTP $code): the image stays staged, the old one keeps running"
  CSRF=""   # the session dies with the reboot
  t0=$(date +%s)
  while [ $(( $(date +%s) - t0 )) -lt "$TIMEOUT" ]; do
    o=$(curl -s -m 1 "$BASE/api/ota/status" 2>/dev/null)
    if [ -n "$o" ]; then
      [ "$back" = 0 ] && { back=1; log "back after $(( $(date +%s) - t0 ))s: $o"; }
      [ "$(json_get "$o" pendingVerify)" = "true" ] && [ "$seenPV" = 0 ] && { seenPV=1; log "pendingVerify=true seen -> the bootloader HAS rollback"; }
      if [ "$(json_get "$o" pendingVerify)" = "false" ] && [ $(( $(date +%s) - t0 )) -ge 20 ]; then break; fi
    fi
    sleep 0.2
  done
  [ "$back" = 1 ] || stop "board did not come back within ${TIMEOUT}s -- needs recovery at home"
  snap=$(snapshot) || stop "board answered once, then stopped"
  set -- $snap
  log "final: uptime=$1 running=$2 boot=$3 pendingVerify=$5 version=${7:-<none>}"
  [ "$1" -lt "$UPTIME0" ] || stop "uptime did not reset ($UPTIME0 -> $1): did it reboot?"
  [ "$2" = "$NEXT0" ] || stop "running $2, expected $NEXT0: ROLLED BACK (the new image never marked itself valid)"
  [ "${7:-}" = "$EXPECT" ] || stop "version '${7:-}' != expected '$EXPECT'"
  [ "$5" = "false" ] || stop "still pendingVerify after the health gate"
  [ "$seenPV" = 1 ] && log "rollback: PROVEN present" || log "rollback: NOT observed (bootloader may lack it, or the gate passed before the first poll)"
  log "stage 3 OK: $EXPECT runs from $2 and is valid. Phone re-registration: watch clientCount (can lag by the registration expiry)."
}

case "$STAGE" in
  0) stage0 ;;
  2) stage2 ;;
  3) stage3 ;;
  *) echo "stage must be 0, 2 or 3" >&2; exit 2 ;;
esac

#!/usr/bin/env bash
# SIPp interop harness against the host build. Starts the PBX binary on
# loopback, runs each scenario once as its own extension, reports PASS/FAIL
# per scenario (sipp exit 0 = every recv matched and every check_it held).
#
#   tests/sipp/run_sipp.sh [path/to/SipServer]   (default: build-wsl/, build_wsl/ or build/SipServer)
#
# Run under WSL/Linux (sipp is Linux-only; Windows firewall prompts are the
# other reason). Needs: sipp >= 3.6. Scenario notes:
#   * every scenario REGISTERs first -- the registrar refuses INVITEs from
#     unknown callers (403), and registration is itself under test;
#   * ooc.xml handles the register-beep INVITE and OPTIONS keepalives the PBX
#     sends outside the scenario's call (486 / 200);
#   * the codec-order pair runs a UAS (callee) and a UAC (caller) sipp side by
#     side; the callee's out-of-call scenario asserts the forked offer's payload
#     order with check_it (sipp keys calls by Call-ID, so a forked INVITE is
#     always "out-of-call" for the instance that registered).
# Logs land in tests/sipp/.logs/ (gitignored).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SERVER="${1:-}"
if [ -z "$SERVER" ]; then for c in "$ROOT/build-wsl/SipServer" "$ROOT/build_wsl/SipServer" "$ROOT/build/SipServer"; do [ -x "$c" ] && SERVER="$c" && break; done; fi
IP=127.0.0.1
SIP_PORT=5060
WEB_PORT=8080
LOG="$HERE/.logs"

if ! command -v sipp >/dev/null; then echo "sipp not installed (apt install sip-tester)"; exit 2; fi
if [ ! -x "$SERVER" ]; then echo "server binary not found: $SERVER"; exit 2; fi

rm -rf "$LOG"; mkdir -p "$LOG"
pkill -x "$(basename "$SERVER")" 2>/dev/null; sleep 0.5
"$SERVER" --ip $IP --port $SIP_PORT --web $WEB_PORT > "$LOG/server.log" 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null; wait $SERVER_PID 2>/dev/null' EXIT
sleep 2

pass=0; fail=0
result() {   # name rc
    if [ "$2" -eq 0 ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (sipp rc=$2)"; fail=$((fail+1)); fi
}

SIPP_COMMON=(-i $IP -m 1 -l 1 -r 1 -timeout_error -nostdin -trace_err -trace_msg)

# name scenario ext localport [extra sipp args...]   (foreground; rc = sipp's)
run_uac() {
    local name="$1" sf="$2" ext="$3" lport="$4"; shift 4
    sipp $IP:$SIP_PORT -sf "$HERE/$sf" -oocsf "$HERE/ooc.xml" -s "$ext" -p "$lport" -timeout 25s \
         "${SIPP_COMMON[@]}" -error_file "$LOG/$name.err" -message_file "$LOG/$name.msg" "$@" \
         > "$LOG/$name.out" 2>&1
}

echo "== SIPp interop against $SERVER"
run_uac register  register.xml      601 5061; result "REGISTER (open)" $?
run_uac echo-pcmu echo-pcmu.xml     602 5062; result "777 echo, PCMU offer -> answer keeps the offer's 0 101" $?
run_uac opus-488  opus-only-488.xml 603 5063; result "Opus-only offer -> 488" $?

# Codec-order pair: callee UAS first (registers, then waits), then the caller.
sipp $IP:$SIP_PORT -sf "$HERE/uas-hold-registration.xml" -oocsf "$HERE/ooc-uas-check-order.xml" -s 605 -p 5065 -timeout 40s \
     "${SIPP_COMMON[@]}" -error_file "$LOG/uas.err" -message_file "$LOG/uas.msg" > "$LOG/uas.out" 2>&1 &
UAS_PID=$!
sleep 2
run_uac uac-g722 uac-g722-first.xml 604 5064 -key callee 605; rc=$?
wait $UAS_PID; uas_rc=$?
[ $uas_rc -ne 0 ] && rc=$uas_rc
result "G.722-first offer: order kept to callee, answer relayed as-is" $rc

echo "== $pass passed, $fail failed  (logs: $LOG)"
[ $fail -eq 0 ]

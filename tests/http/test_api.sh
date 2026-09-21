#!/usr/bin/env bash
# ==============================================================================
# pocket-dial HTTP API Verification Script  (single source of truth)
# ==============================================================================
# This script executes standard, boundary, safety, security (CORS), OTA, and
# admin-auth test scenarios against a running pocket-dial target.
#
# It is the ONE smoke suite used both:
#   * locally / in CI against the host build  (SipServer on 127.0.0.1:8080), and
#   * on real hardware against the device captive-portal AP (192.168.4.1).
#
# Usage:
#   ./test_api.sh [target]
#       target may be a bare IP/host ("192.168.4.1") OR host:port
#       ("127.0.0.1:8080"). Defaults to 192.168.4.1 (device AP) if omitted.
#
# Optional environment:
#   SERVER_PID   If set, means "I launched this server myself and it is
#                disposable" -- i.e. a host/CI run, never a board. Two things key
#                off it:
#                  * the OTA-reboot test asserts this PID is STILL ALIVE
#                    afterwards (the desktop reboot endpoint must be a no-op and
#                    must NOT exit the process), and
#                  * the factory-reset cases (TC-FR-01..03) run AT ALL. They
#                    perform a real reset -- on hardware that would erase the
#                    credential, the carrier OAuth secret, the DID table and the
#                    CDR ring, and reboot the board mid-suite -- so they are
#                    skipped unless this is set.
#
# Test ORDERING is deliberate and load-bearing:
#   0. Admin auth & setup    (RUN FIRST: the device ships with a default login
#                             credential -- admin/admin -- and requireAdmin()
#                             refuses every mutating endpoint without a valid,
#                             fully-set-up session. There is no more
#                             "unprovisioned, no session needed" window; every
#                             suite below needs the $SESSION/$CSRF this
#                             establishes.)
#   1. Happy path            (the two ungated GETs: / and /api/status)
#   2. CSRF / same-origin
#   3. Input validation      (16 KB body cap -> 413 on the buffered endpoints)
#   4. Routing / 404
#   5. OTA                   (same session/CSRF as everything else now --
#                             the "pre-provisioning" window this used to rely
#                             on no longer exists)
#   6. Auth mechanics        (LAST: logs out and deliberately fails login
#                             several times to exercise brute-force lockout,
#                             which would otherwise interfere with the suites
#                             above)
# ==============================================================================

# Terminal Colors for Premium output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0;1m' # No Color
RESET='\033[0m'

TARGET_INPUT="192.168.4.1"
ALLOW_DESTRUCTIVE="${ALLOW_DESTRUCTIVE:-0}"
ADMIN_PIN="${PD_BOARD_ADMIN_PIN:-admin}"

for arg in "$@"; do
    if [ "$arg" = "--allow-destructive" ]; then
        ALLOW_DESTRUCTIVE=1
    elif [[ "$arg" != --* ]]; then
        TARGET_INPUT="$arg"
    fi
done

# If SERVER_PID is set, we are running against a disposable host process: every
# destructive case may run, INCLUDING the factory reset. Without it, the factory
# reset (TC-FR-01..03) never runs, whatever --allow-destructive says: it wipes
# credentials, the OAuth secret, the DID table and the CDR ring on a real board.
ALLOW_FACTORY_RESET=0
if [ -n "${SERVER_PID:-}" ]; then
    ALLOW_DESTRUCTIVE=1
    ALLOW_FACTORY_RESET=1
fi

# Accept either "host" or "host:port". Build BASE_URL accordingly and derive a
# bare host (TARGET_IP) for the Host/Origin headers the same-origin check reads.
if [[ "$TARGET_INPUT" == *:* ]]; then
    TARGET_IP="${TARGET_INPUT%%:*}"
    BASE_URL="http://${TARGET_INPUT}"
    ORIGIN_HDR="http://${TARGET_INPUT}"
    HOST_HDR="${TARGET_INPUT}"
else
    TARGET_IP="${TARGET_INPUT}"
    BASE_URL="http://${TARGET_INPUT}"
    ORIGIN_HDR="http://${TARGET_INPUT}"
    HOST_HDR="${TARGET_INPUT}"
fi

echo -e "${CYAN}======================================================================${RESET}"
echo -e "${CYAN}          POCKET-DIAL HTTP REST API AUTOMATED VERIFICATION           ${RESET}"
echo -e "${CYAN}======================================================================${RESET}"
echo -e "Target            : ${NC}${TARGET_INPUT}${RESET}"
echo -e "Base Connection   : ${NC}${BASE_URL}/${RESET}"
echo -e "Destructive Mode  : ${NC}${ALLOW_DESTRUCTIVE}${RESET}"
echo -e "${CYAN}======================================================================${RESET}\n"

# Statistics trackers
PASSED_TESTS=0
FAILED_TESTS=0

# Helper function to print test header
print_suite() {
    echo -e "\n${BLUE}● Suite: $1${RESET}"
}

# Helper function to assert HTTP Status Codes
assert_status() {
    local test_name="$1"
    local expected_code="$2"
    local actual_code="$3"
    local body="$4"

    if [ "$actual_code" -eq "$expected_code" ]; then
        echo -e "  [${GREEN}PASS${RESET}] ${test_name} (Got ${actual_code}, Expected ${expected_code})"
        ((PASSED_TESTS++))
    else
        echo -e "  [${RED}FAIL${RESET}] ${test_name} (Got ${actual_code}, Expected ${expected_code})"
        if [ -n "$body" ]; then
            echo -e "         Response Body: ${YELLOW}${body}${RESET}"
        fi
        ((FAILED_TESTS++))
    fi
}

# Generic boolean assertion (for content / liveness checks).
assert_true() {
    local test_name="$1"
    local condition="$2"   # "0" == true/pass (shell convention via [ ] exit code passed as string)
    if [ "$condition" = "0" ]; then
        echo -e "  [${GREEN}PASS${RESET}] ${test_name}"
        ((PASSED_TESTS++))
    else
        echo -e "  [${RED}FAIL${RESET}] ${test_name}"
        ((FAILED_TESTS++))
    fi
}

# Ensure clean temp files deletion on exit
cleanup() {
    rm -f temp_large_body.txt temp_ota_body.txt temp_resp_body.txt
}
trap cleanup EXIT

# ── TEST SUITE 0: ADMIN AUTH & INITIAL SETUP (RUN FIRST) ─────────────────────
# The device ships with a default login (AdminAuth::kDefaultUsername/
# kDefaultPassword = admin/admin). requireAdmin() refuses every mutating
# endpoint until (a) a session is logged in AND (b) that session has completed
# initial setup by replacing the default credential -- there is no more
# "unprovisioned, no session needed" bypass at all. Everything below depends
# on the $SESSION/$CSRF this suite establishes.
print_suite "Admin Authentication & Initial Setup"

# TC-AUTH-01: status is reachable pre-login
RESP_DATA=$(curl -s -w "\n%{http_code}" "${BASE_URL}/api/admin/status")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-AUTH-01: GET /api/admin/status (reachable pre-login)" "200" "$HTTP_CODE" "$BODY_CONTENT"

IS_PROVISIONED=0
if [[ "$BODY_CONTENT" == *'"needsSetup":false'* ]]; then
    IS_PROVISIONED=1
    echo -e "  [${GREEN}PASS${RESET}] TC-AUTH-01: device reports needsSetup:false (already provisioned)."
    ((PASSED_TESTS++))
elif [[ "$BODY_CONTENT" == *'"needsSetup":true'* ]]; then
    echo -e "  [${GREEN}PASS${RESET}] TC-AUTH-01: device reports needsSetup:true on the default credential."
    ((PASSED_TESTS++))
else
    echo -e "  [${RED}FAIL${RESET}] TC-AUTH-01: unexpected needsSetup in: ${YELLOW}${BODY_CONTENT}${RESET}"
    ((FAILED_TESTS++))
fi

# TC-AUTH-02: a mutating endpoint with no session at all is 401.
RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Host: ${HOST_HDR}" \
  -H "Origin: ${ORIGIN_HDR}" \
  -d "extension=123" "${BASE_URL}/api/kill")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-AUTH-02: POST /api/kill (no session -> 401)" "401" "$HTTP_CODE" "$BODY_CONTENT"

# TC-AUTH-03: cross-origin login is rejected (403) before anything else.
RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Host: ${HOST_HDR}" \
  -H "Origin: http://malicious-attacker-domain.com" \
  -d "username=admin&password=${ADMIN_PIN}" "${BASE_URL}/api/admin/login")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-AUTH-03: POST /api/admin/login (Cross-Origin rejected)" "403" "$HTTP_CODE" "$BODY_CONTENT"

# TC-AUTH-04: same-origin login -> 200, a pd_session cookie, and CSRF token.
LOGIN_PASS="admin"
if [ "$IS_PROVISIONED" -eq 1 ]; then
    LOGIN_PASS="${ADMIN_PIN}"
fi

LOGIN_RAW=$(curl -s -i -X POST \
  -H "Host: ${HOST_HDR}" \
  -H "Origin: ${ORIGIN_HDR}" \
  -d "username=admin&password=${LOGIN_PASS}" "${BASE_URL}/api/admin/login")
LOGIN_HEADERS=$(printf '%s' "$LOGIN_RAW" | sed -n '1,/^\r*$/p')
LOGIN_BODY=$(printf '%s' "$LOGIN_RAW" | sed '1,/^\r*$/d')
LOGIN_CODE=$(printf '%s' "$LOGIN_HEADERS" | grep -i "^HTTP/" | tail -n1 | awk '{print $2}')
assert_status "TC-AUTH-04: POST /api/admin/login (valid credential -> 200)" "200" "${LOGIN_CODE:-0}" "$LOGIN_HEADERS"

SESSION=$(printf '%s' "$LOGIN_HEADERS" \
    | grep -i "^set-cookie:" \
    | sed -n 's/.*pd_session=\([0-9a-fA-F]*\).*/\1/p' \
    | head -n1)
CSRF=$(printf '%s' "$LOGIN_BODY" \
    | sed -n 's/.*"csrf":"\([0-9a-fA-F]*\)".*/\1/p' \
    | head -n1)
if [ -n "$SESSION" ] && [ -n "$CSRF" ]; then
    echo -e "  [${GREEN}PASS${RESET}] TC-AUTH-04: login issued a pd_session cookie (len ${#SESSION}) and CSRF token (len ${#CSRF})."
    ((PASSED_TESTS++))
else
    echo -e "  [${RED}FAIL${RESET}] TC-AUTH-04: login did not return both a cookie and a CSRF token. Body: ${YELLOW}${LOGIN_BODY}${RESET}"
    ((FAILED_TESTS++))
fi

if [ "$IS_PROVISIONED" -eq 0 ]; then
    # TC-AUTH-05: logged in on the default credential, but setup is not complete --
    # every admin-gated action except set-credential itself must be refused (403).
    RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
      -H "Host: ${HOST_HDR}" \
      -H "Origin: ${ORIGIN_HDR}" \
      -H "Cookie: pd_session=${SESSION}" \
      -H "X-CSRF: ${CSRF}" \
      -d "extension=123" "${BASE_URL}/api/kill")
    HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
    BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
    assert_status "TC-AUTH-05: POST /api/kill (logged in, setup not complete -> 403)" "403" "$HTTP_CODE" "$BODY_CONTENT"

    # TC-AUTH-06: cross-origin set-credential is rejected (403).
    RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
      -H "Host: ${HOST_HDR}" \
      -H "Origin: http://malicious-attacker-domain.com" \
      -H "Cookie: pd_session=${SESSION}" \
      -d "username=admin&password=realpassword123" "${BASE_URL}/api/admin/set-credential")
    HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
    BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
    assert_status "TC-AUTH-06: POST /api/admin/set-credential (Cross-Origin rejected)" "403" "$HTTP_CODE" "$BODY_CONTENT"

    # TC-AUTH-07: complete setup with a real credential -> 200.
    RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
      -H "Host: ${HOST_HDR}" \
      -H "Origin: ${ORIGIN_HDR}" \
      -H "Cookie: pd_session=${SESSION}" \
      -H "X-CSRF: ${CSRF}" \
      -d "username=admin&password=realpassword123" "${BASE_URL}/api/admin/set-credential")
    HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
    BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
    assert_status "TC-AUTH-07: POST /api/admin/set-credential (completes setup -> 200)" "200" "$HTTP_CODE" "$BODY_CONTENT"
else
    echo -e "         ${YELLOW}skipping TC-AUTH-05..07: device already provisioned.${RESET}"
fi

# TC-AUTH-08: status now reports provisioned:true, needsSetup:false.
RESP_DATA=$(curl -s -w "\n%{http_code}" "${BASE_URL}/api/admin/status")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
if [[ "$BODY_CONTENT" == *'"provisioned":true'* && "$BODY_CONTENT" == *'"needsSetup":false'* ]]; then
    echo -e "  [${GREEN}PASS${RESET}] TC-AUTH-08: device reports provisioned:true, needsSetup:false after setup."
    ((PASSED_TESTS++))
else
    echo -e "  [${RED}FAIL${RESET}] TC-AUTH-08: expected provisioned:true/needsSetup:false, got: ${YELLOW}${BODY_CONTENT}${RESET}"
    ((FAILED_TESTS++))
fi

# TC-AUTH-09: the cookie ALONE is not enough (CSRF still required now that
# setup is complete). The same-origin check deliberately admits a request with
# no Origin header (curl and scripts send none), so the per-session CSRF token
# is what actually stops a same-site page from riding the victim's cookie.
RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Host: ${HOST_HDR}" \
  -H "Origin: ${ORIGIN_HDR}" \
  -H "Cookie: pd_session=${SESSION}" \
  -d "extension=123" "${BASE_URL}/api/kill")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-AUTH-09: POST /api/kill (cookie but NO CSRF token -> 403)" "403" "$HTTP_CODE" "$BODY_CONTENT"

echo -e "  ${CYAN}(session established: cookie len ${#SESSION}, csrf len ${#CSRF} -- reused by every suite below)${RESET}"


# ── TEST SUITE 1: HAPPY PATH ENDPOINT VALIDATIONS ────────────────────────────
print_suite "Happy Path & Content Type Delivery"

# TC-HP-01: Get Static Landing Page Dashboard (ungated).
RESP_DATA=$(curl -s -w "\n%{http_code}" "${BASE_URL}/")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-HP-01: GET Landing Dashboard (/)" "200" "$HTTP_CODE"

if [[ "$BODY_CONTENT" == *"<html"* || "$BODY_CONTENT" == *"<HTML"* ]]; then
    echo -e "  [${GREEN}PASS${RESET}] TC-HP-01: Landing Page served valid HTML structure."
    ((PASSED_TESTS++))
else
    echo -e "  [${RED}FAIL${RESET}] TC-HP-01: Landing Page response did not contain expected HTML signature."
    ((FAILED_TESTS++))
fi

# TC-HP-02: Get Active System Status JSON Snapshot (ungated).
RESP_DATA=$(curl -s -w "\n%{http_code}" "${BASE_URL}/api/status")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-HP-02: GET Status API Snapshot (/api/status)" "200" "$HTTP_CODE" "$BODY_CONTENT"

if [[ "$BODY_CONTENT" == *"uptime"* && "$BODY_CONTENT" == *"packetsProcessed"* && "$BODY_CONTENT" == *"clients"* ]]; then
    echo -e "  [${GREEN}PASS${RESET}] TC-HP-02: Status snapshot has complete metrics schema."
    ((PASSED_TESTS++))
else
    echo -e "  [${RED}FAIL${RESET}] TC-HP-02: Status snapshot has incomplete JSON schema."
    ((FAILED_TESTS++))
fi


# ── TEST SUITE 2: CSRF & SAME-ORIGIN SECURITY CHECK ──────────────────────────
print_suite "Same-Origin (CSRF) Security Verification"

# TC-SEC-01: Direct request (no Origin header, e.g. manual curl/script) with a
# valid session+CSRF -> ALLOW. No Origin is treated the same as same-origin.
RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Cookie: pd_session=${SESSION}" \
  -H "X-CSRF: ${CSRF}" \
  -d "extension=9999" "${BASE_URL}/api/kill")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-SEC-01: POST /api/kill (Direct Action - No Origin Header)" "200" "$HTTP_CODE" "$BODY_CONTENT"

# TC-SEC-02: Same-Origin Request (Matching Origin and Host) -> ALLOW
RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Host: ${HOST_HDR}" \
  -H "Origin: ${ORIGIN_HDR}" \
  -H "Cookie: pd_session=${SESSION}" \
  -H "X-CSRF: ${CSRF}" \
  -d "extension=9999" "${BASE_URL}/api/kill")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-SEC-02: POST /api/kill (Same-Origin Header Validation)" "200" "$HTTP_CODE" "$BODY_CONTENT"

# TC-SEC-03: Cross-Origin Request (Malicious script on third-party tab) -> REJECT 403
RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Host: ${HOST_HDR}" \
  -H "Origin: http://malicious-attacker-domain.com" \
  -H "Cookie: pd_session=${SESSION}" \
  -H "X-CSRF: ${CSRF}" \
  -d "extension=9999" "${BASE_URL}/api/kill")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-SEC-03: POST /api/kill (Cross-Origin Request Protection)" "403" "$HTTP_CODE" "$BODY_CONTENT"


# ── TEST SUITE 3: INPUT VALIDATION & LIMIT BOUNDS ────────────────────────────
print_suite "Input Validation, Schema Bounds & Limits"

# TC-ED-01: Payload size restriction (Capped at 16 KB) -> REJECT 413.
# The buffered-body cap is checked before requireAdmin, so no session is needed
# to observe it -- but a session is harmless to include and keeps this suite
# uniform with the others.
echo -e "${YELLOW}  * Generating 17 KB oversized mock body...${RESET}"
dd if=/dev/zero bs=1024 count=17 2>/dev/null | tr '\0' 'A' > temp_large_body.txt

RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: pd_session=${SESSION}" \
  -H "X-CSRF: ${CSRF}" \
  --data-binary @temp_large_body.txt \
  "${BASE_URL}/api/wifi/connect")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-ED-01: POST /api/wifi/connect (Oversized payload > 16 KB check)" "413" "$HTTP_CODE" "$BODY_CONTENT"

# TC-ED-02: Missing Kill Extension Parameter -> REJECT 400
RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Cookie: pd_session=${SESSION}" \
  -H "X-CSRF: ${CSRF}" \
  "${BASE_URL}/api/kill")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-ED-02: POST /api/kill (Empty body / missing parameter check)" "400" "$HTTP_CODE" "$BODY_CONTENT"

# TC-ED-03: Missing Connect SSID Parameter -> REJECT 400
RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Cookie: pd_session=${SESSION}" \
  -H "X-CSRF: ${CSRF}" \
  -d "password=testpass" "${BASE_URL}/api/wifi/connect")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-ED-03: POST /api/wifi/connect (Missing SSID parameter check)" "400" "$HTTP_CODE" "$BODY_CONTENT"


# ── TEST SUITE 4: NON-IMPLEMENTED ENDPOINTS (DESKTOP MODE BEHAVIOR) ──────────
print_suite "Platform Environment Routing & Mock Capabilities"

# TC-ED-04: Non-implemented routes check
RESP_DATA=$(curl -s -w "\n%{http_code}" "${BASE_URL}/api/invalid-route-name-xyz")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-ED-04: GET Invalid Path (Returns 404)" "404" "$HTTP_CODE" "$BODY_CONTENT"


# ── TEST SUITE 5: OTA UPDATE ENDPOINTS ───────────────────────────────────────
# Same session/CSRF as every other mutating route now -- the "pre-provisioning,
# upload gate still open" window this used to rely on no longer exists.
print_suite "OTA Firmware-Update Surface"

# TC-OTA-01: GET /api/ota/status -> 200, ungated, reports otaSupported flag.
RESP_DATA=$(curl -s -w "\n%{http_code}" "${BASE_URL}/api/ota/status")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-OTA-01: GET /api/ota/status (ungated introspection)" "200" "$HTTP_CODE" "$BODY_CONTENT"
# On the host build the stub reports otaSupported:false; on device it is true.
# We only assert the field is present and well-formed here.
if [[ "$BODY_CONTENT" == *'"otaSupported"'* && "$BODY_CONTENT" == *'"running"'* && "$BODY_CONTENT" == *'"inProgress":false'* ]]; then
    echo -e "  [${GREEN}PASS${RESET}] TC-OTA-01: ota/status has otaSupported + partition fields."
    ((PASSED_TESTS++))
else
    echo -e "  [${RED}FAIL${RESET}] TC-OTA-01: ota/status missing expected schema fields."
    ((FAILED_TESTS++))
fi

# TC-OTA-02: Cross-Origin OTA upload -> REJECT 403 (same gate as other mutations).
echo -e "${YELLOW}  * Generating 32 KB mock firmware body...${RESET}"
dd if=/dev/zero bs=1024 count=32 2>/dev/null | tr '\0' 'B' > temp_ota_body.txt

RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Host: ${HOST_HDR}" \
  -H "Origin: http://malicious-attacker-domain.com" \
  -H "Cookie: pd_session=${SESSION}" \
  -H "X-CSRF: ${CSRF}" \
  --data-binary @temp_ota_body.txt \
  "${BASE_URL}/api/ota/upload")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-OTA-02: POST /api/ota/upload (Cross-Origin rejected)" "403" "$HTTP_CODE" "$BODY_CONTENT"

# TC-OTA-03: Same-origin, authenticated OTA upload of a 32 KB body.
#   REGRESSION GUARD: the streaming interception bypasses the 16 KB buffered cap,
#   so this must NOT be 413. On host the stub drains the body and returns 501;
#   on device it would proceed to flash. We accept the device-or-host outcome
#   but explicitly FAIL on 413 (the cap-bypass regression).
RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Host: ${HOST_HDR}" \
  -H "Origin: ${ORIGIN_HDR}" \
  -H "Cookie: pd_session=${SESSION}" \
  -H "X-CSRF: ${CSRF}" \
  --data-binary @temp_ota_body.txt \
  "${BASE_URL}/api/ota/upload")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
if [ "$HTTP_CODE" = "413" ]; then
    echo -e "  [${RED}FAIL${RESET}] TC-OTA-03: 32 KB OTA upload hit the 16 KB buffered cap (got 413 — streaming bypass REGRESSED)."
    echo -e "         Response Body: ${YELLOW}${BODY_CONTENT}${RESET}"
    ((FAILED_TESTS++))
else
    # Host stub -> 501 (Not Implemented). This is the expected CI outcome.
    assert_status "TC-OTA-03: POST /api/ota/upload (32 KB streams past 16 KB cap; host stub 501)" "501" "$HTTP_CODE" "$BODY_CONTENT"
fi

# TC-OTA-04: Empty-body OTA upload (Content-Length: 0) -> REJECT 411.
RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Host: ${HOST_HDR}" \
  -H "Origin: ${ORIGIN_HDR}" \
  -H "Cookie: pd_session=${SESSION}" \
  -H "X-CSRF: ${CSRF}" \
  -H "Content-Length: 0" \
  "${BASE_URL}/api/ota/upload")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-OTA-04: POST /api/ota/upload (Content-Length: 0 -> 411)" "411" "$HTTP_CODE" "$BODY_CONTENT"

# TC-OTA-05: Cross-Origin reboot -> REJECT 403.
RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Host: ${HOST_HDR}" \
  -H "Origin: http://malicious-attacker-domain.com" \
  -H "Cookie: pd_session=${SESSION}" \
  -H "X-CSRF: ${CSRF}" \
  "${BASE_URL}/api/ota/reboot")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-OTA-05: POST /api/ota/reboot (Cross-Origin rejected)" "403" "$HTTP_CODE" "$BODY_CONTENT"

# TC-OTA-06: Same-origin, authenticated reboot -> 200 (host stub is a no-op and
# must NOT exit) or 409 (real device, no staged image).
RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Host: ${HOST_HDR}" \
  -H "Origin: ${ORIGIN_HDR}" \
  -H "Cookie: pd_session=${SESSION}" \
  -H "X-CSRF: ${CSRF}" \
  "${BASE_URL}/api/ota/reboot")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "409" ]; then
    echo -e "  [${GREEN}PASS${RESET}] TC-OTA-06: POST /api/ota/reboot same-origin (Got ${HTTP_CODE})"
    ((PASSED_TESTS++))
else
    echo -e "  [${RED}FAIL${RESET}] TC-OTA-06: POST /api/ota/reboot same-origin (Got ${HTTP_CODE}, expected 200 or 409)"
    echo -e "         Response Body: ${YELLOW}${BODY_CONTENT}${RESET}"
    ((FAILED_TESTS++))
fi

# TC-OTA-07: If SERVER_PID is provided (host/CI), the reboot stub must have left
# the process running (a real esp_restart() would be fatal off-device).
if [ -n "${SERVER_PID:-}" ]; then
    if kill -0 "${SERVER_PID}" 2>/dev/null; then
        echo -e "  [${GREEN}PASS${RESET}] TC-OTA-07: Server PID ${SERVER_PID} still alive after reboot (host stub is a no-op)."
        ((PASSED_TESTS++))
    else
        echo -e "  [${RED}FAIL${RESET}] TC-OTA-07: Server PID ${SERVER_PID} died after /api/ota/reboot — desktop reboot must NOT exit."
        ((FAILED_TESTS++))
    fi
fi


# ── TEST SUITE 6: AUTH MECHANICS  (RUN LAST — IT LOGS OUT AND LOCKS OUT) ─────
# Logout, then deliberately fail login several times to trip the brute-force
# lockout. Must run last: everything above needs a LIVE, working session.
print_suite "Auth Mechanics: Logout & Brute-Force Lockout"

curl -s -o /dev/null -X POST \
  -H "Host: ${HOST_HDR}" \
  -H "Origin: ${ORIGIN_HDR}" \
  -H "Cookie: pd_session=${SESSION}" \
  "${BASE_URL}/api/admin/logout"

# TC-AUTH-10: the just-logged-out session no longer authorizes anything.
RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Host: ${HOST_HDR}" \
  -H "Origin: ${ORIGIN_HDR}" \
  -H "Cookie: pd_session=${SESSION}" \
  -H "X-CSRF: ${CSRF}" \
  -d "extension=9999" "${BASE_URL}/api/kill")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-AUTH-10: POST /api/kill (session destroyed by logout -> 401)" "401" "$HTTP_CODE" "$BODY_CONTENT"

# ── FACTORY RESET  (HOST/CI ONLY — SEE THE GUARD) ────────────────────────────
# This block performs a REAL factory reset, so it runs only when SERVER_PID is
# set. That variable means "I started this server process myself and it is
# disposable" -- the same signal TC-OTA-07 already uses -- and nothing sets it
# when the suite is pointed at a board. Against real hardware these cases would
# erase the admin credential, the carrier OAuth secret, the DID table and the CDR
# ring, and reboot the device out from under the remaining tests.
#
# Placement inside suite 6 is forced from both sides. /api/factory-reset is
# admin-gated, so it needs a LIVE session -- but it also clears the credential and
# destroys every session, so it cannot run before anything above. It must sit
# AFTER TC-AUTH-10 (otherwise that test's 401 would come from the reset having
# killed the session rather than from the logout it is meant to prove) and BEFORE
# TC-AUTH-11 (whose five wrong passwords trip the 429 lockout that would block the
# re-login below).
if [ "$ALLOW_FACTORY_RESET" -ne 1 ]; then
    echo -e "         ${YELLOW}skipping TC-FR-01..03 (factory reset): SERVER_PID unset, so this may be"
    echo -e "         real hardware. The factory reset only ever runs against a host process.${RESET}"
else
# Re-login with the credential TC-AUTH-07 established (or ADMIN_PIN).
RESET_LOGIN_PASS="realpassword123"
if [ "$IS_PROVISIONED" -eq 1 ]; then
    RESET_LOGIN_PASS="${ADMIN_PIN}"
fi

FR_RAW=$(curl -s -i -X POST \
  -H "Host: ${HOST_HDR}" \
  -H "Origin: ${ORIGIN_HDR}" \
  -d "username=admin&password=${RESET_LOGIN_PASS}" "${BASE_URL}/api/admin/login")
FR_HEADERS=$(printf '%s' "$FR_RAW" | sed -n '1,/^\r*$/p')
FR_BODY=$(printf '%s' "$FR_RAW" | sed '1,/^\r*$/d')
FR_SESSION=$(printf '%s' "$FR_HEADERS" \
    | grep -i "^set-cookie:" \
    | sed -n 's/.*pd_session=\([0-9a-fA-F]*\).*/\1/p' \
    | head -n1)
FR_CSRF=$(printf '%s' "$FR_BODY" \
    | sed -n 's/.*"csrf":"\([0-9a-fA-F]*\)".*/\1/p' \
    | head -n1)

# TC-FR-01: confirm token is checked FIRST, before anything is touched, so a
# request without it must be a genuine no-op. Run before the real reset so the
# session is still good afterwards.
RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Host: ${HOST_HDR}" \
  -H "Origin: ${ORIGIN_HDR}" \
  -H "Cookie: pd_session=${FR_SESSION}" \
  -H "X-CSRF: ${FR_CSRF}" \
  -d "confirm=nope" "${BASE_URL}/api/factory-reset")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-FR-01: POST /api/factory-reset (wrong confirm token -> 400, nothing wiped)" "400" "$HTTP_CODE" "$BODY_CONTENT"

# TC-FR-02: the real thing. Must answer 200 on EVERY build. This endpoint used to
# answer 501 {"error":"factory reset not available on desktop"} on any build
# without POCKETDIAL_HAS_WIFI -- including the eth/lan8720 firmwares, where the
# wipe had already completed. The status is the operator's only signal that the
# destructive work happened, so a build that reports failure after succeeding is
# the bug this case exists to catch.
RESP_DATA=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Host: ${HOST_HDR}" \
  -H "Origin: ${ORIGIN_HDR}" \
  -H "Cookie: pd_session=${FR_SESSION}" \
  -H "X-CSRF: ${FR_CSRF}" \
  -d "confirm=ERASE" "${BASE_URL}/api/factory-reset")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
assert_status "TC-FR-02: POST /api/factory-reset (confirm=ERASE -> 200 on every build)" "200" "$HTTP_CODE" "$BODY_CONTENT"

# TC-FR-03: and the 200 must be true. The credential is gone, so the ungated
# status route reports needsSetup:true again -- the inverse of TC-AUTH-08.
RESP_DATA=$(curl -s -w "\n%{http_code}" "${BASE_URL}/api/admin/status")
HTTP_CODE=$(echo "$RESP_DATA" | tail -n1)
BODY_CONTENT=$(echo "$RESP_DATA" | sed '$d')
if [ "$HTTP_CODE" = "200" ] && echo "$BODY_CONTENT" | grep -q '"needsSetup":true'; then
    echo -e "  [${GREEN}PASS${RESET}] TC-FR-03: GET /api/admin/status reports needsSetup:true after the reset."
    ((PASSED_TESTS++))
else
    echo -e "  [${RED}FAIL${RESET}] TC-FR-03: reset answered 200 but the credential survived (expected needsSetup:true)."
    echo -e "         Response Body: ${YELLOW}${BODY_CONTENT}${RESET}"
    ((FAILED_TESTS++))
fi
fi  # end ALLOW_FACTORY_RESET guard around TC-FR-01..03

# TC-AUTH-11: brute-force lockout — 5 consecutive wrong passwords trip a 429.
# Gated behind ALLOW_DESTRUCTIVE so board runs don't lock out the admin account.
if [ "$ALLOW_DESTRUCTIVE" -ne 1 ]; then
    echo -e "         ${YELLOW}skipping TC-AUTH-11 (brute-force lockout): ALLOW_DESTRUCTIVE unset (0), so this"
    echo -e "         may be real hardware. Pass --allow-destructive or export ALLOW_DESTRUCTIVE=1 to run it.${RESET}"
else
LOCKED_OUT=1
for attempt in 1 2 3 4 5; do
    WRONG_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
      -H "Host: ${HOST_HDR}" \
      -H "Origin: ${ORIGIN_HDR}" \
      -d "username=admin&password=wrong" "${BASE_URL}/api/admin/login")
    echo -e "         attempt ${attempt}: /api/admin/login (wrong password) -> ${WRONG_CODE}"
    if [ "$WRONG_CODE" = "429" ]; then
        LOCKED_OUT=0
    fi
done
assert_true "TC-AUTH-11: 5x wrong password engages 429 lockout" "$LOCKED_OUT"
fi


# ── FINAL VERIFICATION SUMMARY REPORT ─────────────────────────────────────────
echo -e "\n${CYAN}======================================================================${RESET}"
echo -e "${CYAN}                     API TEST EXECUTION SUMMARY                      ${RESET}"
echo -e "${CYAN}======================================================================${RESET}"
echo -e "  Total Tests Executed : $((PASSED_TESTS + FAILED_TESTS))"
echo -e "  Tests Passed         : ${GREEN}${PASSED_TESTS}${RESET}"
if [ "$FAILED_TESTS" -eq 0 ]; then
    echo -e "  Tests Failed         : ${GREEN}0 (SUCCESS)${RESET}"
    echo -e "${CYAN}======================================================================${RESET}"
    echo -e "${GREEN}>>> SUCCESS: The pocket-dial firmware matches all REST specifications!${RESET}"
    exit 0
else
    echo -e "  Tests Failed         : ${RED}${FAILED_TESTS}${RESET}"
    echo -e "${CYAN}======================================================================${RESET}"
    echo -e "${RED}>>> FAILURE: Some test cases did not meet REST specifications!${RESET}"
    exit 1
fi

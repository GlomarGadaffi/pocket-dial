#!/bin/sh
# Self-test for the commit-hygiene gate (tools/ci/commit_hygiene.sh and
# .githooks/commit-msg). Run by .github/workflows/commit-hygiene.yml.
#
# Proves: a message carrying the noreply attribution address (any case,
# trailer or body) is rejected by the hook and by the range scan; a
# users.noreply.github.com address is allowed; a bad range fails; an empty
# range fails. The address is built from pieces so this file never holds it.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
LIB="$HERE/commit_hygiene.sh"
HOOK="$ROOT/.githooks/commit-msg"

U="noreply"
H="anthropic"
ADDR="${U}@${H}.com"
ADDR_UP="$(printf '%s' "$ADDR" | tr 'a-z' 'A-Z')"
OKADDR="12345+someone@users.${U}.github.com"

FAILS=0
ok()   { echo "ok:   $1"; }
bad()  { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# hook_rejects NAME MESSAGE EXPECT(reject|accept)
hook_case() {
    printf '%s\n' "$2" > "$TMP/msg"
    sh "$HOOK" "$TMP/msg" >/dev/null 2>&1
    rc=$?
    if [ "$3" = reject ] && [ "$rc" -ne 0 ]; then ok "hook rejects: $1"
    elif [ "$3" = accept ] && [ "$rc" -eq 0 ]; then ok "hook accepts: $1"
    else bad "hook $3 expected: $1 (rc=$rc)"; fi
}

hook_case "address in trailer" "fix: x

Co-Authored-By: Bot <${ADDR}>" reject
hook_case "address upper case" "fix: x

Co-Authored-By: Bot <${ADDR_UP}>" reject
hook_case "address in body" "fix: x

mentions ${ADDR} in prose" reject
hook_case "github users.noreply address" "fix: x

Co-authored-by: Someone <${OKADDR}>" accept
hook_case "plain message" "fix: x

--superlite" accept

# A checker that ERRORS (rc 2) must make the hook reject, never pass. Copy the
# hook next to a stub checker that always exits 2.
mkdir -p "$TMP/stub/.githooks" "$TMP/stub/tools/ci"
cp "$HOOK" "$TMP/stub/.githooks/commit-msg"
printf '#!/bin/sh\nexit 2\n' > "$TMP/stub/tools/ci/commit_hygiene.sh"
printf 'fix: x\n\n--superlite\n' > "$TMP/msg"
sh "$TMP/stub/.githooks/commit-msg" "$TMP/msg" >/dev/null 2>&1
rc=$?
if [ "$rc" -eq 1 ]; then ok "hook rejects when the checker errors (rc 2)"
else bad "hook must reject when the checker errors (rc=$rc)"; fi

# The checker itself: an unknown kind is an error (2), not "clean".
printf 'x\n' | sh "$LIB" match nonsense >/dev/null 2>&1
rc=$?
if [ "$rc" -eq 2 ]; then ok "checker errors (rc 2) on an unknown kind"
else bad "checker unknown kind should be rc 2 (rc=$rc)"; fi

# Range cases need a throwaway repo.
R="$TMP/repo"
git init -q "$R" || { bad "git init"; exit 1; }
(
    cd "$R" || exit 1
    git config user.email t@example.invalid
    git config user.name t
    git config commit.gpgsign false
    git config core.hooksPath "$TMP/nohooks"
    git commit -q --allow-empty -m "base"
    git tag base
    git commit -q --allow-empty -m "clean one"
    git tag clean
    git commit -q --allow-empty -m "$(printf 'trailer\n\nCo-Authored-By: Bot <%s>' "$ADDR")"
    git tag trailer
    git commit -q --allow-empty -m "$(printf 'upper\n\nbody %s here' "$ADDR_UP")"
    git tag upper
    git commit -q --allow-empty -m "$(printf 'ok\n\nCo-authored-by: S <%s>' "$OKADDR")"
    git tag okaddr
) || bad "fixture repo setup"

# range_case NAME EXPECT(pass|fail) ARGS...
range_case() {
    kind="$1"; name="$2"; want="$3"; shift 3
    (cd "$R" && sh "$LIB" range "$kind" "$@") >/dev/null 2>&1
    rc=$?
    if [ "$want" = pass ] && [ "$rc" -eq 0 ]; then ok "range passes: $name"
    elif [ "$want" = fail ] && { [ "$rc" -eq 1 ] || [ "$rc" -eq 2 ]; }; then ok "range fails: $name"
    else bad "range $want expected: $name (rc=$rc)"; fi
}

range_case address "clean commit"            pass base..clean
range_case address "address in trailer"      fail base..trailer
range_case address "address upper in body"   fail clean..upper
range_case address "users.noreply allowed"   pass upper..okaddr
range_case address "bad range (unknown sha)" fail 0123456789abcdef0123456789abcdef01234567..clean
range_case address "empty range"             fail clean..clean

# The Claude-Session trailer goes through the same machinery.
(cd "$R" && git commit -q --allow-empty -m "$(printf 's\n\nClaude-Session: https://example.invalid/x')" && git tag sess)
range_case trailer "session trailer" fail okaddr..sess
range_case trailer "no session trailer" pass base..clean
range_case trailer "bad range" fail 0123456789abcdef0123456789abcdef01234567..clean
range_case trailer "empty range" fail clean..clean

if [ "$FAILS" -ne 0 ]; then
    echo "test_commit_hygiene: $FAILS failure(s)"
    exit 1
fi
echo "test_commit_hygiene: all cases passed"

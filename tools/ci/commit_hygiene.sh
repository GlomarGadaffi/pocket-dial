#!/bin/sh
# The ONE place the commit-hygiene patterns live. Both .githooks/commit-msg
# (local) and .github/workflows/commit-hygiene.yml (CI) call this script, so
# the two cannot drift apart (issues #326, #341, #1106).
#
#   commit_hygiene.sh match   KIND          stdin matches KIND? exit 0 = yes
#   commit_hygiene.sh range   KIND REVARGS  scan every commit of a rev-list
#   commit_hygiene.sh text    KIND LABEL    scan stdin (e.g. PR body); 1 = hit
#
# KIND is "trailer" (Claude-Session:) or "address" (the noreply attribution
# address). Exit codes: 0 clean, 1 forbidden content found, 2 usage or git
# failure. A scan that could not read its input NEVER passes: rev-list
# failing, an empty range, or a failed git log are all exit 2.
#
# Tests: tools/ci/test_commit_hygiene.sh

# Issue #341 gaps 3 + 4. Any case; the trailer at line start, or anywhere in a
# line when followed by its URL (a 72-column reflow joins it onto the
# Co-authored-by line). Prose that merely names the trailer does not match.
TRAILER_RE='(^claude-session:)|(claude-session:[[:space:]]*https?://)'

# Built from pieces so no file in the repo holds the address itself.
ADDR_USER="noreply"
ADDR_HOST="anthropic\.com"
ADDR_RE="${ADDR_USER}@${ADDR_HOST}"

pattern_for() {
    case "$1" in
        trailer) PAT="$TRAILER_RE"; WHAT="a Claude-Session: trailer" ;;
        address) PAT="$ADDR_RE";    WHAT="the noreply attribution address" ;;
        *) echo "commit_hygiene: unknown kind '$1'" >&2; exit 2 ;;
    esac
}

# grep -c, never -q: -q closes the pipe early and, under pipefail, a big
# producer's SIGPIPE status masks the real result (see #339/#341). Input here
# is already in a variable, so this is belt and braces.
hit() { printf '%s\n' "$2" | grep -Eic "$1" >/dev/null; }

# verdict PAT TEXT: 0 = forbidden content found, 1 = clean. Any other grep
# status is a checker error: exit 2, never "clean".
verdict() {
    hit "$1" "$2"
    vrc=$?
    case "$vrc" in
        0|1) return "$vrc" ;;
    esac
    echo "::error::commit_hygiene: grep failed (rc ${vrc}); refusing to report clean." >&2
    exit 2
}

cmd="${1:-}"
kind="${2:-}"

case "$cmd" in
match)
    pattern_for "$kind"
    verdict "$PAT" "$(cat)"
    ;;
text)
    pattern_for "$kind"
    if verdict "$PAT" "$(cat)"; then
        echo "::error::${3:-The text} carries ${WHAT}."
        exit 1
    fi
    exit 0
    ;;
range)
    pattern_for "$kind"
    shift 2
    [ "$#" -gt 0 ] || { echo "::error::commit_hygiene: no range given" >&2; exit 2; }
    if ! shas="$(git rev-list "$@")"; then
        echo "::error::git rev-list $* failed (is the base commit in the fetched history?). Refusing to report clean." >&2
        exit 2
    fi
    if [ -z "$shas" ]; then
        echo "::error::git rev-list $* returned no commits. Nothing was checked; refusing to report clean." >&2
        exit 2
    fi
    n=0
    found=0
    for sha in $shas; do
        if ! msg="$(git log -1 --format=%B "$sha")"; then
            echo "::error::git log failed for ${sha}. Refusing to report clean." >&2
            exit 2
        fi
        n=$((n + 1))
        if verdict "$PAT" "$msg"; then
            subject="$(git log -1 --format=%s "$sha" 2>/dev/null)"
            echo "::error::Commit ${sha} (\"${subject}\") carries ${WHAT}."
            found=1
        fi
    done
    echo "Scanned ${n} commit(s) for ${WHAT}."
    [ "$found" -eq 0 ] || exit 1
    exit 0
    ;;
*)
    echo "usage: commit_hygiene.sh match|text|range KIND [...]" >&2
    exit 2
    ;;
esac

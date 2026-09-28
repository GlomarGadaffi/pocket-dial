#!/usr/bin/env bash
# Self-check for run_clang_tidy_safety.sh (#592 review): the ratchet must FAIL
# when the analysis produces nothing (dead compile DB / broken tool reads as a
# count of 0). A stub clang-tidy that runs but emits no diagnostics must make
# the gate exit non-zero. Run from the repo root; needs no build or clang-tidy.
set -u
stub=$(mktemp)
trap 'rm -f "$stub"' EXIT
printf '#!/bin/sh\n[ "$1" = --version ] && echo stub\nexit 0\n' > "$stub"
chmod +x "$stub"
if CT="$stub" LOG=/dev/null bash tools/ci/run_clang_tidy_safety.sh /nonexistent >/dev/null 2>&1; then
  echo "FAIL: gate passed with zero diagnostics (fails open)"; exit 1
fi
echo "PASS: gate fails when the analysis yields nothing"

#!/usr/bin/env bash
# Safety subset of clang-tidy (issue #372, plan item 2). BLOCKING ratchet.
#
# MISRA C does not apply to this C++ tree, and no free tool checks MISRA
# C++:2023 conformance. These six checks enforce the load-bearing rules that
# matter for the reliability bar (see #372). This is NOT a conformance claim.
#
#   cppcoreguidelines-no-malloc             Rule 21.6.1  no dynamic memory
#   misc-no-recursion                       Rule 8.2.10  no recursion
#   bugprone-unused-return-value            Rule 0.1.2   return values used
#   cert-err33-c                            Rule 0.1.2   (C stdlib returns)
#   cppcoreguidelines-pro-type-member-init  uninitialised members
#   cppcoreguidelines-init-variables        uninitialised locals
#
# Each check has its own baseline, measured with the pinned clang-tidy-18 over
# src/** (generated Sdp.cpp excluded, as in ci.yml's generic step). A count
# that differs from its baseline FAILS. Above: a new violation. Below: either
# findings were fixed (re-pin down in that PR) or the analysis silently did
# not run (dead compile DB reads as 0). Numbers only ratchet toward zero.
#
# Usage, from the repo root: tools/ci/run_clang_tidy_safety.sh [build-dir]
# The build dir needs compile_commands.json (CMAKE_EXPORT_COMPILE_COMMANDS=ON).
# CT overrides the binary (default clang-tidy-18).
set -uo pipefail

BUILD="${1:-build}"
CT="${CT:-clang-tidy-18}"

declare -A BASELINE=(
  # Raw per-TU counts (a header finding counts once per including .cpp),
  # same counting as ci.yml's CLANG_TIDY_BASELINE.
  [cppcoreguidelines-no-malloc]=14
  [misc-no-recursion]=4
  [bugprone-unused-return-value]=0
  [cert-err33-c]=33
  [cppcoreguidelines-pro-type-member-init]=28
  [cppcoreguidelines-init-variables]=22
)

"$CT" --version || { echo "::error::$CT not runnable"; exit 2; }
[ -f "$BUILD/compile_commands.json" ] || { echo "::error::no $BUILD/compile_commands.json"; exit 2; }
CHECKS="-*$(printf ',%s' "${!BASELINE[@]}")"
LOG="${LOG:-clang-tidy-safety.log}"
: > "$LOG"
while IFS= read -r f; do
  "$CT" -p "$BUILD" --quiet --header-filter='.*/src/.*' --checks="$CHECKS" \
        "$f" >> "$LOG" 2>&1 || true
done < <(find src -name '*.cpp' ! -path 'src/SIP/Sdp.cpp' | sort)

rc=0
for c in $(printf '%s\n' "${!BASELINE[@]}" | sort); do
  # Aliased checks print as [a,b]; match the name inside the bracket list.
  n=$(grep -E "(warning|error):" "$LOG" | grep -cE "[[,]${c}[],]" || true)
  b=${BASELINE[$c]}
  if [ "$n" -gt "$b" ]; then
    echo "::error::$c: $n > baseline $b -- new violation(s):"
    grep -E "(warning|error):.*[[,]${c}[],]" "$LOG" | sort -u
    rc=1
  elif [ "$n" -lt "$b" ]; then
    # FAIL, not warn: a dead compile DB or broken tool also reads as 0.
    echo "::error::$c: $n < baseline $b -- findings fixed (re-pin to $n in this PR) or the analysis did not run"
    rc=1
  else
    echo "$c: $n (baseline $b) ok"
  fi
done
exit $rc

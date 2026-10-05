#!/usr/bin/env bash
# The ONE cppcheck invocation. Both .github/workflows/ci.yml (the required
# PR/main gate) and .github/workflows/ci-glolab.yml (the nightly on the
# bigdog runner) call this script, so the two can't disagree about what
# is checked.
#
# Why it's a script: until this change each workflow carried its own copy of
# the command. The nightly copy never got the Sdp.cpp suppression below, so the
# first nightly on bigdog failed cppcheck on a tree the PR gate had passed
# (run 35991694144). Two copies of a gate drift; one copy can't.
#
# Run from the repository root. Needs the pinned cppcheck (CPPCHECK_VERSION in
# the workflow) on PATH or installed at $HOME/cppcheck-install.
#
# Fallback (#372): the shared WSL image ships a dpkg -x extract at
# ~/cppcheck-root instead. Run as-is it dies on `libtinyxml2.so.11: cannot open
# shared object file` (nothing sets LD_LIBRARY_PATH), and once that is fixed it
# dies again on `Failed to load std.cfg`, because the binary looks for cfg/
# next to itself or under its compiled-in FILESDIR (/usr/lib/x86_64-linux-gnu/
# cppcheck), and the extract is under neither. So when no runnable cppcheck is
# on PATH, copy the binary next to a cfg/ symlink in a cache dir and run that
# with LD_LIBRARY_PATH set. CI installs the pinned build, never reaches this
# branch, and the version it prints is the image's, not the pinned one.
set -euo pipefail

export PATH="$HOME/cppcheck-install/bin:$PATH"
CPPCHECK=cppcheck
if ! cppcheck --version >/dev/null 2>&1; then
    root="${CPPCHECK_ROOT:-$HOME/cppcheck-root}"
    lib="$root/usr/lib/x86_64-linux-gnu"
    if [ -x "$root/usr/bin/cppcheck" ] && [ -d "$lib/cppcheck/cfg" ]; then
        shim="${XDG_CACHE_HOME:-$HOME/.cache}/pocket-dial/cppcheck-shim"
        mkdir -p "$shim"
        cp -f "$root/usr/bin/cppcheck" "$shim/cppcheck.$$"
        mv -f "$shim/cppcheck.$$" "$shim/cppcheck"
        ln -sfn "$lib/cppcheck/cfg" "$shim/cfg"
        export LD_LIBRARY_PATH="$lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        CPPCHECK="$shim/cppcheck"
        echo "run_cppcheck.sh: no pinned cppcheck; using $root (NOT the CI-pinned build, findings may differ)" >&2
    fi
fi
"$CPPCHECK" --version

# On the Sdp.cpp suppression: that file is re2c OUTPUT (issue #196). It is
# never hand-edited and is drift-checked against Sdp.re, so a finding in it
# cannot be fixed in place -- any edit would be reverted by the next
# regeneration and flagged as drift.
#
# The finding itself is benign codegen: the generated DFA walks its input by
# incrementing a by-value `const char* YYCURSOR` parameter, which cppcheck
# reports as uselessAssignmentPtrArg -- an assignment to a pointer parameter
# with no effect outside the function. Literally true and beside the point:
# the caller wants the returned token, not the final cursor position.
#
# Scoped to that ONE check on that ONE file, deliberately, rather than the
# blanket `--suppress=*:<path>` used for qrcode.c. Generated code can still
# contain findings worth acting on; silencing the whole file would hide them
# permanently.
exec "$CPPCHECK" --error-exitcode=1 \
     --enable=warning,performance \
     --inline-suppr \
     --suppress=missingIncludeSystem \
     --suppress=unmatchedSuppression \
     --suppress='*:main/ui/qrcode.c' \
     --suppress='*:main/ui/qrcode.h' \
     --suppress=unknownMacro:main/ui/ui.cpp \
     --suppress=uselessAssignmentPtrArg:src/SIP/Sdp.cpp \
     -I src/Helpers -I src/SIP -I main \
     src/ main/

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
set -euo pipefail

export PATH="$HOME/cppcheck-install/bin:$PATH"
cppcheck --version

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
exec cppcheck --error-exitcode=1 \
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

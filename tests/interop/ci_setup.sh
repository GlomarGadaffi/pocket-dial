#!/usr/bin/env bash
# Build the pjsua the interop harness drives, pinned, into <prefix>, and print
# its path. Shared by the PR gate (.github/workflows/interop.yml) and the
# nightly self-hosted run (#377), so both judge the PBX against the same UA.
#
#   tests/interop/ci_setup.sh <prefix>        e.g.  ~/pjsua-bin
#   PJSUA="$(tests/interop/ci_setup.sh ~/pjsua-bin)" bash tests/interop/run_interop.sh build/SipServer
#
# Idempotent: an existing <prefix>/pjsua is reused as-is, which is what lets the
# workflow cache <prefix> keyed on this file's hash (pin + flags live here).
#
# Pinned to the pjproject commit the shared debian-pocketdial image was built
# from, with its flags, so a CI result means what a local one does. Bump both
# together, deliberately.
#
# PJMEDIA_HAS_VIDEO matters although nothing sends video: pjsua's CLI compiles
# its call-id picker inside "#if PJSUA_HAS_VIDEO", and without it
# "call transfer_replaces <id>" rejects every id, so attended_transfer could
# never issue its REFER -- a failure that says nothing about the PBX.
set -euo pipefail

PJPROJECT_REPO="https://github.com/pjsip/pjproject"
PJPROJECT_SHA="79c7e8fe1ffe62efce791256526c742818e16d2e"   # 2.17-dev, 2026-09-04
CONFIGURE_FLAGS=(--disable-sound --disable-ssl --disable-opencore-amr --disable-libwebrtc)

prefix="${1:?usage: ci_setup.sh <prefix>}"
bin="$prefix/pjsua"

# A path to a pjsua that doesn't run must never reach the harness: it would
# start no UAs and the suite would fail for reasons unrelated to the PBX -- or
# worse, a caller that trusts "printed a path" would carry on. So the path is
# printed ONLY after the binary answers --version; otherwise nothing on stdout
# and a non-zero exit. Applied to a cached binary too, not just a fresh build.
smoke() {
    "$1" --version 2>&1 | grep -q 'PJ_VERSION'
}

if [ -x "$bin" ]; then
    if smoke "$bin"; then
        echo "$bin"
        exit 0
    fi
    echo "ci_setup.sh: cached $bin fails the --version smoke check; rebuilding" >&2
    rm -f "$bin"
fi

mkdir -p "$prefix"
src="$(mktemp -d)"
trap 'rm -rf "$src"' EXIT
{
    git -C "$src" init -q
    git -C "$src" remote add origin "$PJPROJECT_REPO"
    git -C "$src" fetch -q --depth 1 origin "$PJPROJECT_SHA"
    git -C "$src" checkout -q FETCH_HEAD
    echo "#define PJMEDIA_HAS_VIDEO 1" > "$src/pjlib/include/pj/config_site.h"
    (cd "$src" && ./configure "${CONFIGURE_FLAGS[@]}" && make dep && make -j"$(nproc)")
} >&2
cp "$(ls "$src"/pjsip-apps/bin/pjsua-* | head -n1)" "$bin"
if ! smoke "$bin"; then
    echo "ci_setup.sh: freshly built $bin fails the --version smoke check" >&2
    rm -f "$bin"
    exit 1
fi
echo "$bin"

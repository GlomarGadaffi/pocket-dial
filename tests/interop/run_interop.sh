#!/usr/bin/env bash
# Real-SIP-stack interop harness. Sibling to tests/sipp/run_sipp.sh: same
# discovery-then-run shape, but the far end is pjsip's pjsua (and baresip, when
# installed) rather than a replayed SIPp scenario, so the PBX is judged by what
# a production stack will actually accept.
#
#   tests/interop/run_interop.sh [path/to/SipServer] [--only a,b]
#
# Run under WSL/Linux: the UAs bind 127.0.0.x source addresses and speak RTP,
# neither of which behaves on Windows without firewall prompts (see
# docs/ETH_SMOKE.md and the wsl-for-socket-tests note).
#
# pjsua is NOT packaged for Debian -- build it once into your WSL home:
#   git clone --depth 1 https://github.com/pjsip/pjproject ~/pjproject
#   cd ~/pjproject && echo "#define PJMEDIA_HAS_VIDEO 1" > pjlib/include/pj/config_site.h
#   ./configure --disable-sound --disable-ssl && make dep && make -j"$(nproc)"
# PJMEDIA_HAS_VIDEO matters even though nothing here sends video: pjsua's CLI
# compiles its dynamic call-id picker inside "#if PJSUA_HAS_VIDEO", and without
# it "call transfer_replaces <id>" rejects every id, so the attended-transfer
# scenario can never issue its REFER. Build with --disable-video and that one
# scenario fails for a reason that has nothing to do with the PBX.
# The binary lands in ~/pjproject/pjsip-apps/bin/ and is found automatically;
# override with PJSUA=/path/to/pjsua.
#
# baresip IS packaged and is optional:  sudo apt install -y baresip baresip-core
# Without it the mixed-stack scenario reports SKIP and the exit code ignores it.
#
# Logs (server + one full SIP trace per UA) land in tests/interop/.logs/.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"

if ! command -v python3 >/dev/null; then echo "python3 not found"; exit 2; fi
exec python3 "$HERE/interop.py" "$@"

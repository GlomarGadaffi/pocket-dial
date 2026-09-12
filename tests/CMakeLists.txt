cmake_minimum_required(VERSION 3.11)
project(pocket_dial_tests CXX)

# The codebase is C++17 (std::string_view / std::optional in SipMessage, the digest
# store, etc.). GCC/Clang default to C++17, so CI was implicitly fine, but MSVC
# defaults to C++14 and fails to parse those headers. Pin the standard explicitly so
# the host suite builds identically on every toolchain.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

enable_testing()

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

include_directories(${gtest_SOURCE_DIR}/include ../src/SIP ../src/Helpers)

add_executable(sip_parser_tests
    SipMessage_test.cpp
    # RFC regressions found by tests/interop/ (real pjsip stack): SDP answers
    # that invented payload types, Via received/rport naming the server instead
    # of the request source, and a non-2xx final response to a PBX-originated
    # INVITE that was never ACKed.
    InteropRfc_test.cpp
    SipMessage_header_test.cpp
    # Issue #101(B): SDP parse-once cache. Covers every body-mutation path that
    # must invalidate it — including reset() and `*msg = source`, the two ways
    # the message pool recycles a slot into a different call.
    SipSdpMessage_cache_test.cpp
    # CWE-674 hardening: the SDP parser must stay flat, non-recursive and bounded
    # against the UNISOC T612 a=acap-flood RCE class (SSD advisory, 2026), even as
    # SDP negotiation adds a= attribute handling on this branch.
    SipSdpMessage_hardening_test.cpp
    # T-7 (docs/THREAT_MODEL.md): SipMessage::checkSdp() structural caps + the
    # RFC 5939 capability-negotiation refusal, and the handle()-level gate that
    # applies them to every SDP-bearing message before any decode or relay.
    # Also pins the decode paths as zero-heap via a counting operator new.
    SdpAdmission_test.cpp
    # Issue #101(A)/(E): message-pool backpressure (bounded heap fallback, then
    # refuse) and the concurrent-handout invariant. Draws on the process-global
    # pool, so each test releases what it holds before it ends.
    RequestsHandler_pool_test.cpp
    # Issue #115: the 777 SDP-loopback echo test must call allocateSession()
    # BEFORE building any 180/200, mirroring the ordinary call-to-call INVITE
    # path, so a full session pool gets a real 503 instead of a false 200.
    Invite777SessionPool_test.cpp
    # Relay codec policy: filterAudioCodecs()/offersSupportedAudio() replaced the
    # blind enforceG711() "0 8 101" rewrite on peer-to-peer legs -- offer order
    # preserved, G.722 admitted, unsupported payloads (and their rtpmap/fmtp)
    # dropped, 488 when nothing is left.
    SdpNegotiate_test.cpp
    # onInvite admission gates: the 488 codec gate and the Secure-mode INVITE
    # digest challenge (drawbridge #125), driven through handle().
    InviteAdmission_test.cpp
    SipStatus_test.cpp
    SipDigest_test.cpp
    ArpLookup_test.cpp
    Pbx_test.cpp
    PageZone_test.cpp
    # Issue #74: broadcast/ring-group hold-resume relay. onOk()'s Connected/Held
    # relay used to explicitly exclude broadcast sessions, so a hold re-INVITE's
    # 200 OK was silently dropped instead of reaching the held leg. Drives a full
    # 999 broadcast call through connect -> hold -> resume via handle().
    BroadcastHoldResume_test.cpp
    # Issue #128: blind transfer's onRefer() tore down the transferor's ORIGINAL
    # session (endCall(), pure local bookkeeping) without ever sending the
    # dropped party a BYE on the wire. Drives a direct call through connect,
    # then a blind transfer, and asserts the dropped party's phone actually
    # gets a BYE for the dialog it was on (not just that the target gets an
    # INVITE).
    BlindTransfer_test.cpp
    # Issue #131: attended transfer (REFER + Replaces, RFC 3891), ported from
    # drawbridge. Splices two live P2P sessions via cross re-INVITEs carrying
    # swapped SDP, then drops the transferor. Drives two direct calls through
    # connect, then the splice, and asserts the crossed SDP, the splice
    # re-INVITE's OK never reaching the dropped transferor, the post-splice
    # BYE relay between the two remaining legs, and the 603-decline path for
    # an unresolvable Replaces target.
    AttendedTransfer_test.cpp
    # Issue #133: onRefer() admitted any REGISTERed From, never checking that the
    # REFER's source was actually a leg of the Call-ID it named — onBye's #46
    # guard with no counterpart. Covers the forged blind teardown, the forged
    # ?Replaces= splice of a consult dialog the source is not on, and that a
    # genuine in-dialog transfer still completes.
    ReferSourceAuth_test.cpp
    # Issue #69: the bounded pattern -> action dial plan that generalizes the
    # ring-group mechanism. Pure grammar/precedence/cap coverage against
    # DialPlan.hpp, end-to-end routing (dispatch + fallthrough) driven through
    # RequestsHandler::handle(), and a real-socket round-trip of the
    # POST /api/dialplan admin surface through HttpServer.
    DialPlan_test.cpp
    Rtp_test.cpp
    RtpReceiver_test.cpp
    PlayoutBuffer_test.cpp
    AnchorClient_test.cpp
    MediaBridge_test.cpp
    # Wires the AnchorClient/MediaBridge/TelephonyProvider extension point into
    # RequestsHandler's own call routing (virtual extension 555, opt-in, docs/
    # FEATURE_ROADMAP.md's "Anchored media") — the boot-time provider selection +
    # MediaBridge pool + rx-audio fanout, and the onInvite()/onBye() intercept,
    # driven end to end through RequestsHandler::handle() against the Loopback
    # reference client (the only AnchorClient this project ships).
    AnchorRouting_test.cpp
    MixBus_test.cpp
    # Issue #75: MixBus wired into MediaBridge (BUS mode) and made dialable as the
    # 888 meet-me room. Covers the N-way minus-self mix end-to-end through the real
    # µ-law rim, a leg leaving mid-conference, and the RequestsHandler 888 intercept.
    ConferenceRoom_test.cpp
    # Phase 0 of docs/PLAN_ADMIN_HTTP_ONLY.md: dark-by-default HTTP admin plane
    # test contract. Pulls in HttpServer.cpp for the first time in this target.
    AdminHttpGate_test.cpp
    # Issue #32: the live SIP tracer's data path — the actual bytes GET
    # /api/trace puts on the wire for the terminal's `trace on` command to
    # render, not just the C++-side getTraceRecords() accessor other tests
    # already cover.
    HttpTraceCommand_test.cpp
    # Issue #77: DTMF CLASS codes (*60/*80/*73/*72NNNN) must update the same
    # dashboard snapshot the HTTP setters do, not bypass it by writing
    # _dnd/_forwards directly from inside onDtmfInfo's _mutex lock.
    DtmfClassCodes_test.cpp
    # Wire-level coverage for the decomposed SIP state machines, driven through a
    # FakePbxEnv that records what each machine enqueues. The park/beep/BLF paths
    # build their requests by hand, so only a byte-level assertion catches header
    # defects like a doubled "Call-ID:" in the park retrieve re-INVITE.
    ParkOrbit_test.cpp
    # Issue #68: directed (**<ext>) and group (*8) call pickup — reuses ring-
    # group membership as the pickup-group table (see PbxConfig.hpp). Drives
    # RequestsHandler::handle() end to end (REGISTER/INVITE/OK/BYE) so the
    # CANCEL-the-loser fork, the swapped-SDP 200 OKs, the answer-first-wins
    # race in both directions, and the cross-dialog BYE bridge are all
    # asserted at the wire level.
    CallPickup_test.cpp
    RegisterBeeper_test.cpp
    BlfSubscriptions_test.cpp
    DashboardSnapshot_test.cpp
    # /api/pcap ring buffer + libpcap serializer (Issue #33). Pure/host-testable —
    # PcapCapture.hpp has no dependency beyond sockaddr_in.
    PcapCapture_test.cpp
    # Zero-touch phone auto-provisioning (Issue #35): the pure Yealink config
    # builder + the HttpServer path-shape check + RequestsHandler wiring.
    ProvisioningConfig_test.cpp
    # SIP digest-auth primitives + per-extension HA1 secret store. Both are
    # host-compilable: SipDigest vendors a portable MD5 (no mbedTLS) and
    # SipSecretStore uses an in-memory map under !ESP_PLATFORM (no NVS).
    ../src/Helpers/SipDigest.cpp
    ../src/Helpers/SipSecretStore.cpp
    # ArpLookup compiles to a host stub (returns nullopt — no ARP table off-device)
    # under !ESP_PLATFORM, so it links cleanly into the host test binary and lets
    # RequestsHandler's Learn-mode path build on the desktop.
    ../src/Helpers/ArpLookup.cpp
    # AdminAuth is self-contained (vendored SHA-256, host-stubbed NVS/RNG under
    # !ESP_PLATFORM). RequestsHandler::onDtmfInfo references AdminAuth::verifyPin for
    # the DTMF *PIN# admin menu, so it must be linked into the host binary too.
    ../src/Helpers/AdminAuth.cpp
    # SoftAP WPA2 settings: default-off, generated passphrase, and the WPA2
    # length/charset bounds that stop a typo from bringing the AP up open.
    DeviceConfig_test.cpp
    # DeviceConfig: SoftAP WPA2 settings + the flash-time cfgseed reader.
    # Host-stubbed under !ESP_PLATFORM (no NVS, no cfgseed partition), so the
    # dashboard AP-security endpoints stay exercisable on the desktop build.
    ../src/Helpers/DeviceConfig.cpp
    ../src/SIP/SipMessage.cpp
    ../src/SIP/SipStatus.cpp
    # Media beachhead (RTP sender + 440 media extension). RtpSender.cpp compiles to
    # host stubs (no sockets/FreeRTOS) under !ESP_PLATFORM; RequestsHandler.cpp +
    # SipSdpMessage/SipClient/Session are pulled in so the 440 SDP-answer and the
    # single-stream cap are unit-testable on the desktop build.
    ../src/SIP/RtpSender.cpp
    # Inbound media path (RtpReceiver): mirror of RtpSender. Host-stubbed under
    # !ESP_PLATFORM so the µ-law decode + RTP-parse helpers and the single-stream
    # cap are unit-testable on the desktop build (see RtpReceiver_test.cpp).
    ../src/SIP/RtpReceiver.cpp
    # Adaptive jitter buffer used by AnchorClient implementations. Pure C++17;
    # no ESP/socket dependencies. Exercises write/read/overrun/underrun paths.
    ../src/SIP/PlayoutBuffer.cpp
    # AnchorClient reference implementation. Pure loopback (no network); exercises
    # the AnchorClient contract: init/start/makeCall/audio/drop/stop lifecycle.
    ../src/SIP/LoopbackAnchorClient.cpp
    # RTP<->AnchorClient glue. Host-compilable: RtpReceiver/RtpSender::start()
    # are no-op stubs under !ESP_PLATFORM, so the lifecycle/identity bookkeeping
    # and the feedRx -> PlayoutBuffer path are exercisable on the desktop build.
    ../src/SIP/MediaBridge.cpp
    # The fixed-size TelephonyProviderType registry/factory (name/implemented
    # lookups + registerProvider/select) that RequestsHandler's boot-time anchor
    # wiring now uses to select LoopbackAnchorClient. Pure C++17, no ESP dependency.
    ../src/SIP/TelephonyProvider.cpp
    # Conference mix bus (see docs/CONFERENCE_MIXER.md). Pure C++17, no ESP
    # dependency. mix_kernels_scalar.cpp is the always-on scalar reference --
    # the ESP32-S3 PIE vector kernels (src/SIP/pie/) are opt-in and not built here.
    ../src/SIP/MixBus.cpp
    ../src/SIP/mix_kernels_scalar.cpp
    # The meet-me room that makes the bus dialable (Issue #75): one MixBus, N
    # {RtpReceiver, RtpSender, MediaBridge} legs, and the ONE periodic mix-tick
    # driver. Host-compilable — the driver is a std::thread off-device and the
    # tests step the clock with tickOnce() instead of starting it.
    ../src/SIP/ConferenceRoom.cpp
    # Issue #53/#101(A)/#101(E): the static SipMessage pool, extracted out of
    # RequestsHandler into its own translation unit.
    ../src/SIP/SipMessagePool.cpp
    # The five DND/forward/ring-group/page-zone/dial-plan PBX feature tables,
    # extracted out of RequestsHandler into their own translation unit.
    ../src/SIP/PbxFeatureConfig.cpp
    # The CDR ring buffer, extracted out of RequestsHandler into its own
    # translation unit.
    ../src/SIP/CdrRing.cpp
    # The DTMF digit-collection state machine + CLASS/admin codes, extracted
    # out of RequestsHandler into its own translation unit.
    ../src/SIP/DtmfFeatureCodes.cpp
    # The fork/group/dial-plan routing engine, extracted out of RequestsHandler
    # into its own translation unit.
    ../src/SIP/CallForker.cpp
    # Directed/group call pickup completion, extracted out of RequestsHandler
    # into its own translation unit.
    ../src/SIP/CallPickup.cpp
    ../src/SIP/RequestsHandler.cpp
    ../src/SIP/TransactionLayer.cpp
    ../src/SIP/Registrar.cpp
    ../src/SIP/RegisterBeeper.cpp
    ../src/SIP/ParkOrbit.cpp
    ../src/SIP/BlfSubscriptions.cpp
    ../src/SIP/SipSdpMessage.cpp
    ../src/SIP/SipClient.cpp
    ../src/SIP/Session.cpp
    # HttpServer + its OTA dependency, both already host-compilable (platform
    # guards on every ESP-only branch) but not previously linked into this
    # target. Needed by AdminHttpGate_test.cpp above.
    ../src/Helpers/HttpServer.cpp
    ../src/Helpers/OtaUpdater.cpp
)

target_link_libraries(sip_parser_tests PRIVATE gtest gtest_main)

if (WIN32)
    target_link_libraries(sip_parser_tests PRIVATE wsock32 ws2_32)
else()
    target_link_libraries(sip_parser_tests PRIVATE pthread)
endif()

add_test(NAME sip_parser_tests COMMAND sip_parser_tests)

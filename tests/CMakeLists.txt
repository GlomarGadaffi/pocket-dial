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
    # drawbridge #178/#90: the register-beep guard was wired into onFinalFailure
    # alone, but 180/480/486/487 each have their OWN handlerKey in handle()'s
    # dispatch switch — so all four fell through to endHandle(), which minted a
    # 404 back at the phone off the beep's own "pbx" From while the three finals
    # went unACKed. The pre-existing regression used 400 Bad SDP, the one code
    # with no specific handlerKey and thus the one that already hit the guard,
    # which is precisely why this survived. The 180 case is the subtle one: it
    # must be RECOGNISED without being consumed (a 1xx takes no ACK and does not
    # end the INVITE transaction, RFC 3261 §17.1.1).
    RegisterBeepRouting_test.cpp
    # RFC 5424 syslog frame construction: PRI arithmetic (facility*8 + severity),
    # the NILVALUE "-" timestamp we must emit until SNTP has synced, field order.
    Syslog_test.cpp
    # Prometheus /metrics text-exposition format — content type, HELP/TYPE lines,
    # and that a monotonic counter is exported as a counter rather than a gauge.
    MetricsEndpoint_test.cpp
    # Issue #159 (SMTP client), Phase 1: the pure protocol engine (base64,
    # EHLO capability parsing, dot-stuffing, the chunked base64 attachment
    # writer, the RFC 5322 date formatter) plus end-to-end coverage driven
    # through the REAL plain-TCP transport (SmtpClient::SmtpTransport)
    # against a scripted fake SMTP server on loopback -- greeting, every AUTH
    # variant, 4xx/5xx handling at each step, DATA dot-stuffing on the wire,
    # and timeouts. Ports 18130-18159 (see CONTRIBUTING_FIRMWARE.md's table).
    SmtpDialogue_test.cpp
    # RS256 JWT construction (Google service-account domain-wide delegation,
    # issue #159's Gmail Workspace path) + signature verification against a
    # fixed embedded test key -- OpenSSL host-side, mbedTLS on-device (see
    # GoogleServiceAuth.cpp's platform split).
    GoogleServiceAuth_test.cpp
    # HTTP admin surface for the two files above: GET/POST /api/email
    # (never echoes stored secrets, even authenticated) and POST
    # /api/email/test, driven through a real HttpServer socket exactly like
    # AdminHttpGate_test.cpp's other routes. Ports 18160-18169.
    EmailHttp_test.cpp
    SipDigest_test.cpp
    # Issue #164 groundwork: the CLIENT half of digest auth. SipDigest_test
    # covers the registrar direction (build a challenge, verify an inbound
    # Authorization); this covers the UAC direction (parse a challenge, compute
    # the response, emit the header). Every hash asserted there is PUBLISHED —
    # RFC 2617 §3.5, RFC 7616 §3.9.1, and RFC 2069 §2.4 as corrected by Verified
    # Errata 749 — because a digest implementation that only agrees with itself
    # will agree with itself while failing against every real SBC.
    SipDigestClient_test.cpp
    # The REGISTER user agent built on top of it: challenge/retry, nc
    # incrementing across refreshes, stale-nonce re-challenge, 423 + Min-Expires,
    # a server-shortened Expires, and the backoff that keeps a refusing carrier
    # SBC from being hammered (several ITSPs auto-blacklist for that).
    SipRegistrationClient_test.cpp
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
    # Issue #198: RFC 4028 session timers. Pins the arming DECISION (a 2xx with
    # Session-Expires but no refresher parameter obliges nobody, so arming a
    # reaper could only ever produce a spurious BYE) and the OPTIONS capability
    # advertisement. The negative assertions are the load-bearing ones: Supported
    # must NOT claim "timer" while Min-SE/422 handling is absent, which is the
    # over-claiming failure class issue #199 exists to document.
    SessionTimer_test.cpp
    # Issue #191: /api/kill used to hand-roll its form parse, swallowing every
    # parameter after "extension=" and never URL-decoding. Pins the shared
    # getFormParam() boundary semantics it now uses.
    ApiKillParse_test.cpp
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
    # Issue #202: service extensions -- the alphanumeric pseudo-AORs the engine
    # owns (pbx/moh/server). Covers the fixed table, the REGISTER refusal that
    # stops a phone taking one of those names (the register-beep paths depend by
    # name on findClient("pbx") MISSING), the reserved-name guards on every
    # config surface including the forward TARGET nothing ever validated, and the
    # alarm that fires if a service is marked dialable before anything can answer
    # a call routed to it.
    ServiceExtensions_test.cpp
    # The wall clock this firmware never had. Covers the pure RFC 3339 formatter
    # (fixed vectors, so a CI timezone change cannot make it pass for the wrong
    # reason) and the UNSYNCED path, which is permanent on the host build and is
    # exactly the degraded state every caller has to branch on.
    TimeSync_test.cpp
    # Music on hold (#162): parked callers used to hear literal silence (park
    # answered a=inactive on port 9 and started no sender). Covers the parts where
    # a bug is silent and maddening -- the WAV parser (a "skip 44 bytes" reader
    # plays the header as audio), the cursor wrap (off-by-one = a click once per
    # loop), the gain table (sign fold = a crack instead of clipping), and the
    # port-0/port-9 cases that mean "no audio here".
    HoldMusic_test.cpp
    MohPreview_test.cpp
    Rtp_test.cpp
    RtpReceiver_test.cpp
    # RFC 4733 telephone-event decode. Only reachable on a SERVER-TERMINATED leg
    # (440/555/888, and the voicemail/IVR roadmap) -- an ordinary call's RTP is
    # peer-to-peer and never reaches the board. The receive loop used to drop
    # every non-PCMU packet as "wrong codec", so a phone in its default DTMF mode
    # could not drive a server-side menu at all.
    TelephoneEvent_test.cpp
    PlayoutBuffer_test.cpp
    AnchorClient_test.cpp
    MediaBridge_test.cpp
    # Wires the AnchorClient/MediaBridge/TelephonyProvider extension point into
    # RequestsHandler's own call routing (virtual extension 555, opt-in, docs/
    # FEATURE_ROADMAP.md's "Anchored media") — the boot-time provider selection +
    # MediaBridge pool + rx-audio fanout, and the onInvite()/onBye() intercept,
    # driven end to end through RequestsHandler::handle() against the Loopback
    # reference client (used here for deterministic, no-network testing; a
    # second real implementation, TelephonyAnchorClient, exists but isn't
    # exercised by this host suite — see its own test files below).
    AnchorRouting_test.cpp
    # The bounded Telephony-API credential slot table ported from drawbridge,
    # plus the TelephonyProviderType::Telephony enumerator (now backed by the
    # real TelephonyAnchorClient, also ported from drawbridge). CRUD +
    # validation + the https:// gate + active-slot selection, and the property
    # that matters most for a credential store: view() never exposes the
    # plaintext secret, only bootSlot() does.
    TelephonyApiConfig_test.cpp
    # The bounded DID -> extension inbound routing table (new: neither
    # pocket-dial nor drawbridge had per-DID targeting before this). Pure
    # data-model coverage -- CRUD, lookup, field validation, and the
    # POCKETDIAL_MAX_DID_MAPPINGS bound. IS wired into call routing now --
    # RequestsHandler::routeInboundAnchorCall() calls extensionForDid() (see
    # DidMapping.hpp's BOUNDARY comment) -- but only the single configured
    # route DN can ever match, so this suite still exercises the class
    # directly rather than through call routing.
    DidMapping_test.cpp
    # The HTTP admin surface for the two tables above: GET/PUT/activate on
    # TelephonyApiConfig's credential slots and GET/PUT/DELETE on DidMapping's
    # DID->extension table, driven through a real HttpServer socket exactly
    # like AdminHttpGate_test.cpp's other routes (same requireAdmin gate).
    TelephonyConfigHttp_test.cpp
    # TelephonyAnchorClient (ported from drawbridge, Stage A of the port): the
    # pure, host-compilable helpers the real ESP-only client depends on. The
    # client itself (cJSON/mbedTLS/esp_http_client/esp_websocket_client) only
    # compiles on-device, so these three suites are what keeps the JWT-decode,
    # WS entity-path parse, and URL-builder / percent-encode / JSON-escape
    # logic exercised on the host build.
    UrlEncode_test.cpp
    JsonEscape_test.cpp
    TelephonyAnchorLogic_test.cpp
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
    # Issue #148: the duplicate-tracking feedback loop between sweep()'s Timer-A
    # retransmit and drainOutbox()'s maybeTrack() scan, driven directly so the
    # same INVITE can be re-fed deterministically.
    TransactionLayer_test.cpp
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
    # The REGISTER user agent (issue #164 groundwork). Pure C++17 — it never
    # touches a socket by design (see its header: the caller owns the _outbox vs
    # _asyncOutbox choice), so it links into the host suite with no stub arm.
    ../src/SIP/SipRegistrationClient.cpp
    # ArpLookup compiles to a host stub (returns nullopt — no ARP table off-device)
    # under !ESP_PLATFORM, so it links cleanly into the host test binary and lets
    # RequestsHandler's Learn-mode path build on the desktop.
    ../src/Helpers/ArpLookup.cpp
    # TimeSync: the SNTP wall clock. The formatter is pure; the SNTP client is
    # ESP-only, so the host build is PERMANENTLY unsynced — which is exactly the
    # degraded state every caller must branch on, and therefore worth exercising.
    ../src/Helpers/TimeSync.cpp
    # Syslog: RFC 5424 frame builder. Pure formatter host-side, UDP socket ESP-only.
    ../src/Helpers/Syslog.cpp
    # AdminAuth is self-contained (vendored SHA-256, host-stubbed NVS/RNG under
    # !ESP_PLATFORM). RequestsHandler::onDtmfInfo references AdminAuth::verifyPin for
    # the DTMF *PIN# admin menu, so it must be linked into the host binary too.
    ../src/Helpers/AdminAuth.cpp
    # SoftAP WPA2 settings: default-off, generated passphrase, and the WPA2
    # length/charset bounds that stop a typo from bringing the AP up open.
    DeviceConfig_test.cpp
    # Issue #181: the NVS schema decision table and the migration walker. The
    # rows that matter are "provisioned device with no version stamp" (every
    # board in the field on the release that introduces versioning — adopt as
    # v1, never wipe) and "stamp newer than this firmware" (an OTA rollback
    # lands here by itself — write nothing, log loudly, still boot).
    # planSchema()/runSchemaMigrations() are pure and platform-neutral for
    # exactly this reason; the nvs_open glue around them is ESP-only.
    SchemaVersion_test.cpp
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
    # The real WAN-anchor AnchorClient implementation (ported from drawbridge,
    # Stage A). Compiles to a host-stub arm under !ESP_PLATFORM (the real
    # cJSON/mbedTLS/esp_http_client/esp_websocket_client logic is ESP-only) so
    # it links into the host suite the same way RtpSender.cpp does.
    ../src/SIP/TelephonyAnchorClient.cpp
    # RTP<->AnchorClient glue. Host-compilable: RtpReceiver/RtpSender::start()
    # are no-op stubs under !ESP_PLATFORM, so the lifecycle/identity bookkeeping
    # and the feedRx -> PlayoutBuffer path are exercisable on the desktop build.
    ../src/SIP/MediaBridge.cpp
    # The fixed-size TelephonyProviderType registry/factory (name/implemented
    # lookups + registerProvider/select) that RequestsHandler's boot-time anchor
    # wiring now uses to select LoopbackAnchorClient. Pure C++17, no ESP dependency.
    ../src/SIP/TelephonyProvider.cpp
    # The bounded Telephony-API credential slot table (ported from drawbridge).
    # Host-compilable: falls back to a 0600-permission config file under
    # !ESP_PLATFORM instead of NVS. See TelephonyApiConfig_test.cpp.
    ../src/SIP/TelephonyApiConfig.cpp
    # The bounded DID -> extension inbound routing table (new, data-model only
    # -- see DidMapping.hpp's BOUNDARY comment). Same host-file/NVS split as
    # TelephonyApiConfig.cpp. See DidMapping_test.cpp.
    ../src/SIP/DidMapping.cpp
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
    # Music on hold (#162). The WAV parser, cursor wrap and gain table are pure and
    # host-tested; the socket and the 20 ms pacing task are ESP-only stubs here.
    ../src/SIP/HoldMusic.cpp
    ../src/SIP/BlfSubscriptions.cpp
    ../src/SIP/SipSdpMessage.cpp
    ../src/SIP/SipClient.cpp
    ../src/SIP/Session.cpp
    # HttpServer + its OTA dependency, both already host-compilable (platform
    # guards on every ESP-only branch) but not previously linked into this
    # target. Needed by AdminHttpGate_test.cpp above.
    ../src/Helpers/HttpServer.cpp
    ../src/Helpers/OtaUpdater.cpp
    # Issue #159 (SMTP client): the pure protocol engine (no sockets/TLS --
    # see SmtpDialogue.hpp's header comment) and the real transport
    # (plain-TCP identical on host/device; esp_tls only under ESP_PLATFORM --
    # see SmtpClient.hpp). Both link into the host suite the same way
    # RtpSender.cpp/TelephonyAnchorClient.cpp do.
    ../src/Helpers/SmtpDialogue.cpp
    ../src/Helpers/SmtpClient.cpp
    # RS256 JWT construction + signing for the Workspace service-account
    # XOAUTH2 path. Host-only crypto backend is OpenSSL (see this file's
    # platform split and find_package(OpenSSL) below); ESP-only backend is
    # mbedTLS, already a project dependency (main/CMakeLists.txt REQUIRES).
    ../src/Helpers/GoogleServiceAuth.cpp
    # NVS-backed (namespace "pbxcfg") SMTP/service-account configuration.
    # Host-stubbed in-memory under !ESP_PLATFORM, same pattern as
    # AdminAuth.cpp/DeviceConfig.cpp.
    ../src/Helpers/EmailConfigStore.cpp
)

target_link_libraries(sip_parser_tests PRIVATE gtest gtest_main)

# Issue #159: RS256 JWT signing on the host build uses OpenSSL (EVP_DigestSign)
# rather than mbedTLS -- IDF v6.0.1 only ships mbedtls/private headers (see
# SipDigest.hpp's identical reasoning for vendoring MD5 instead of depending on
# them), and a full mbedTLS build is not otherwise part of the host toolchain.
#
# OPTIONAL, not REQUIRED -- see the matching block in the top-level
# CMakeLists.txt for the full reasoning. Short version: `REQUIRED` here meant a
# Windows/MSVC host build could not configure at all, on a platform
# CONTRIBUTING_FIRMWARE.md lists as supported, because only ci.yml's Linux
# runner installs libssl-dev.
#
# Without it, the five GoogleServiceAuthCrypto tests compile out and one
# always-present test GTEST_SKIPs with an explanation, so the gap shows up in
# the test log instead of looking like full coverage. The three
# GoogleServiceAuthPure tests -- the JWT header/claims construction, which is
# where the escaping and exact-shape bugs would live -- need no crypto and run
# everywhere.
find_package(OpenSSL)
if (OpenSSL_FOUND)
    target_link_libraries(sip_parser_tests PRIVATE OpenSSL::Crypto)
    target_compile_definitions(sip_parser_tests PRIVATE PD_HAVE_OPENSSL=1)
else()
    message(STATUS
        "OpenSSL not found -- the GoogleServiceAuthCrypto tests (RS256 signature "
        "verification, issue #159) will be skipped. Every other test still runs. "
        "See CONTRIBUTING_FIRMWARE.md to install it.")
endif()

if (WIN32)
    target_link_libraries(sip_parser_tests PRIVATE wsock32 ws2_32)
else()
    target_link_libraries(sip_parser_tests PRIVATE pthread)
endif()

add_test(NAME sip_parser_tests COMMAND sip_parser_tests)

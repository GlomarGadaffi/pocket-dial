# Select transport: "wifi" for SoftAP mode, "eth" for W5500 Ethernet (PoE),
#   "lan8720" for internal-EMAC LAN8720 Ethernet (LilyGO T-Internet-COM, classic ESP32),
#   "display" for Guition AXS15231B Display
# Override at build time:  idf.py -D SIP_TRANSPORT=display build
# NOTE: lan8720 requires the classic ESP32 (has the internal EMAC):  idf.py set-target esp32
if(NOT DEFINED SIP_TRANSPORT)
    set(SIP_TRANSPORT "eth")      # default to W5500 Ethernet (LilyGO T-ETH-ELITE pins; see PD_ETH_BOARD)
endif()

set(ADDITIONAL_SRCS "")

# ESP-IDF v6.0 is the supported floor. Fail here, at configure time, rather than
# ~1400 objects into a build with "component esp_driver_ledc could not be found"
# — LEDC (and gpio/spi/i2c) were split out of the monolithic `driver` component
# in v5.3+, main/CMakeLists.txt requires them by their split names, and two
# managed components in idf_component.yml carry `idf_version >= 6.0.0` rules.
# That missing-component error is exactly what silently broke the
# v1.3.0-pre-alpha release run, which was still pinned to v5.2.1.
if(IDF_VERSION_MAJOR LESS 6)
    message(FATAL_ERROR
        "pocket-dial requires ESP-IDF v6.0 or later; this is v${IDF_VERSION_MAJOR}.${IDF_VERSION_MINOR}. "
        "Both .github/workflows/ci.yml and release.yml build on v6.0.1. "
        "Install a v6.x toolchain (see docs/FLASHING.md) and re-run idf.py.")
endif()

# The v6 split-driver components. Kept as one variable because four transport
# branches below need the same set.
set(IDF_V6_DRIVERS esp_driver_gpio esp_driver_spi esp_driver_i2c)

if(SIP_TRANSPORT STREQUAL "eth")
    set(MAIN_SRC "esp_main_eth.cpp")
    set(EXTRA_REQUIRES esp_eth espressif__w5500 ${IDF_V6_DRIVERS})
    # W5500 boards differ only in their SPI pin map. Select with -D PD_ETH_BOARD=<board>:
    #   elite     → LilyGO T-ETH-ELITE S3 (default; the board on the bench)
    #   waveshare → Waveshare ESP32-S3-ETH (PoE)
    # esp_main_eth.cpp picks the pins from the PD_ETH_BOARD_* define emitted below.
    if(NOT DEFINED PD_ETH_BOARD)
        set(PD_ETH_BOARD "elite")
    endif()
    if(PD_ETH_BOARD STREQUAL "elite")
        set(ETH_BOARD_DEF "PD_ETH_BOARD_ELITE")
    elseif(PD_ETH_BOARD STREQUAL "waveshare")
        set(ETH_BOARD_DEF "PD_ETH_BOARD_WAVESHARE")
    else()
        message(FATAL_ERROR "Unknown PD_ETH_BOARD='${PD_ETH_BOARD}' — use 'elite' or 'waveshare'")
    endif()
    message(STATUS "SipServer transport: W5500 Ethernet — board: ${PD_ETH_BOARD}")
elseif(SIP_TRANSPORT STREQUAL "lan8720")
    # LilyGO T-Internet-COM: classic ESP32 internal EMAC + external LAN8720 PHY (RMII).
    # Internal EMAC is built into esp_eth; the PHY power pin needs gpio. IDF v6.0 moved
    # the chip-specific PHY drivers out of esp_eth, so the LAN87xx driver now comes from
    # the espressif/lan87xx managed component (see idf_component.yml). On v5.x esp_eth
    # still ships esp_eth_phy_new_lan87xx, so the extra REQUIRES is only needed on v6+.
    #
    # Issue #111: LAN8720 drives the classic ESP32's INTERNAL EMAC — it cannot work on
    # any other target (S2/S3/C-series have no internal EMAC), so this has to fail here,
    # at configure time, rather than ~1400 objects into the build. Left unguarded, the
    # component manager quietly declines to fetch espressif/lan87xx on a non-esp32 target
    # (its own idf_component.yml rules: target == esp32), so the missing-header error
    # that eventually surfaces reads like an ESP-IDF version mismatch, not an
    # unsupported target/transport pairing. Use SIP_TRANSPORT=eth (W5500) elsewhere.
    if(NOT IDF_TARGET STREQUAL "esp32")
        message(FATAL_ERROR
            "SIP_TRANSPORT=lan8720 requires the classic ESP32's internal EMAC; "
            "IDF_TARGET is '${IDF_TARGET}'. Use SIP_TRANSPORT=eth (W5500) on ${IDF_TARGET}, "
            "or set-target esp32 for the internal-EMAC LAN8720 board.")
    endif()
    set(MAIN_SRC "esp_main_eth_lan8720.cpp")
    set(EXTRA_REQUIRES esp_eth espressif__lan87xx ${IDF_V6_DRIVERS})
    message(STATUS "SipServer transport: LAN8720 Ethernet (internal EMAC / RMII, classic ESP32)")
elseif(SIP_TRANSPORT STREQUAL "display")
    set(MAIN_SRC "esp_main_display.cpp")
    set(EXTRA_REQUIRES esp_lcd espressif__esp_lcd_touch lvgl__lvgl esp_driver_ledc
        ${IDF_V6_DRIVERS})
    set(ADDITIONAL_SRCS "drivers/esp_lcd_axs15231b.c" "ui/ui.cpp" "ui/qrcode.c" "wifi/DnsServer.cpp")
    message(STATUS "SipServer transport: Guition AXS15231B Touch Display (LVGL)")
else()
    set(MAIN_SRC "esp_main.cpp")
    set(EXTRA_REQUIRES ${IDF_V6_DRIVERS})
    message(STATUS "SipServer transport: WiFi SoftAP")
endif()

idf_component_register(SRCS ${MAIN_SRC}
                            ${ADDITIONAL_SRCS}
                            "../src/Helpers/UdpServer.cpp"
                            "../src/Helpers/HttpServer.cpp"
                            "../src/Helpers/AdminAuth.cpp"
                            "../src/Helpers/DeviceConfig.cpp"
                            "../src/Helpers/SipDigest.cpp"
                            "../src/Helpers/SipSecretStore.cpp"
                            "../src/Helpers/ArpLookup.cpp"
                            "../src/Helpers/OtaUpdater.cpp"
                            # SNTP wall clock. Additive to steady_clock, never a
                            # replacement: steady_clock stays the clock for every
                            # duration and timer precisely because it cannot step.
                            "../src/Helpers/TimeSync.cpp"
                            # RFC 5424 syslog frame builder + UDP emitter. Present
                            # but not yet hooked into LogQueue: the drain task runs
                            # on a 2048-byte stack and send()'s frame buffer would
                            # not fit, so wiring it needs a stack bump first.
                            "../src/Helpers/Syslog.cpp"
                            "../src/SIP/SipMessagePool.cpp"
                            "../src/SIP/PbxFeatureConfig.cpp"
                            "../src/SIP/CdrRing.cpp"
                            "../src/SIP/DtmfFeatureCodes.cpp"
                            "../src/SIP/CallForker.cpp"
                            "../src/SIP/CallPickup.cpp"
                            "../src/SIP/RequestsHandler.cpp"
                            "../src/SIP/TransactionLayer.cpp"
                            "../src/SIP/Registrar.cpp"
                            "../src/SIP/RegisterBeeper.cpp"
                            "../src/SIP/ParkOrbit.cpp"
                            "../src/SIP/BlfSubscriptions.cpp"
                            "../src/SIP/Session.cpp"
                            "../src/SIP/SipClient.cpp"
                            "../src/SIP/SipMessage.cpp"
                            "../src/SIP/SipMessageFactory.cpp"
                            "../src/SIP/SipSdpMessage.cpp"
                            "../src/SIP/SipServer.cpp"
                            "../src/SIP/SipStatus.cpp"
                            "../src/SIP/RtpSender.cpp"
                            "../src/SIP/RtpReceiver.cpp"
                            "../src/SIP/PlayoutBuffer.cpp"
                            "../src/SIP/LoopbackAnchorClient.cpp"
                            "../src/SIP/TelephonyAnchorClient.cpp"
                            "../src/SIP/MediaBridge.cpp"
                            "../src/SIP/TelephonyProvider.cpp"
                            "../src/SIP/TelephonyApiConfig.cpp"
                            "../src/SIP/DidMapping.cpp"
                            "../src/SIP/MixBus.cpp"
                            "../src/SIP/mix_kernels_scalar.cpp"
                            "../src/SIP/ConferenceRoom.cpp"
                    INCLUDE_DIRS "../src/Helpers" "../src/SIP" "drivers" "ui" "wifi"
                    REQUIRES nvs_flash lwip esp_netif esp_event freertos mdns app_update esp_driver_ledc console esp_timer esp_websocket_client esp_http_client cjson mbedtls ${EXTRA_REQUIRES}
                    PRIV_REQUIRES esp_wifi)

# Issue #49: the display transport reserves Core 1 for the LVGL graphics task and
# runs the SIP engine on Core 0, so the UDP receiver (which carries SIP signaling)
# must stay on Core 0. The SoftAP/Ethernet transports run SIP on Core 1 and use the
# UdpServer default (Core 1).
# Pure-Ethernet transports (W5500 "eth" and LAN8720 "lan8720") have no WiFi at all,
# so they must NOT define POCKETDIAL_HAS_WIFI.
if(NOT SIP_TRANSPORT STREQUAL "eth" AND NOT SIP_TRANSPORT STREQUAL "lan8720")
    target_compile_definitions(${COMPONENT_LIB} PRIVATE POCKETDIAL_HAS_WIFI)
endif()

# W5500 board pin-map selector (see the eth branch above). Drives the #if in
# esp_main_eth.cpp; absent the define, that file falls back to the Elite pins.
if(SIP_TRANSPORT STREQUAL "eth")
    target_compile_definitions(${COMPONENT_LIB} PRIVATE ${ETH_BOARD_DEF})
endif()

if(SIP_TRANSPORT STREQUAL "display")
    target_compile_definitions(${COMPONENT_LIB} PRIVATE POCKETDIAL_UDP_RX_CORE=0)
    # qrcode.c (ricmoo QRCode, vendored): uses #pragma mark (an Xcode-ism) GCC flags as an
    # unknown pragma, plus an `x < 0` guard on an unsigned arg that -Wtype-limits reports
    # as always-false. Both are harmless in this third-party file; demote to warnings.
    set_source_files_properties("ui/qrcode.c" PROPERTIES COMPILE_FLAGS "-Wno-error=unknown-pragmas -Wno-error=type-limits")
    # esp_main_display.cpp builds the AXS15231B panel-IO configs through the driver's
    # partial designated-initializer macros (the IDF convention); under C++ -Wextra the
    # unset trailing flag fields trip -Werror=missing-field-initializers. Demote it.
    set_source_files_properties("esp_main_display.cpp" PROPERTIES COMPILE_FLAGS "-Wno-error=missing-field-initializers")
endif()

# Resource-constrained profile: shrink the pre-allocated SIP object pools to fit a
# low-RAM classic ESP32 (ESP32-WROOM, 520KB SRAM, no PSRAM). The message pool is the
# heaviest consumer (one std::string buffer per slot), so it gets cut the most.
# These override the #ifndef defaults in src/SIP/PoolConfig.hpp (32/8/32).
# Pair with sdkconfig.defaults.esp32_constrained + partitions_4mb.csv:
#   idf.py -D SIP_TRANSPORT=lan8720 -D SIP_CONSTRAINED=1 \
#          -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.esp32_constrained" \
#          set-target esp32 build
if(SIP_CONSTRAINED)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        POCKETDIAL_MAX_CLIENTS=8
        POCKETDIAL_MAX_SESSIONS=4
        POCKETDIAL_MSG_POOL=8)
    message(STATUS "SipServer profile: RESOURCE-CONSTRAINED (clients=8 sessions=4 msgpool=8)")
endif()

cmake_minimum_required (VERSION 3.16)

# Issue #411: decide the firmware version once, for every build flavour. See
# cmake/FirmwareVersion.cmake for why ESP-IDF's own fallback always said "1".
include(${CMAKE_CURRENT_LIST_DIR}/cmake/FirmwareVersion.cmake)
pocketdial_firmware_version(POCKETDIAL_RESOLVED_FW_VERSION)

if(DEFINED ENV{IDF_PATH})
    # Must be set BEFORE project(): that is where ESP-IDF reads PROJECT_VER into
    # the app descriptor. Set it after and IDF runs its own `git describe`,
    # which is the call that fails in CI's container.
    set(PROJECT_VER "${POCKETDIAL_RESOLVED_FW_VERSION}")
    # Also written next to the build, so tools/ci/check_app_version.py can
    # compare the binary against what CMake actually chose.
    file(WRITE "${CMAKE_BINARY_DIR}/pocketdial_fw_version.txt" "${POCKETDIAL_RESOLVED_FW_VERSION}")
    include($ENV{IDF_PATH}/tools/cmake/project.cmake)
    project("SipServer")
    idf_build_set_property(COMPILE_DEFINITIONS "LV_TICK_CUSTOM_SYS_TIME_EXPR=((esp_timer_get_time()/1000LL))" APPEND)
else()
    project ("SipServer")

    # Issue #411: the host binary reports the same version string the firmware
    # would (FirmwareInfo.cpp reads it), so /api/status has one shape everywhere.
    add_compile_definitions(POCKETDIAL_FW_VERSION="${POCKETDIAL_RESOLVED_FW_VERSION}")

    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)

    if (WIN32)
        # windows.h's max()/min() macros collide with std::max/std::min (e.g.
        # Registrar.cpp's noteChange()) unless suppressed. Applies to this
        # directory and tests/ (add_subdirectory below inherits directory
        # properties regardless of its own project() call).
        add_compile_definitions(NOMINMAX)
    endif()

    if (MSVC)
        add_compile_options(/Zc:lambda)
    endif()

    set(SRC_DIR "${PROJECT_SOURCE_DIR}/src")

    set(HELPERS_SRC_FILES "${SRC_DIR}/Helpers")
    file(GLOB_RECURSE HELPERS_SRC
        "${HELPERS_SRC_FILES}/*.cpp"
        "${HELPERS_SRC_FILES}/*.h"
        "${HELPERS_SRC_FILES}/*.hpp"
    )

    set(SIP_SRC_FILES "${SRC_DIR}/SIP")
    file(GLOB_RECURSE SIP_SRC
        "${SIP_SRC_FILES}/*.cpp"
        "${SIP_SRC_FILES}/*.h"
        "${SIP_SRC_FILES}/*.hpp"
    )

    include_directories(${HELPERS_SRC_FILES} ${SIP_SRC_FILES})
    add_executable (SipServer "main.cpp" ${SIP_SRC} ${HELPERS_SRC} )

    # Issue #159: GoogleServiceAuth.cpp's host build signs RS256 JWTs with
    # OpenSSL (EVP_DigestSign) rather than mbedTLS -- see that file's own
    # platform-split comment for why (IDF only ships mbedtls/private/*
    # headers; a full mbedTLS build is not otherwise part of the host
    # toolchain). SipServer globs every src/Helpers/*.cpp, so it picks this
    # up too. tests/CMakeLists.txt (via add_subdirectory below) does the same
    # search; whichever of the two configures first, CMake caches the result,
    # so this is not a second real search.
    #
    # NOT `REQUIRED`. It was, and that silently broke the Windows/MSVC host
    # build: OpenSSL is not present by default there, so `cmake -B build -S .`
    # died at configure with "Could NOT find OpenSSL" -- on a platform
    # CONTRIBUTING_FIRMWARE.md documents as a supported host-test path, and
    # with nothing anywhere naming the new prerequisite. Only ci.yml's Linux
    # runner installs libssl-dev.
    #
    # Optional instead, because what is actually lost without it is narrow and
    # host-only: RS256 SIGNING on the host. The device build uses mbedTLS and
    # is untouched; the XOAUTH2 token fetch is ESP-only regardless. So a
    # Windows host build without OpenSSL still configures, still builds, and
    # still runs every test except the five that exercise the signature
    # itself. See CONTRIBUTING_FIRMWARE.md for how to install it if you want
    # those.
    find_package(OpenSSL)
    if (OpenSSL_FOUND)
        target_link_libraries(SipServer OpenSSL::Crypto)
        target_compile_definitions(SipServer PRIVATE PD_HAVE_OPENSSL=1)
    else()
        message(STATUS
            "OpenSSL not found -- host RS256 JWT signing (issue #159) is disabled. "
            "Everything else builds normally. To enable it: apt install libssl-dev, "
            "brew install openssl, or vcpkg install openssl (see CONTRIBUTING_FIRMWARE.md).")
    endif()

    if (WIN32)
        target_link_libraries(SipServer wsock32 ws2_32)
    elseif (UNIX)
        # 64-bit std::atomic counters (RequestsHandler packet stats) lower to libatomic
        # calls on ARMv7 (no native 8-byte atomic instruction) — link it. Harmless on
        # x86-64 where the atomics are inlined. Required for the Orbic cross-build (#82).
        target_link_libraries(SipServer -pthread atomic)
    else()
        message(FATAL_ERROR "Unsupported platform.")
    endif()

    target_compile_options(SipServer PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -Wpedantic>
        $<$<CXX_COMPILER_ID:MSVC>:/W4>
    )

    source_group("Helpers"  FILES ${HELPERS_SRC_FILES})
    source_group("SIP"      FILES ${SIP_SRC_FILES})

    # Tests pull googletest in via FetchContent — skip for cross-compiles (the ARMv7
    # musl Orbic build, issue #82) where we only want the SipServer binary:
    #   cmake ... -DCMAKE_TOOLCHAIN_FILE=cmake/armv7-linux-musleabihf.cmake -DBUILD_TESTING=OFF
    option(BUILD_TESTING "Build the host unit tests" ON)
    if(BUILD_TESTING)
        add_subdirectory(tests)
    endif()
endif()

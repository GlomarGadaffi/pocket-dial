cmake_minimum_required (VERSION 3.16)

if(DEFINED ENV{IDF_PATH})
    include($ENV{IDF_PATH}/tools/cmake/project.cmake)
    project("SipServer")
    idf_build_set_property(COMPILE_DEFINITIONS "LV_TICK_CUSTOM_SYS_TIME_EXPR=((esp_timer_get_time()/1000LL))" APPEND)
else()
    project ("SipServer")

    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)

    if (WIN32)
        # windows.h's max()/min() macros collide with std::max/std::min (e.g.
        # Registrar.cpp's noteChange()) unless suppressed. Applies to this
        # directory and tests/ (add_subdirectory below inherits directory
        # properties regardless of its own project() call).
        add_compile_definitions(NOMINMAX)
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
    # up too. tests/CMakeLists.txt (via add_subdirectory below) also calls
    # find_package(OpenSSL REQUIRED); whichever of the two configures first,
    # CMake caches the result, so this is not a second real search.
    find_package(OpenSSL REQUIRED)
    target_link_libraries(SipServer OpenSSL::Crypto)

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

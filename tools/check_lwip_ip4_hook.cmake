# Issue #496 / #509 review: post-build proof that lwIP's ip4_input() CALLS the
# IPv4 input guard (main/pd_lwip_hooks.c, src/Helpers/Ip4InputGuard.h).
#
# The guard only exists if lwIP's own ip4.c was compiled with our hook header
# (ESP_IDF_LWIP_HOOK_FILENAME, set on the lwip component in the root
# CMakeLists.txt). If that wiring ever silently stops applying -- a renamed
# property, an IDF that drops the include, a cached build dir -- ip4.c compiles
# without LWIP_HOOK_IP4_INPUT, the "-u pd_ip4_input_hook" link option still
# links our function in, and nothing calls it. Reassembly would then run
# unguarded, which is the ~500 KB-per-socket DoS the guard exists to stop.
#
# So check lwIP's archive itself: ip4.c's object must carry an UNDEFINED
# reference to pd_ip4_input_hook. That reference exists only if the macro
# expanded at the call site in ip4_input().
#
# Invoked from the root CMakeLists.txt as:
#   cmake -DNM=<nm> -DLWIP_LIB=<liblwip.a> -P check_lwip_ip4_hook.cmake

if(NOT NM OR NOT LWIP_LIB)
    message(FATAL_ERROR "check_lwip_ip4_hook: NM and LWIP_LIB must be set")
endif()

execute_process(
    COMMAND "${NM}" -A "${LWIP_LIB}"
    OUTPUT_VARIABLE symbols
    RESULT_VARIABLE nm_rc)
if(NOT nm_rc EQUAL 0)
    message(FATAL_ERROR "check_lwip_ip4_hook: '${NM}' failed on ${LWIP_LIB} (${nm_rc})")
endif()

# nm -A prefixes every line with "<archive>:<member>:"; the member for ip4.c is
# ip4.c.obj (CMake) or ip4.c.o. An undefined symbol shows as "U <name>".
if(symbols MATCHES "ip4\\.c\\.(obj|o):[ \t]+U pd_ip4_input_hook")
    # Printed on success so a build log PROVES the check ran (see #420's check).
    message(STATUS "Issue #496: lwIP ip4_input() calls pd_ip4_input_hook (IPv4 input guard wired)")
else()
    message(FATAL_ERROR
        "Issue #496: lwIP's ip4.c does not call pd_ip4_input_hook. The IPv4 input "
        "guard is NOT wired (ESP_IDF_LWIP_HOOK_FILENAME did not reach lwIP), so "
        "reassembled fragments are unguarded. See tools/check_lwip_ip4_hook.cmake.")
endif()

# Issue #1145: post-build proof that the Ethernet images install the count-only
# esp_eth input hook (main/pd_eth_ingress.c).
#
# The hook is reached only through a function pointer that
# pd_eth_ingress_install() hands to esp_eth_update_input_path_info(). If an
# edit drops the install call from an eth main, the image still builds and
# boots, and the glue's own input path silently stays in place: no counts.
#
# So check three links of the chain:
#   1. the eth main's object carries an UNDEFINED reference to
#      pd_eth_ingress_install (the call site was compiled),
#   2. pd_eth_ingress.c's object references esp_eth_update_input_path_info
#      (the install really installs), and
#   3. the linked image defines pd_eth_ingress_input (the hook is in it).
# And one property of it: pd_eth_ingress.c's object emits no pd_l2_ helper
# out of line. The hook is IRAM_ATTR; an out-of-line copy of a header helper
# would sit in flash (PD_L2_INLINE, L2IngressVerdict.h, is always_inline for this).
#
# Invoked from the root CMakeLists.txt as:
#   cmake -DNM=<nm> -DELF=<app.elf> -DMAIN_LIB=<libmain.a> -P check_eth_input_hook.cmake

if(NOT NM OR NOT ELF OR NOT MAIN_LIB)
    message(FATAL_ERROR "check_eth_input_hook: NM, ELF and MAIN_LIB must be set")
endif()

foreach(target IN ITEMS MAIN_LIB ELF)
    execute_process(
        COMMAND "${NM}" -A "${${target}}"
        OUTPUT_VARIABLE symbols_${target}
        RESULT_VARIABLE nm_rc)
    if(NOT nm_rc EQUAL 0)
        message(FATAL_ERROR "check_eth_input_hook: '${NM}' failed on ${${target}} (${nm_rc})")
    endif()
endforeach()

# nm -A prefixes every line with "<archive>:<member>:" (or "<elf>:"). An
# undefined symbol shows as "U <name>", a defined function as "T"/"t".
set(missing "")
if(NOT symbols_MAIN_LIB MATCHES "esp_main_eth(_lan8720)?\\.cpp\\.(obj|o):[ \t]+U pd_eth_ingress_install")
    string(APPEND missing " the eth main does not call pd_eth_ingress_install;")
endif()
if(NOT symbols_MAIN_LIB MATCHES "pd_eth_ingress\\.c\\.(obj|o):[ \t]+U esp_eth_update_input_path_info")
    string(APPEND missing " pd_eth_ingress.c does not call esp_eth_update_input_path_info;")
endif()
if(NOT symbols_ELF MATCHES "[0-9a-f]+ [Tt] pd_eth_ingress_input\n")
    string(APPEND missing " the image does not link pd_eth_ingress_input;")
endif()
if(symbols_MAIN_LIB MATCHES "pd_eth_ingress\\.c\\.(obj|o):[0-9a-f]+ [Tt] (pd_l2_[A-Za-z0-9_]+)")
    string(APPEND missing " pd_eth_ingress.c emits ${CMAKE_MATCH_2} out of line (flash, not IRAM);")
endif()

if(missing)
    message(FATAL_ERROR
        "Issue #1145: esp_eth input hook check failed:${missing} "
        "see tools/check_eth_input_hook.cmake.")
endif()
# Printed on success so a build log PROVES the check ran (see #420's check).
message(STATUS "Issue #1145: eth main installs the esp_eth input hook (pd_eth_ingress_input linked)")

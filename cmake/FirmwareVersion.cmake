# FirmwareVersion.cmake -- the ONE place the firmware version string is decided
# (issue #411). Used by the ESP-IDF build (as PROJECT_VER, which lands in the
# app descriptor) and by both host builds (as the POCKETDIAL_FW_VERSION compile
# definition), so /api/status reports one shape everywhere.
#
# WHY THIS EXISTS: with PROJECT_VER unset, ESP-IDF runs `git describe` itself
# and falls back to "1" when that fails. In CI it always failed. The build runs
# in the espressif/idf container, where git refuses the runner-owned checkout:
#
#   fatal: detected dubious ownership in repository at '/__w/pocket-dial/pocket-dial'
#   -- Could not use 'git describe' to determine PROJECT_VER.
#   -- App "SipServer" version: 1
#
# So this calls git itself with the checkout named as a safe.directory ON THIS
# ONE COMMAND ONLY (`git -c`), never written to any config. A global
# safe.directory in the container would disable the ownership check for every
# repository, for the rest of the job. core.fsmonitor is forced off on the
# same command: fsmonitor is how a repository's config gets code to run from
# an otherwise read-only git call, and a version stamp has no need of it.
#
# THE 31-CHARACTER LIMIT: esp_app_desc_t.version is char[32]. IDF truncates a
# longer PROJECT_VER, and the part it cuts is the END -- which is exactly where
# `-dirty` lives. `v1.5.0-beta.2-93-g98cc830-dirty` is already 31, so a few
# more commits since the tag would silently drop the dirty flag. When the full
# describe does not fit, this falls back to the abbreviated commit hash plus
# `-dirty`, which always fits and never loses either the commit or the flag.
#
# OVERRIDE: -DPOCKETDIAL_FW_VERSION=<string> wins over git, for release or
# reproducible builds that stamp an exact string. It is still held to the
# 31-character limit.

# Captured at include time: inside the function CMAKE_CURRENT_LIST_DIR would be
# the CALLER's directory, and CMAKE_CURRENT_FUNCTION_LIST_DIR needs CMake 3.17
# while the top-level project declares 3.16 as its minimum.
set(_POCKETDIAL_FWVER_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}")

# The length limit comes from ONE file, shared with tools/ci/check_app_version.py,
# so the build and the gate that checks it cannot disagree about when the
# fallback applies. (A number here and another in the script is exactly the
# drift a gate exists to catch, not to suffer from.)
file(STRINGS "${_POCKETDIAL_FWVER_CMAKE_DIR}/FirmwareVersionMaxLen.txt"
     POCKETDIAL_FW_VERSION_MAX_LEN LIMIT_COUNT 1)
string(STRIP "${POCKETDIAL_FW_VERSION_MAX_LEN}" POCKETDIAL_FW_VERSION_MAX_LEN)
if(NOT POCKETDIAL_FW_VERSION_MAX_LEN MATCHES "^[0-9]+$")
    message(FATAL_ERROR "cmake/FirmwareVersionMaxLen.txt must hold a single number, "
                        "got '${POCKETDIAL_FW_VERSION_MAX_LEN}'")
endif()

# STALENESS: the stamp is decided at CONFIGURE time, and an incremental
# `idf.py build` does not reconfigure by itself. Without this, committing and
# rebuilding locally would flash the NEW code stamped with the OLD commit --
# attributing a bench result to the wrong build, which is the exact failure
# #411 exists to remove. So the files that change on commit / checkout /
# stage are made configure dependencies: CMake re-runs, and the stamp is
# recomputed, whenever one of them moves.
#
#   HEAD           checkout, or a detached-HEAD commit
#   <branch ref>   a commit on the current branch
#   packed-refs    a ref that lives packed rather than loose
#   index          staging, commit, checkout
#
# Paths come from `git rev-parse --git-path`, which maps them correctly for a
# linked worktree (HEAD and index are per-worktree; refs are in the common dir).
#
# NOT covered, stated rather than implied: editing a tracked file WITHOUT
# staging it touches none of these, so a build right after such an edit keeps
# the previous clean/-dirty flag until something reconfigures. CI is unaffected:
# `idf.py set-target` reconfigures from scratch on every run, and
# tools/ci/check_app_version.py fails any image whose stamp names a different
# commit from the checkout's.
function(_pocketdial_reconfigure_on_git_change git_cmd repo_root)
    set(deps "")
    foreach(what HEAD index packed-refs)
        execute_process(COMMAND ${git_cmd} rev-parse --git-path ${what}
                        OUTPUT_VARIABLE p RESULT_VARIABLE rc OUTPUT_STRIP_TRAILING_WHITESPACE
                        ERROR_QUIET)
        if(rc EQUAL 0 AND NOT "${p}" STREQUAL "")
            get_filename_component(p "${p}" ABSOLUTE BASE_DIR "${repo_root}")
            if(EXISTS "${p}")
                list(APPEND deps "${p}")
            endif()
        endif()
    endforeach()
    # The branch HEAD points at, if any (a detached HEAD has none; HEAD itself
    # then changes on every checkout and commit, and is already listed).
    execute_process(COMMAND ${git_cmd} symbolic-ref -q HEAD
                    OUTPUT_VARIABLE ref RESULT_VARIABLE rc OUTPUT_STRIP_TRAILING_WHITESPACE
                    ERROR_QUIET)
    if(rc EQUAL 0 AND NOT "${ref}" STREQUAL "")
        execute_process(COMMAND ${git_cmd} rev-parse --git-path ${ref}
                        OUTPUT_VARIABLE p RESULT_VARIABLE rc2 OUTPUT_STRIP_TRAILING_WHITESPACE
                        ERROR_QUIET)
        if(rc2 EQUAL 0 AND NOT "${p}" STREQUAL "")
            get_filename_component(p "${p}" ABSOLUTE BASE_DIR "${repo_root}")
            if(EXISTS "${p}")
                list(APPEND deps "${p}")
            endif()
        endif()
    endif()
    if(deps)
        set_property(DIRECTORY "${CMAKE_SOURCE_DIR}" APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${deps})
    endif()
endfunction()

function(pocketdial_firmware_version out_var)
    # #384 (H1): an optional second argument is a suffix every stamp carries,
    # ahead of any -dirty and inside the same limit (the bench probe's "-probe").
    set(suffix "${ARGV1}")
    string(LENGTH "${suffix}" suffix_len)
    math(EXPR describe_max "${POCKETDIAL_FW_VERSION_MAX_LEN} - ${suffix_len}")
    # The repository root, independent of which project included this file:
    # the top-level project and tests/ both use it. This file lives in <root>/cmake.
    get_filename_component(repo_root "${_POCKETDIAL_FWVER_CMAKE_DIR}/.." REALPATH)

    find_package(Git QUIET)
    if(GIT_FOUND)
        set(git_cmd "${GIT_EXECUTABLE}"
            -c "safe.directory=${repo_root}"
            -c core.fsmonitor=false
            -C "${repo_root}")
    endif()

    if(DEFINED POCKETDIAL_FW_VERSION AND NOT "${POCKETDIAL_FW_VERSION}" STREQUAL "")
        set(version "${POCKETDIAL_FW_VERSION}")
        set(source "override")
        # ONE-SHOT (#461 review, MAJOR 2): a -D lands in CMakeCache.txt, so it
        # used to stamp every later build too, and (with no git deps registered)
        # a commit never reconfigured past it -- new code under an old stamp.
        # Consume it here, and still register the git dependencies, so the next
        # commit/checkout reconfigures to the git value unless -D is passed again.
        unset(POCKETDIAL_FW_VERSION CACHE)
        if(GIT_FOUND)
            _pocketdial_reconfigure_on_git_change("${git_cmd}" "${repo_root}")
        endif()
    else()
        set(version "unknown")
        set(source "no git")
        if(GIT_FOUND)
            # #872: --abbrev=12, pinned. git's default abbreviation grows with
            # the object count, so a stamp taken early and a check run later
            # (tools/ci/check_app_version.py, ABBREV there) could differ in
            # length for the same commit. 12 + "v1.5.1-123-g" + "-dirty" is 30.
            execute_process(
                COMMAND ${git_cmd} describe --tags --always --dirty --abbrev=12
                OUTPUT_VARIABLE full
                ERROR_VARIABLE err
                RESULT_VARIABLE rc
                OUTPUT_STRIP_TRAILING_WHITESPACE)
            if(rc EQUAL 0 AND NOT "${full}" STREQUAL "")
                _pocketdial_reconfigure_on_git_change("${git_cmd}" "${repo_root}")
                string(LENGTH "${full}" full_len)
                if(full_len LESS_EQUAL describe_max)
                    set(version "${full}")
                    set(source "git describe")
                else()
                    # Too long for the app descriptor: keep the commit and the
                    # dirty flag, drop the tag. `--exclude=*` matches every tag
                    # out, so --always yields the bare abbreviated hash.
                    #
                    # --abbrev=7, NOT longer, on purpose. tests/run.py's
                    # same_commit() accepts a bare hash only as a PREFIX of its
                    # own describe's -g<hash> (exact otherwise, #461 review), and
                    # an unpinned describe's -g<hash> uses git's default
                    # abbreviation (7, auto-extended for uniqueness). --abbrev is
                    # a MINIMUM that git also extends for uniqueness, so this hash
                    # is a prefix of any describe's; a 12-char one would not be.
                    execute_process(
                        COMMAND ${git_cmd} describe --always --dirty --abbrev=7 "--exclude=*"
                        OUTPUT_VARIABLE short
                        RESULT_VARIABLE rc2
                        OUTPUT_STRIP_TRAILING_WHITESPACE)
                    if(rc2 EQUAL 0 AND NOT "${short}" STREQUAL "")
                        set(version "${short}")
                        set(source "git hash (describe '${full}' exceeds ${describe_max} chars)")
                    endif()
                endif()
            else()
                # Say WHY, loudly, rather than leave the next person to find a
                # version of "unknown" on a board. This is the message CI used
                # to swallow.
                string(STRIP "${err}" err)
                message(WARNING "pocket-dial: git describe failed (${rc}): ${err}")
            endif()
        endif()
    endif()

    if(NOT "${suffix}" STREQUAL "")
        if("${version}" MATCHES "^(.*)-dirty$")
            set(version "${CMAKE_MATCH_1}${suffix}-dirty")
        else()
            set(version "${version}${suffix}")
        endif()
    endif()

    # JSON-safe by construction (#461 review): /api/status streams the version
    # into its JSON raw, with no per-request escaping (which allocated on the
    # http_conn stack). git describe and the short-hash fallback always fit
    # this set; an override that does not is refused here, not at runtime.
    if(NOT "${version}" MATCHES "^[A-Za-z0-9._+-]+$")
        message(FATAL_ERROR
            "pocket-dial: firmware version '${version}' has characters outside "
            "[A-Za-z0-9._+-]; /api/status emits it into JSON unescaped.")
    endif()

    string(LENGTH "${version}" len)
    if(len GREATER POCKETDIAL_FW_VERSION_MAX_LEN)
        message(FATAL_ERROR
            "pocket-dial: firmware version '${version}' is ${len} chars; the app "
            "descriptor holds ${POCKETDIAL_FW_VERSION_MAX_LEN}. It would be truncated.")
    endif()

    message(STATUS "pocket-dial firmware version: ${version} (${source})")
    set(${out_var} "${version}" PARENT_SCOPE)
endfunction()

# (#461 review, MAJOR 3) The host builds get the stamp from ONE generated header,
# included only by src/Helpers/FirmwareInfo.cpp, instead of a directory-wide
# compile definition: a definition that changes on every commit changes every
# TU's flags and rebuilt the whole tree. file(CONFIGURE)-style write-if-changed
# means a new commit touches this header, and so recompiles only FirmwareInfo.cpp.
# Call once per build tree; include_directories(${CMAKE_BINARY_DIR}/generated).
function(pocketdial_write_fw_version_header version)
    set(dir "${CMAKE_BINARY_DIR}/generated")
    set(path "${dir}/pocketdial_fw_version.h")
    string(REPLACE "\\" "\\\\" esc "${version}")
    string(REPLACE "\"" "\\\"" esc "${esc}")
    set(content "// Generated by cmake/FirmwareVersion.cmake (#411). Do not edit.\n#define POCKETDIAL_FW_VERSION \"${esc}\"\n")
    if(EXISTS "${path}")
        file(READ "${path}" old)
    else()
        set(old "")
    endif()
    if(NOT "${old}" STREQUAL "${content}")
        file(MAKE_DIRECTORY "${dir}")
        file(WRITE "${path}" "${content}")
    endif()
endfunction()

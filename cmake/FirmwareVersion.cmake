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

set(POCKETDIAL_FW_VERSION_MAX_LEN 31)

# Captured at include time: inside the function CMAKE_CURRENT_LIST_DIR would be
# the CALLER's directory, and CMAKE_CURRENT_FUNCTION_LIST_DIR needs CMake 3.17
# while the top-level project declares 3.16 as its minimum.
set(_POCKETDIAL_FWVER_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}")

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
    # The repository root, independent of which project included this file:
    # the top-level project and tests/ both use it. This file lives in <root>/cmake.
    get_filename_component(repo_root "${_POCKETDIAL_FWVER_CMAKE_DIR}/.." REALPATH)

    if(DEFINED POCKETDIAL_FW_VERSION AND NOT "${POCKETDIAL_FW_VERSION}" STREQUAL "")
        set(version "${POCKETDIAL_FW_VERSION}")
        set(source "override")
    else()
        set(version "unknown")
        set(source "no git")
        find_package(Git QUIET)
        if(GIT_FOUND)
            set(git_cmd "${GIT_EXECUTABLE}"
                -c "safe.directory=${repo_root}"
                -c core.fsmonitor=false
                -C "${repo_root}")
            execute_process(
                COMMAND ${git_cmd} describe --tags --always --dirty
                OUTPUT_VARIABLE full
                ERROR_VARIABLE err
                RESULT_VARIABLE rc
                OUTPUT_STRIP_TRAILING_WHITESPACE)
            if(rc EQUAL 0 AND NOT "${full}" STREQUAL "")
                _pocketdial_reconfigure_on_git_change("${git_cmd}" "${repo_root}")
                string(LENGTH "${full}" full_len)
                if(full_len LESS_EQUAL POCKETDIAL_FW_VERSION_MAX_LEN)
                    set(version "${full}")
                    set(source "git describe")
                else()
                    # Too long for the app descriptor: keep the commit and the
                    # dirty flag, drop the tag. `--exclude=*` matches every tag
                    # out, so --always yields the bare abbreviated hash.
                    #
                    # --abbrev=7, NOT longer, on purpose. tests/run.py matches
                    # the board's string against its own `git describe` by
                    # SUBSTRING, and describe's -g<hash> uses git's default
                    # abbreviation (7, auto-extended for uniqueness). --abbrev
                    # is a MINIMUM that git also extends for uniqueness, so this
                    # hash is never longer than describe's: always a prefix of
                    # it, always a substring. A 12-char hash would never be a
                    # substring of `...-g98cc830` and every clean build past
                    # the limit would fail provenance.
                    execute_process(
                        COMMAND ${git_cmd} describe --always --dirty --abbrev=7 "--exclude=*"
                        OUTPUT_VARIABLE short
                        RESULT_VARIABLE rc2
                        OUTPUT_STRIP_TRAILING_WHITESPACE)
                    if(rc2 EQUAL 0 AND NOT "${short}" STREQUAL "")
                        set(version "${short}")
                        set(source "git hash (describe '${full}' exceeds ${POCKETDIAL_FW_VERSION_MAX_LEN} chars)")
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

    string(LENGTH "${version}" len)
    if(len GREATER POCKETDIAL_FW_VERSION_MAX_LEN)
        message(FATAL_ERROR
            "pocket-dial: firmware version '${version}' is ${len} chars; the app "
            "descriptor holds ${POCKETDIAL_FW_VERSION_MAX_LEN}. It would be truncated.")
    endif()

    message(STATUS "pocket-dial firmware version: ${version} (${source})")
    set(${out_var} "${version}" PARENT_SCOPE)
endfunction()

include_guard(GLOBAL)

# rhp_set_warnings(<target>) — the project-wide warning set, applied to every RHP-owned target,
# plus the free code generation flags: unreferenced inline functions and global data dropped per
# object (/Zc:inline, /Gw; -ffunction-sections -fdata-sections lets a consumer's linker drop them).
function(rhp_set_warnings target)
    if(MSVC)
        # cl.exe and clang-cl both take MSVC-style flags.
        target_compile_options(${target} PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8 /Zc:inline /Gw)
        if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
            target_compile_options(${target} PRIVATE /Zc:preprocessor)
        endif()
        if(RHP_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow
                                                 -ffunction-sections -fdata-sections)
        if(RHP_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()

# rhp_third_party_flags(<target> [UTF8] [SECTIONS]): a third-party target RHP builds from upstream
# sources (Lua, Monocypher, replxx), which aren't clean under rhp_set_warnings: its warnings off (/W0,
# -w), plus, when asked, MSVC's /utf-8 (UTF8) and the free code generation flags (SECTIONS: /Zc:inline
# /Gw; -ffunction-sections -fdata-sections).
function(rhp_third_party_flags target)
    cmake_parse_arguments(PARSE_ARGV 1 arg "UTF8;SECTIONS" "" "")
    if(MSVC)
        set(flags "")
        if(arg_UTF8)
            list(APPEND flags /utf-8)
        endif()
        list(APPEND flags /W0)
        if(arg_SECTIONS)
            list(APPEND flags /Zc:inline /Gw)
        endif()
    else()
        set(flags -w)
        if(arg_SECTIONS)
            list(APPEND flags -ffunction-sections -fdata-sections)
        endif()
    endif()
    target_compile_options(${target} PRIVATE ${flags})
endfunction()

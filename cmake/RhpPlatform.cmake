include_guard(GLOBAL)

# Maps the CMake target system to one RHP_PLATFORM_* definition.
# Only Src/rhp/platform may branch on these; everything else uses Rhp::platform traits.
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(RHP_PLATFORM "WINDOWS")
elseif(CMAKE_SYSTEM_NAME STREQUAL "iOS")
    set(RHP_PLATFORM "IOS")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(RHP_PLATFORM "MACOS")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Android")
    set(RHP_PLATFORM "ANDROID")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(RHP_PLATFORM "LINUX")
else()
    message(FATAL_ERROR "RHP: unsupported target system '${CMAKE_SYSTEM_NAME}'")
endif()

message(STATUS "RHP: platform ${RHP_PLATFORM}, compiler ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")

# rhp_apply_platform(<target>) — adds the platform definition to a target's PUBLIC interface.
function(rhp_apply_platform target)
    target_compile_definitions(${target} PUBLIC RHP_PLATFORM_${RHP_PLATFORM}=1)
    if(RHP_PLATFORM STREQUAL "WINDOWS")
        target_compile_definitions(${target} PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    endif()
endfunction()

cmake_minimum_required(VERSION 3.28)

project(rhp
    DESCRIPTION "Remote Hot Patch - portable remote Lua execution for C++"
    HOMEPAGE_URL "https://github.com/tonytranrp/RHP"
    LANGUAGES CXX
)

set(RHP_IS_TOP_LEVEL ${PROJECT_IS_TOP_LEVEL})

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(RhpOptions)
include(RhpPlatform)
include(RhpWarnings)
include(RhpSanitizers)
include(CPM)
include(Dependencies)

add_subdirectory(Src)

if(RHP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(Tests)
endif()

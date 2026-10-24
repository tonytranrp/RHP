cmake_minimum_required(VERSION 3.28)

project(rhp
    DESCRIPTION "Remote Hot Patch - portable remote Lua execution for C++"
    HOMEPAGE_URL "https://github.com/tonytranrp/RHP"
    LANGUAGES CXX
)

set(RHP_IS_TOP_LEVEL ${PROJECT_IS_TOP_LEVEL})

# RHP uses no C++20 modules: skip the per-source dependency scan CMake does for C++20 and up
# (clang-scan-deps also failed to honour clang-cl's -imsvc system include paths on CI runners).
# Directory-scoped: a parent project including RHP keeps its own setting.
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

# Prepended: RHP's own modules win over same-named ones a parent project put on the path.
list(PREPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(RhpOptions)
include(RhpPlatform)
include(RhpWarnings)
include(RhpSanitizers)
include(CPM)
include(Dependencies)
include(RhpBuildConfig)

add_subdirectory(Src)

if(RHP_INSTALL)
    include(RhpInstall)
endif()

if(RHP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(Tests)
endif()

if(RHP_BUILD_EXAMPLES)
    add_subdirectory(Examples)
endif()

if(RHP_BUILD_TOOLS AND RHP_ENABLE)
    add_subdirectory(Tools)
endif()

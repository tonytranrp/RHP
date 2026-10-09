include_guard(GLOBAL)

option(RHP_ENABLE "Build the live RHP host. OFF compiles hosts to inert stubs and patch points to direct calls." ON)
option(RHP_BUILD_TESTS "Build Tests/" ${RHP_IS_TOP_LEVEL})
option(RHP_BUILD_EXAMPLES "Build Examples/" ${RHP_IS_TOP_LEVEL})
option(RHP_BUILD_TOOLS "Build Tools/ (rhp-cli)" ${RHP_IS_TOP_LEVEL})
option(RHP_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
set(RHP_SANITIZE "" CACHE STRING "Sanitizers to enable: 'address;undefined', 'address' (MSVC) or 'thread'")

if(NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 23)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_CXX_STANDARD LESS 23)
    message(FATAL_ERROR "RHP requires C++23 (CMAKE_CXX_STANDARD is ${CMAKE_CXX_STANDARD})")
endif()

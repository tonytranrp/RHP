include_guard(GLOBAL)

# rhp_asio: standalone Asio (header-only). Only Rhp::net links it, PRIVATE and build tree only, and
# only its .cpp files include asio.hpp, so Asio never reaches a consumer (nor the installed package).
# SYSTEM keeps upstream warnings out of RHP's warnings-as-errors build.
if(NOT DEFINED asio_SOURCE_DIR)
    message(FATAL_ERROR "RHP: include RhpAsio after CPMAddPackage(NAME asio ...)")
endif()

add_library(rhp_asio INTERFACE)
add_library(Rhp::asio ALIAS rhp_asio)
# Since asio-1-38 the headers live in include/ and asio/include is a git symlink to it (older
# releases have only asio/include). Prefer the real directory: clang-cl doesn't resolve the symlink
# where git created one (GitHub's Windows runners), and checkouts without symlink support turn it
# into a one-line file.
if(EXISTS "${asio_SOURCE_DIR}/include/asio.hpp")
    set(rhp_asio_include "${asio_SOURCE_DIR}/include")
else()
    set(rhp_asio_include "${asio_SOURCE_DIR}/asio/include")
endif()
target_include_directories(rhp_asio SYSTEM INTERFACE "${rhp_asio_include}")
target_compile_definitions(rhp_asio INTERFACE ASIO_STANDALONE ASIO_NO_DEPRECATED)
target_link_libraries(rhp_asio INTERFACE Threads::Threads)
if(RHP_PLATFORM STREQUAL "WINDOWS")
    # Windows 10 (RHP's floor) for the IOCP features Asio picks at compile time.
    target_compile_definitions(rhp_asio INTERFACE _WIN32_WINNT=0x0A00)
    target_link_libraries(rhp_asio INTERFACE ws2_32 mswsock)
endif()

include_guard(GLOBAL)

# rhp_asio: standalone Asio (header-only). Only Rhp::net links it, PRIVATE, and only its .cpp files
# include asio.hpp, so Asio never reaches a consumer. SYSTEM keeps upstream warnings out of RHP's
# warnings-as-errors build.
if(NOT DEFINED asio_SOURCE_DIR)
    message(FATAL_ERROR "RHP: include RhpAsio after CPMAddPackage(NAME asio ...)")
endif()

find_package(Threads REQUIRED)

add_library(rhp_asio INTERFACE)
add_library(Rhp::asio ALIAS rhp_asio)
# The upstream repo keeps headers in asio/include (a symlink to include/ in some checkouts).
if(EXISTS "${asio_SOURCE_DIR}/asio/include/asio.hpp")
    set(rhp_asio_include "${asio_SOURCE_DIR}/asio/include")
else()
    set(rhp_asio_include "${asio_SOURCE_DIR}/include")
endif()
target_include_directories(rhp_asio SYSTEM INTERFACE "${rhp_asio_include}")
target_compile_definitions(rhp_asio INTERFACE ASIO_STANDALONE ASIO_NO_DEPRECATED)
target_link_libraries(rhp_asio INTERFACE Threads::Threads)
if(RHP_PLATFORM STREQUAL "WINDOWS")
    # Windows 10 (RHP's floor) for the IOCP features Asio picks at compile time.
    target_compile_definitions(rhp_asio INTERFACE _WIN32_WINNT=0x0A00)
    target_link_libraries(rhp_asio INTERFACE ws2_32 mswsock)
endif()

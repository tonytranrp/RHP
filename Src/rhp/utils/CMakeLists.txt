rhp_add_module(utils
    HEADERS
        base64.hpp
        byte_buffer.hpp
        crc32c.hpp
        fixed_string.hpp
        function_traits.hpp
        overloaded.hpp
        scope_guard.hpp
        siphash.hpp
        spsc_ring.hpp
        type_list.hpp
        units.hpp
        utf8.hpp
    SOURCES
        crc32c.cpp
)

# 64-bit ARM Linux / Android without the CRC extension in the compile target (Android's and generic
# Linux's baseline): crc32c.cpp checks the CPU at run time instead (__builtin_cpu_supports, whose
# runtime asks the OS), where the toolchain compiles and links that. Apple keeps the compile-time
# check: macOS targets have the extension; iOS uses the tables.
if(RHP_PLATFORM MATCHES "^(LINUX|ANDROID)$" AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
    include(CheckCXXSourceCompiles)
    check_cxx_source_compiles([=[
        #include <arm_acle.h>
        #include <cstdint>
        __attribute__((target("crc"))) static std::uint32_t step(std::uint32_t c, std::uint64_t v) { return __crc32cd(c, v); }
        int main() { return __builtin_cpu_supports("crc") ? static_cast<int>(step(0, 1) & 1u) : 0; }
    ]=] RHP_HAS_AARCH64_CPU_CHECK)
    if(RHP_HAS_AARCH64_CPU_CHECK)
        target_compile_definitions(rhp_utils PRIVATE RHP_CRC32C_ARM_RUNTIME=1)
    endif()
endif()

#pragma once

#include <cstdint>

#include <rhp/utils/byte_buffer.hpp>

namespace Rhp::utils {

// CRC-32C (Castagnoli, reflected polynomial 0x82F63B78) - per-frame integrity on non-TLS links.
// The CPU's CRC32C instruction where it has one (SSE4.2 on x86-64, checked at run time; the ARMv8 CRC
// extension when the compiler targets it, or checked at run time on 64-bit ARM Linux / Android when
// CMake sets RHP_CRC32C_ARM_RUNTIME), else slicing-by-8 tables; every path gives the same result.
[[nodiscard]] std::uint32_t crc32c(bytes_view data, std::uint32_t crc = 0) noexcept;
// Always the tables (what crc32c falls back to): for tests and comparisons.
[[nodiscard]] std::uint32_t crc32c_portable(bytes_view data, std::uint32_t crc = 0) noexcept;

// Incremental form: feed chunks, then read value().
class crc32c_hasher {
public:
    void update(bytes_view data) noexcept { crc_ = crc32c(data, crc_); }
    [[nodiscard]] std::uint32_t value() const noexcept { return crc_; }
    void reset() noexcept { crc_ = 0; }

private:
    std::uint32_t crc_ = 0;
};

} // namespace Rhp::utils

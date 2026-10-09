#pragma once

#include <cstdint>

#include <rhp/utils/byte_buffer.hpp>

namespace Rhp::utils {

// CRC-32C (Castagnoli, reflected polynomial 0x82F63B78) — per-frame integrity on non-TLS links.
// Software slicing-by-8; hardware (SSE4.2 / ARMv8 CRC) dispatch can slot in behind the same API.
[[nodiscard]] std::uint32_t crc32c(bytes_view data, std::uint32_t crc = 0) noexcept;

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

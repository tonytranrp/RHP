#pragma once

#include <bit>
#include <concepts>
#include <cstddef>
#include <cstring>
#include <memory_resource>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace Rhp::utils {

using bytes_view = std::span<const std::byte>;

[[nodiscard]] inline bytes_view as_bytes(std::string_view text) noexcept {
    return std::as_bytes(std::span{text.data(), text.size()});
}

// Little-endian encode/decode of unsigned integers — the wire byte order.
template <std::unsigned_integral T>
constexpr void store_le(std::span<std::byte, sizeof(T)> out, T value) noexcept {
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        out[i] = static_cast<std::byte>(value >> (8 * i));
    }
}

template <std::unsigned_integral T>
[[nodiscard]] constexpr T load_le(std::span<const std::byte, sizeof(T)> in) noexcept {
    T value = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        value |= static_cast<T>(static_cast<T>(in[i]) << (8 * i));
    }
    return value;
}

// Growable byte buffer with an injectable memory resource.
class byte_buffer {
public:
    byte_buffer() = default;
    explicit byte_buffer(std::pmr::memory_resource* resource) : bytes_(resource) {}

    [[nodiscard]] std::size_t size() const noexcept { return bytes_.size(); }
    [[nodiscard]] bool empty() const noexcept { return bytes_.empty(); }
    [[nodiscard]] bytes_view view() const noexcept { return bytes_; }
    [[nodiscard]] std::span<std::byte> mutable_view() noexcept { return bytes_; }

    void clear() noexcept { bytes_.clear(); }
    void reserve(std::size_t n) { bytes_.reserve(n); }
    void resize(std::size_t n) { bytes_.resize(n); }

    void append(bytes_view data) { bytes_.insert(bytes_.end(), data.begin(), data.end()); }
    void append(std::string_view text) { append(as_bytes(text)); }

    template <std::unsigned_integral T>
    void append_le(T value) {
        const std::size_t at = bytes_.size();
        bytes_.resize(at + sizeof(T));
        store_le<T>(std::span<std::byte, sizeof(T)>{bytes_.data() + at, sizeof(T)}, value);
    }

    // Reads sizeof(T) bytes at offset; nullopt if out of range.
    template <std::unsigned_integral T>
    [[nodiscard]] std::optional<T> read_le(std::size_t offset) const noexcept {
        if (offset > bytes_.size() || bytes_.size() - offset < sizeof(T)) {
            return std::nullopt;
        }
        return load_le<T>(std::span<const std::byte, sizeof(T)>{bytes_.data() + offset, sizeof(T)});
    }

    [[nodiscard]] bool operator==(const byte_buffer& other) const noexcept {
        return bytes_.size() == other.bytes_.size() &&
               (bytes_.empty() || std::memcmp(bytes_.data(), other.bytes_.data(), bytes_.size()) == 0);
    }

private:
    std::pmr::vector<std::byte> bytes_;
};

} // namespace Rhp::utils

#pragma once

#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
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

// Little-endian encode/decode of unsigned integers - the wire byte order.
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

    // One memcpy (a pmr vector's insert copies element by element through the allocator on some
    // standard libraries). `data` may be a view of this buffer.
    void append(bytes_view data) {
        if (data.empty()) {
            return;
        }
        const std::size_t at = bytes_.size();
        const std::byte* from = data.data();
        const auto from_addr = reinterpret_cast<std::uintptr_t>(from);
        const auto own_addr = reinterpret_cast<std::uintptr_t>(bytes_.data());
        const bool inside = !bytes_.empty() && from_addr >= own_addr && from_addr < own_addr + at;
        const std::size_t offset = inside ? static_cast<std::size_t>(from - bytes_.data()) : 0;
        make_room(at + data.size());
        bytes_.resize(at + data.size());
        std::memcpy(bytes_.data() + at, inside ? bytes_.data() + offset : from, data.size());
    }
    void append(std::string_view text) { append(as_bytes(text)); }

    template <std::unsigned_integral T>
    void append_le(T value) {
        const std::size_t at = bytes_.size();
        make_room(at + sizeof(T));
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
    // Small writes (an encoder appending a few bytes at a time) start from 64 bytes and double, instead
    // of reallocating at 1, 2, 3, 4, 6, 9, ... bytes.
    static constexpr std::size_t kFirstCapacity = 64;

    void make_room(std::size_t total) {
        if (total > bytes_.capacity()) {
            std::size_t grown = bytes_.capacity() * 2;
            grown = grown < kFirstCapacity ? kFirstCapacity : grown;
            bytes_.reserve(total > grown ? total : grown);
        }
    }

    std::pmr::vector<std::byte> bytes_;
};

} // namespace Rhp::utils

#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>

namespace Rhp::security {

// A pre-shared secret (16..64 bytes; 32 is what `rhp-cli keygen` makes). Wiped on destruction,
// never printed. Text form is standard base64.
class key {
public:
    static constexpr std::size_t kMinSize = 16;
    static constexpr std::size_t kMaxSize = 64; // BLAKE2b's key limit

    key() = default;
    ~key();
    key(const key& other) = default;
    key& operator=(const key& other);
    key(key&& other) noexcept;
    key& operator=(key&& other) noexcept;

    [[nodiscard]] static result<key> from_bytes(std::span<const std::byte> bytes);
    [[nodiscard]] static result<key> from_base64(std::string_view text);
    // The base64 text of an environment variable (RHP_KEY_DEV=...).
    [[nodiscard]] static result<key> from_env(std::string_view variable);
    // A file holding the base64 text (surrounding whitespace ignored).
    [[nodiscard]] static result<key> from_file(const std::string& path);
    // 32 fresh random bytes.
    [[nodiscard]] static result<key> generate();

    [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return bytes_; }
    [[nodiscard]] bool empty() const noexcept { return bytes_.empty(); }
    [[nodiscard]] std::string to_base64() const;

    // Whether the bytes look chosen by a person rather than random: printable ASCII only (a
    // passphrase, base64-encoded) or fewer distinct values than half the size (zeros, a repeated
    // pattern). 32 random bytes pass both with near certainty. For warnings only (identity files
    // report it): never a reason to refuse a key.
    [[nodiscard]] bool looks_weak() const noexcept;

private:
    void wipe() noexcept;

    std::vector<std::byte> bytes_;
};

// Zeroes memory in a way the optimizer keeps (secrets leaving scope).
void secure_wipe(void* data, std::size_t size) noexcept;

[[nodiscard]] std::string base64_encode(std::span<const std::byte> bytes);
[[nodiscard]] result<std::vector<std::byte>> base64_decode(std::string_view text);

} // namespace Rhp::security

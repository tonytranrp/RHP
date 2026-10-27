#include <array>
#include <cstddef>
#include <cstdlib>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/security/detail/text.hpp>
#include <rhp/security/hash.hpp>
#include <rhp/security/key.hpp>
#include <rhp/utils/base64.hpp>
#include <rhp/utils/scope_guard.hpp>

namespace Rhp::security {

void secure_wipe(void* data, std::size_t size) noexcept {
    // Volatile stores can't be optimized away as dead.
    auto* p = static_cast<volatile unsigned char*>(data);
    for (std::size_t i = 0; i < size; ++i) {
        p[i] = 0;
    }
}

std::string base64_encode(std::span<const std::byte> bytes) {
    return utils::base64_encode(bytes);
}

result<std::vector<std::byte>> base64_decode(std::string_view text) {
    text = detail::trim(text);
    if (text.size() % 4 != 0) {
        return fail(errc::kInvalidArgument, "base64 text length is not a multiple of 4", "security.base64");
    }
    auto bytes = utils::base64_decode(text);
    if (!bytes) {
        return fail(errc::kInvalidArgument, "invalid base64 character", "security.base64");
    }
    return std::move(*bytes);
}

// Declared in hash.hpp; here because it needs no cryptography (it builds with RHP_ENABLE=OFF).
std::string to_hex(std::span<const std::byte> bytes) {
    constexpr std::string_view kDigits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const std::byte b : bytes) {
        const auto n = std::to_integer<unsigned>(b);
        out += kDigits[n >> 4];
        out += kDigits[n & 15u];
    }
    return out;
}

// ---- key -----------------------------------------------------------------------------------------

key::~key() {
    wipe();
}

key& key::operator=(const key& other) {
    if (this != &other) {
        wipe();
        bytes_ = other.bytes_;
    }
    return *this;
}

key::key(key&& other) noexcept : bytes_(std::move(other.bytes_)) {
    other.bytes_.clear();
}

key& key::operator=(key&& other) noexcept {
    if (this != &other) {
        wipe();
        bytes_ = std::move(other.bytes_);
        other.bytes_.clear();
    }
    return *this;
}

void key::wipe() noexcept {
    if (!bytes_.empty()) {
        secure_wipe(bytes_.data(), bytes_.size());
    }
    bytes_.clear();
}

result<key> key::from_bytes(std::span<const std::byte> bytes) {
    if (bytes.size() < kMinSize || bytes.size() > kMaxSize) {
        return fail(errc::kInvalidArgument, std::format("a key must be {}..{} bytes, got {}", kMinSize, kMaxSize, bytes.size()), "security.key");
    }
    key k;
    k.bytes_.assign(bytes.begin(), bytes.end());
    return k;
}

result<key> key::from_base64(std::string_view text) {
    auto bytes = base64_decode(text);
    if (!bytes) {
        return std::unexpected{std::move(bytes).error()};
    }
    const utils::scope_guard wipe{[&bytes]() noexcept { secure_wipe(bytes->data(), bytes->size()); }};
    return from_bytes(*bytes);
}

result<key> key::from_env(std::string_view variable) {
    const std::string name{variable};
#if defined(_MSC_VER)
    char* text = nullptr;
    std::size_t length = 0;
    if (_dupenv_s(&text, &length, name.c_str()) != 0 || text == nullptr) {
        return fail(errc::kNotFound, std::format("environment variable {} is not set", name), "security.key");
    }
    std::string copy{text};
    secure_wipe(text, length);
    std::free(text);
    auto k = from_base64(copy);
    secure_wipe(copy.data(), copy.size());
    return k;
#else
    const char* text = std::getenv(name.c_str());
    if (text == nullptr) {
        return fail(errc::kNotFound, std::format("environment variable {} is not set", name), "security.key");
    }
    return from_base64(text);
#endif
}

result<key> key::from_file(const std::string& path) {
    auto text = detail::read_file(path);
    if (!text) {
        return fail(errc::kNotFound, std::format("can't read key file {}", path), "security.key");
    }
    auto k = from_base64(*text);
    secure_wipe(text->data(), text->size());
    return k;
}

result<key> key::generate() {
    std::array<std::byte, 32> bytes{};
    if (auto filled = platform::random_bytes(bytes); !filled) {
        return std::unexpected{std::move(filled).error()};
    }
    auto k = from_bytes(bytes);
    secure_wipe(bytes.data(), bytes.size());
    return k;
}

std::string key::to_base64() const {
    return base64_encode(bytes_);
}

} // namespace Rhp::security

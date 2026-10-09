#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/security/key.hpp>

namespace Rhp::security {

namespace {

constexpr std::string_view kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

[[nodiscard]] int sextet(char c) noexcept {
    const auto at = kAlphabet.find(c);
    return at == std::string_view::npos ? -1 : static_cast<int>(at);
}

[[nodiscard]] std::string_view trim(std::string_view text) noexcept {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())) != 0) {
        text.remove_prefix(1);
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())) != 0) {
        text.remove_suffix(1);
    }
    return text;
}

} // namespace

void secure_wipe(void* data, std::size_t size) noexcept {
    // Volatile stores can't be optimized away as dead.
    auto* p = static_cast<volatile unsigned char*>(data);
    for (std::size_t i = 0; i < size; ++i) {
        p[i] = 0;
    }
}

std::string base64_encode(std::span<const std::byte> bytes) {
    std::string out;
    out.reserve((bytes.size() + 2) / 3 * 4);
    std::size_t i = 0;
    for (; i + 3 <= bytes.size(); i += 3) {
        const auto n = (std::to_integer<std::uint32_t>(bytes[i]) << 16) | (std::to_integer<std::uint32_t>(bytes[i + 1]) << 8) |
                       std::to_integer<std::uint32_t>(bytes[i + 2]);
        out += kAlphabet[(n >> 18) & 63];
        out += kAlphabet[(n >> 12) & 63];
        out += kAlphabet[(n >> 6) & 63];
        out += kAlphabet[n & 63];
    }
    if (const std::size_t rest = bytes.size() - i; rest > 0) {
        std::uint32_t n = std::to_integer<std::uint32_t>(bytes[i]) << 16;
        if (rest == 2) {
            n |= std::to_integer<std::uint32_t>(bytes[i + 1]) << 8;
        }
        out += kAlphabet[(n >> 18) & 63];
        out += kAlphabet[(n >> 12) & 63];
        out += rest == 2 ? kAlphabet[(n >> 6) & 63] : '=';
        out += '=';
    }
    return out;
}

result<std::vector<std::byte>> base64_decode(std::string_view text) {
    text = trim(text);
    if (text.size() % 4 != 0) {
        return fail(errc::kInvalidArgument, "base64 text length is not a multiple of 4", "security.base64");
    }
    std::vector<std::byte> out;
    out.reserve(text.size() / 4 * 3);
    for (std::size_t i = 0; i < text.size(); i += 4) {
        const bool last = i + 4 == text.size();
        int v[4];
        int pad = 0;
        for (int j = 0; j < 4; ++j) {
            const char c = text[i + static_cast<std::size_t>(j)];
            if (c == '=' && last && j >= 2) {
                v[j] = 0;
                ++pad;
                continue;
            }
            if (pad > 0 || (v[j] = sextet(c)) < 0) {
                return fail(errc::kInvalidArgument, "invalid base64 character", "security.base64");
            }
        }
        const auto n = static_cast<std::uint32_t>((v[0] << 18) | (v[1] << 12) | (v[2] << 6) | v[3]);
        out.push_back(static_cast<std::byte>(n >> 16));
        if (pad < 2) {
            out.push_back(static_cast<std::byte>(n >> 8));
        }
        if (pad < 1) {
            out.push_back(static_cast<std::byte>(n));
        }
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
    auto k = from_bytes(*bytes);
    secure_wipe(bytes->data(), bytes->size());
    return k;
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
    std::ifstream in{path, std::ios::binary};
    if (!in) {
        return fail(errc::kNotFound, std::format("can't read key file {}", path), "security.key");
    }
    std::string text{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
    auto k = from_base64(text);
    secure_wipe(text.data(), text.size());
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

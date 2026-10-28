// Secrets sealed with a passphrase: Argon2i, then XChaCha20-Poly1305 (Monocypher). The format is in
// key_store.hpp.
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <format>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <monocypher.h>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/security/detail/bytes.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/key_store.hpp>

namespace Rhp::security {

using detail::u8;

namespace {

constexpr const char* kPassphraseWhere = "security.passphrase";
constexpr std::string_view kSealedPrefix = "argon2i:";
constexpr std::size_t kSaltBytes = 16;
constexpr std::size_t kAeadNonceBytes = 24;
constexpr std::size_t kAeadMacBytes = 16;
constexpr std::size_t kDerivedKeyBytes = 32;
// What a sealed value may ask of the machine that opens it.
constexpr std::uint32_t kMinMemoryKib = 8; // Argon2's minimum: 8 blocks of 1 KiB per lane
constexpr std::uint32_t kMaxMemoryKib = 1024u * 1024u;
constexpr std::uint32_t kMaxPasses = 64;

// The 32-byte key Argon2i makes of the passphrase and salt, wiped when it goes.
struct derived_key {
    std::array<std::uint8_t, kDerivedKeyBytes> bytes{};

    derived_key() = default;
    ~derived_key() { crypto_wipe(bytes.data(), bytes.size()); }
    derived_key(const derived_key&) = delete;
    derived_key& operator=(const derived_key&) = delete;
};

[[nodiscard]] result<void> derive(derived_key& out, std::string_view passphrase, std::span<const std::byte, kSaltBytes> salt, const passphrase_kdf& kdf) {
    // Argon2 needs nb_blocks KiB of 8-byte-aligned work area.
    const std::size_t words = std::size_t{kdf.memory_kib} * 1024 / sizeof(std::uint64_t);
    std::unique_ptr<std::uint64_t[]> work;
    try {
        work = std::make_unique_for_overwrite<std::uint64_t[]>(words);
    } catch (const std::bad_alloc&) {
        return fail(errc::kMemoryExceeded, std::format("Argon2i needs {} KiB", kdf.memory_kib), kPassphraseWhere);
    }
    const crypto_argon2_config config{CRYPTO_ARGON2_I, kdf.memory_kib, kdf.passes, 1};
    const crypto_argon2_inputs inputs{u8(passphrase.data()), u8(salt.data()), static_cast<std::uint32_t>(passphrase.size()), static_cast<std::uint32_t>(salt.size())};
    crypto_argon2(out.bytes.data(), static_cast<std::uint32_t>(out.bytes.size()), work.get(), config, inputs, crypto_argon2_no_extras);
    crypto_wipe(work.get(), words * sizeof(std::uint64_t));
    return {};
}

[[nodiscard]] std::string header_of(const passphrase_kdf& kdf) {
    return std::format("{}m={},t={}:", kSealedPrefix, kdf.memory_kib, kdf.passes);
}

// "m=<n>,t=<n>:" after the prefix: the parameters and where the base64 starts.
[[nodiscard]] result<passphrase_kdf> read_header(std::string_view sealed, std::size_t& body) {
    const auto bad = [] { return fail(errc::kInvalidArgument, "not a passphrase-sealed value (argon2i:m=<KiB>,t=<passes>:<base64>)", kPassphraseWhere); };
    if (!sealed.starts_with(kSealedPrefix)) {
        return bad();
    }
    std::string_view rest = sealed.substr(kSealedPrefix.size());
    passphrase_kdf kdf;
    const auto number = [&](std::string_view label, char end, std::uint32_t& out) {
        if (!rest.starts_with(label)) {
            return false;
        }
        rest.remove_prefix(label.size());
        const auto [ptr, ec] = std::from_chars(rest.data(), rest.data() + rest.size(), out);
        if (ec != std::errc{} || ptr == rest.data() + rest.size() || *ptr != end) {
            return false;
        }
        rest.remove_prefix(static_cast<std::size_t>(ptr - rest.data()) + 1);
        return true;
    };
    if (!number("m=", ',', kdf.memory_kib) || !number("t=", ':', kdf.passes)) {
        return bad();
    }
    if (kdf.memory_kib < kMinMemoryKib || kdf.memory_kib > kMaxMemoryKib || kdf.passes < 1 || kdf.passes > kMaxPasses) {
        return fail(errc::kInvalidArgument, std::format("Argon2i with {} KiB and {} passes is outside what this build opens ({}..{} KiB, 1..{} passes)", kdf.memory_kib, kdf.passes, kMinMemoryKib, kMaxMemoryKib, kMaxPasses),
                    kPassphraseWhere);
    }
    body = sealed.size() - rest.size();
    return kdf;
}

} // namespace

bool is_passphrase_sealed(std::string_view value) noexcept {
    return value.starts_with(kSealedPrefix);
}

result<std::string> seal_with_passphrase(std::span<const std::byte> secret, std::string_view passphrase, const passphrase_kdf& kdf) {
    if (kdf.memory_kib < kMinMemoryKib || kdf.memory_kib > kMaxMemoryKib || kdf.passes < 1 || kdf.passes > kMaxPasses) {
        return fail(errc::kInvalidArgument, std::format("Argon2i takes {}..{} KiB and 1..{} passes", kMinMemoryKib, kMaxMemoryKib, kMaxPasses), kPassphraseWhere);
    }
    // salt || nonce || mac || ciphertext
    std::vector<std::byte> body(kSaltBytes + kAeadNonceBytes + kAeadMacBytes + secret.size());
    if (auto filled = platform::random_bytes(std::span{body}.first(kSaltBytes + kAeadNonceBytes)); !filled) {
        return std::unexpected{std::move(filled).error()};
    }
    const std::span<const std::byte, kSaltBytes> salt{body.data(), kSaltBytes};
    derived_key k;
    if (auto ok = derive(k, passphrase, salt, kdf); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    const std::string header = header_of(kdf);
    std::byte* nonce = body.data() + kSaltBytes;
    std::byte* mac = nonce + kAeadNonceBytes;
    std::byte* cipher = mac + kAeadMacBytes;
    crypto_aead_lock(u8(cipher), u8(mac), k.bytes.data(), u8(nonce), u8(header.data()), header.size(), u8(secret.data()), secret.size());
    return header + base64_encode(body);
}

result<key> open_with_passphrase(std::string_view sealed, std::string_view passphrase) {
    std::size_t at = 0;
    const auto kdf = read_header(sealed, at);
    if (!kdf) {
        return std::unexpected{kdf.error()};
    }
    const std::string_view header = sealed.substr(0, at);
    auto body = base64_decode(sealed.substr(at));
    if (!body || body->size() < kSaltBytes + kAeadNonceBytes + kAeadMacBytes) {
        return fail(errc::kInvalidArgument, "a damaged passphrase-sealed value", kPassphraseWhere);
    }
    const std::span<const std::byte, kSaltBytes> salt{body->data(), kSaltBytes};
    derived_key k;
    if (auto ok = derive(k, passphrase, salt, *kdf); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    const std::byte* nonce = body->data() + kSaltBytes;
    const std::byte* mac = nonce + kAeadNonceBytes;
    const std::byte* cipher = mac + kAeadMacBytes;
    const std::size_t size = body->size() - (kSaltBytes + kAeadNonceBytes + kAeadMacBytes);
    std::vector<std::byte> plain(size);
    const int opened = crypto_aead_unlock(u8(plain.data()), u8(mac), k.bytes.data(), u8(nonce), u8(header.data()), header.size(), u8(cipher), size);
    if (opened != 0) {
        return fail(errc::kAuth, "wrong passphrase (or the sealed value was changed)", kPassphraseWhere);
    }
    auto out = key::from_bytes(plain);
    secure_wipe(plain.data(), plain.size());
    return out;
}

} // namespace Rhp::security

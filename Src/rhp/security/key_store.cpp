// Key stores: files (plain, passphrase-sealed or wrapped), DPAPI, the Keychain and app callbacks. No
// cryptography of its own: sealing is passphrase.cpp, wrapping the platform's or the app's, so this
// builds with RHP_ENABLE=OFF too.
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/platform/key_storage.hpp>
#include <rhp/security/detail/text.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/key_handle.hpp>
#include <rhp/security/key_store.hpp>
#include <rhp/utils/scope_guard.hpp>

namespace Rhp::security {

namespace {

constexpr const char* kWhere = "security.key_store";
constexpr std::string_view kWrappedPrefix = "wrapped:";
constexpr std::string_view kFileHeader = "# RHP key: keep it private\n";

[[nodiscard]] result<void> check_name(std::string_view name) {
    const auto allowed = [](char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '.' || c == '_' || c == '-'; };
    if (name.empty() || name.size() > 64 || name.front() == '.' || !std::ranges::all_of(name, allowed)) {
        return fail(errc::kInvalidArgument, std::format("'{}' is no key name (1..64 letters, digits, '.', '_', '-'; not starting with '.')", name), kWhere);
    }
    return {};
}

// Bytes that are wiped when they go (what unwrapping and base64 decoding return).
struct wiped_bytes {
    std::vector<std::byte> bytes;

    explicit wiped_bytes(std::vector<std::byte> b) noexcept : bytes(std::move(b)) {}
    ~wiped_bytes() { secure_wipe(bytes.data(), bytes.size()); }
    wiped_bytes(const wiped_bytes&) = delete;
    wiped_bytes& operator=(const wiped_bytes&) = delete;
};

[[nodiscard]] result<key> key_from(result<std::vector<std::byte>> bytes) {
    if (!bytes) {
        return std::unexpected{std::move(bytes).error()};
    }
    const wiped_bytes plain{std::move(*bytes)};
    return key::from_bytes(plain.bytes);
}

// The quoted value of the file's `secret = "..."` line.
[[nodiscard]] result<std::string> secret_value(std::string_view text, const std::filesystem::path& path) {
    for (const detail::text_line& line : detail::content_lines(text)) {
        const auto eq = line.text.find('=');
        if (eq == std::string_view::npos || detail::trim(line.text.substr(0, eq)) != "secret") {
            continue;
        }
        const std::string_view v = detail::trim(line.text.substr(eq + 1));
        if (v.size() < 2 || v.front() != '"' || v.back() != '"') {
            break;
        }
        return std::string{v.substr(1, v.size() - 2)};
    }
    const std::u8string name = path.u8string();
    return fail(errc::kInvalidArgument, std::format("{}: no `secret = \"...\"` line", std::string_view{reinterpret_cast<const char*>(name.data()), name.size()}), kWhere);
}

} // namespace

// ---- private keys in stores -----------------------------------------------------------------------

result<void> store_key(key_store& to, std::string_view name, key_algorithm alg, std::span<const std::byte> private_key) {
    if (private_key.size() != key_handle::kPrivateKeySize) {
        return fail(errc::kInvalidArgument, std::format("a {} private key is {} bytes, got {}", to_string(alg), key_handle::kPrivateKeySize, private_key.size()), kWhere);
    }
    std::vector<std::byte> tagged;
    tagged.reserve(1 + private_key.size());
    tagged.push_back(alg == key_algorithm::kP256 ? std::byte{2} : std::byte{1});
    tagged.insert(tagged.end(), private_key.begin(), private_key.end());
    const wiped_bytes wipe{std::move(tagged)};
    auto secret = key::from_bytes(wipe.bytes);
    if (!secret) {
        return std::unexpected{std::move(secret).error()};
    }
    return to.store(name, *secret);
}

result<key_handle> load_key(const key_store& from, std::string_view name) {
    auto secret = from.load(name);
    if (!secret) {
        return std::unexpected{std::move(secret).error()};
    }
    const std::span<const std::byte> bytes = secret->bytes();
    if (bytes.size() != 1 + key_handle::kPrivateKeySize || (bytes[0] != std::byte{1} && bytes[0] != std::byte{2})) {
        return fail(errc::kInvalidArgument, std::format("'{}' holds no private key", name), kWhere);
    }
    return key_handle::from_private_key(bytes[0] == std::byte{2} ? key_algorithm::kP256 : key_algorithm::kEd25519, bytes.subspan(1));
}

// ---- files ----------------------------------------------------------------------------------------

file_key_store::file_key_store(std::filesystem::path directory, file_key_store_options options)
    : directory_(std::move(directory)), options_(std::move(options)) {}

file_key_store::file_key_store(std::filesystem::path directory, key_wrapping wrapping)
    : directory_(std::move(directory)), wrapping_(std::move(wrapping)) {}

std::filesystem::path file_key_store::path_of(std::string_view name) const {
    return directory_ / std::filesystem::path{std::u8string{name.begin(), name.end()} + u8".rhpkey"};
}

result<key> file_key_store::load(std::string_view name) const {
    if (auto ok = check_name(name); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    const std::filesystem::path path = path_of(name);
    auto text = detail::read_file(path);
    if (!text) {
        return fail(errc::kNotFound, std::format("no key '{}' in this store", name), kWhere);
    }
    const utils::scope_guard wipe_text{[&]() noexcept { secure_wipe(text->data(), text->size()); }};
    auto value = secret_value(*text, path);
    if (!value) {
        return std::unexpected{std::move(value).error()};
    }
    const utils::scope_guard wipe_value{[&]() noexcept { secure_wipe(value->data(), value->size()); }};
    if (is_passphrase_sealed(*value)) {
        if (options_.passphrase.empty()) {
            return fail(errc::kAuth, std::format("key '{}' is sealed with a passphrase and this store has none", name), kWhere);
        }
        return open_with_passphrase(*value, options_.passphrase);
    }
    if (value->starts_with(kWrappedPrefix)) {
        if (!wrapping_.unwrap) {
            return fail(errc::kInvalidArgument, std::format("key '{}' is wrapped and this store can't unwrap", name), kWhere);
        }
        auto wrapped = base64_decode(std::string_view{*value}.substr(kWrappedPrefix.size()));
        if (!wrapped) {
            return std::unexpected{std::move(wrapped).error()};
        }
        return key_from(wrapping_.unwrap(*wrapped));
    }
    return key::from_base64(*value);
}

result<void> file_key_store::store(std::string_view name, const key& secret) {
    if (auto ok = check_name(name); !ok) {
        return ok;
    }
    std::string value;
    const utils::scope_guard wipe_value{[&]() noexcept { secure_wipe(value.data(), value.size()); }};
    if (wrapping_.wrap) {
        auto wrapped = wrapping_.wrap(secret.bytes());
        if (!wrapped) {
            return std::unexpected{std::move(wrapped).error()};
        }
        value = std::string{kWrappedPrefix} + base64_encode(*wrapped);
    } else if (!options_.passphrase.empty()) {
        auto sealed = seal_with_passphrase(secret.bytes(), options_.passphrase, options_.kdf);
        if (!sealed) {
            return std::unexpected{std::move(sealed).error()};
        }
        value = std::move(*sealed);
    } else {
        value = secret.to_base64();
    }
    // One allocation of the final size, so the plain base64 leaves no reallocated copy behind.
    constexpr std::string_view kOpen = "secret = \"";
    constexpr std::string_view kClose = "\"\n";
    std::string text;
    const utils::scope_guard wipe_text{[&]() noexcept { secure_wipe(text.data(), text.size()); }};
    text.reserve(kFileHeader.size() + kOpen.size() + value.size() + kClose.size());
    text += kFileHeader;
    text += kOpen;
    text += value;
    text += kClose;
    if (auto made = platform::make_private_directory(directory_); !made) {
        return made;
    }
    return platform::write_private_file(path_of(name), std::as_bytes(std::span{text}));
}

result<void> file_key_store::remove(std::string_view name) {
    if (auto ok = check_name(name); !ok) {
        return ok;
    }
    std::error_code ec;
    if (!std::filesystem::remove(path_of(name), ec)) {
        return fail(ec ? errc::kRuntime : errc::kNotFound, ec ? ec.message() : std::format("no key '{}' in this store", name), kWhere);
    }
    return {};
}

dpapi_key_store::dpapi_key_store(std::filesystem::path directory)
    : file_key_store(std::move(directory), key_wrapping{[](std::span<const std::byte> plain) { return platform::protect(plain); },
                                                        [](std::span<const std::byte> wrapped) { return platform::unprotect(wrapped); }}) {}

// ---- Keychain -------------------------------------------------------------------------------------

keychain_key_store::keychain_key_store(std::string service) : service_(std::move(service)) {}

result<key> keychain_key_store::load(std::string_view name) const {
    if (auto ok = check_name(name); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    return key_from(platform::keychain_load(service_, name));
}

result<void> keychain_key_store::store(std::string_view name, const key& secret) {
    if (auto ok = check_name(name); !ok) {
        return ok;
    }
    return platform::keychain_store(service_, name, secret.bytes());
}

result<void> keychain_key_store::remove(std::string_view name) {
    if (auto ok = check_name(name); !ok) {
        return ok;
    }
    return platform::keychain_remove(service_, name);
}

// ---- app callbacks --------------------------------------------------------------------------------

callback_key_store::callback_key_store(key_store_callbacks callbacks) : callbacks_(std::move(callbacks)) {}

result<key> callback_key_store::load(std::string_view name) const {
    if (auto ok = check_name(name); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    if (!callbacks_.load) {
        return fail(errc::kDisabled, "this key store has no load function", kWhere);
    }
    return callbacks_.load(name);
}

result<void> callback_key_store::store(std::string_view name, const key& secret) {
    if (auto ok = check_name(name); !ok) {
        return ok;
    }
    if (!callbacks_.store) {
        return fail(errc::kDisabled, "this key store has no store function", kWhere);
    }
    return callbacks_.store(name, secret);
}

result<void> callback_key_store::remove(std::string_view name) {
    if (auto ok = check_name(name); !ok) {
        return ok;
    }
    if (!callbacks_.remove) {
        return fail(errc::kDisabled, "this key store has no remove function", kWhere);
    }
    return callbacks_.remove(name);
}

} // namespace Rhp::security

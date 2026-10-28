// RHP_ENABLE=OFF: no cryptography is built, so no key handle can be made, nothing verifies and no
// passphrase seals (key stores still keep plain and wrapped secrets: key_store.cpp).
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/key_handle.hpp>
#include <rhp/security/key_store.hpp>

namespace Rhp::security {

namespace {

constexpr const char* kDisabledMessage = "RHP is compiled out (RHP_ENABLE=0)";

} // namespace

result<key_handle> key_handle::from_private_key(key_algorithm, std::span<const std::byte>) {
    return fail(errc::kDisabled, kDisabledMessage, "security.key_handle");
}

result<key_handle> key_handle::from_ed25519(const ed25519_secret_key&) {
    return fail(errc::kDisabled, kDisabledMessage, "security.key_handle");
}

result<key_handle> key_handle::from_callback(key_algorithm, std::span<const std::byte>, sign_function) {
    return fail(errc::kDisabled, kDisabledMessage, "security.key_handle");
}

result<std::vector<std::byte>> key_handle::sign(std::span<const std::byte>) const {
    return fail(errc::kDisabled, kDisabledMessage, "security.key_handle");
}

result<void> verify(key_algorithm, std::span<const std::byte>, std::span<const std::byte>, std::span<const std::byte>) {
    return fail(errc::kDisabled, kDisabledMessage, "security.key_handle");
}

std::string key_fingerprint(key_algorithm, std::span<const std::byte>) {
    return {};
}

result<key> generate_private_key(key_algorithm) {
    return fail(errc::kDisabled, kDisabledMessage, "security.key_handle");
}

result<std::string> seal_with_passphrase(std::span<const std::byte>, std::string_view, const passphrase_kdf&) {
    return fail(errc::kDisabled, kDisabledMessage, "security.passphrase");
}

result<key> open_with_passphrase(std::string_view, std::string_view) {
    return fail(errc::kDisabled, kDisabledMessage, "security.passphrase");
}

bool is_passphrase_sealed(std::string_view value) noexcept {
    return value.starts_with("argon2i:");
}

} // namespace Rhp::security

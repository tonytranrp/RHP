// RHP_ENABLE=OFF: no cryptography is built, so no key handle can be made and nothing verifies.
#include <cstddef>
#include <span>
#include <string>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/key_handle.hpp>

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

} // namespace Rhp::security

// RHP_ENABLE=OFF: Monocypher isn't fetched, so nothing can be signed or checked. Keys still load
// and the trusted-signers file still parses (signing_keys.cpp); signing and verifying report
// kDisabled, and a public key can't be derived (it comes back all zero).
#include <array>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/security/ed25519.hpp>

namespace Rhp::security {

ed25519_public_key ed25519_secret_key::public_key() const {
    return {};
}

std::array<std::byte, ed25519_secret_key::kSignatureSize> ed25519_secret_key::sign(std::span<const std::byte>) const {
    return {};
}

bool ed25519_check(const ed25519_public_key&, std::span<const std::byte>, std::span<const std::byte>) noexcept {
    return false;
}

result<value> signing_key::sign(std::string_view) const {
    return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "security.signature");
}

result<std::string> trusted_signers::verify(std::string_view, const value&) const {
    return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "security.signature");
}

} // namespace Rhp::security

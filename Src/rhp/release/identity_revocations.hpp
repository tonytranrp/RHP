#pragma once

#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/identity_revocations.hpp>

namespace Rhp::release {

// Identity revocations as they travel (decision AL12): a security::identity_revocation_list signed
// by the root's revocation role (without a root, by the manager's "*" release keys) over
// kIdentityRevocationSignatureDomain || body. Cumulative and seq-capped like release revocation
// lists (AL9); a release::manager keeps the union (manager::identities()).
//
// Body (canonical MessagePack): {seq, issued_at, cert_serials = [string] (sorted),
//   signer_keys = [{alg, pub}] (sorted), device_keys = [{alg, pub}] (sorted)}
// Envelope (a ".rhpidrev" file, a kTrust document): {rhp = "identity-revocations", body, signatures = [{signer, sig}]}.
inline constexpr std::string_view kIdentityRevocationSignatureDomain{"rhp/identity-revocations\0", 25};
inline constexpr std::size_t kMaxSerial = 128;

struct signed_identity_revocations {
    security::identity_revocation_list body;
    std::vector<std::byte> body_bytes;
    std::vector<signature> signatures;
};

[[nodiscard]] result<void> validate(const security::identity_revocation_list& list);
[[nodiscard]] result<std::vector<std::byte>> encode_identity_revocation_list(const security::identity_revocation_list& list);
// Strict: what encode_identity_revocation_list writes (kProtocol otherwise).
[[nodiscard]] result<security::identity_revocation_list> decode_identity_revocation_list(std::span<const std::byte> body);

[[nodiscard]] result<signed_identity_revocations> make_identity_revocations(security::identity_revocation_list list);
[[nodiscard]] result<void> sign(signed_identity_revocations& r, const security::signing_key& key);
[[nodiscard]] result<std::vector<std::byte>> encode_identity_revocations(const signed_identity_revocations& r);
// Signatures are not checked here (a release::manager checks them against its trust).
[[nodiscard]] result<signed_identity_revocations> decode_identity_revocations(std::span<const std::byte> envelope);

} // namespace Rhp::release

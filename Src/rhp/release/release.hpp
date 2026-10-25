#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/security/ed25519.hpp>

namespace Rhp::release {

// A release: the signed manifest, its sources and the signatures over it. What travels (a
// ".rhprel" file, a kReleaseApply request) is its envelope:
//
//   {rhp = "release-envelope", body = <canonical manifest bytes>, signatures = [{signer, sig}],
//    sources = [module source, ...], revocations = <a signed revocation list> | nil}
//
// Only the body is signed: sources are bound to it by their BLAKE2b-256 in the manifest, and an
// embedded revocation list carries its own signatures.
struct release {
    manifest body;
    std::vector<std::byte> body_bytes; // canonical encoding of `body`
    release_id id{};                   // BLAKE2b-256 of body_bytes
    std::vector<std::string> sources;  // one per manifest module, in its order
    std::vector<signature> signatures;
    std::vector<std::byte> revocations; // a signed revocation list to apply first; empty: none
};

// Builds an unsigned release from a manifest whose modules name the sources (hashes are filled in
// here, one source per module, in order).
[[nodiscard]] result<release> make_release(manifest m, std::vector<std::string> sources);

// Adds `key`'s signature over the body (replacing an earlier one by the same signer).
[[nodiscard]] result<void> sign(release& r, const security::signing_key& key);

[[nodiscard]] result<std::vector<std::byte>> encode_release(const release& r);

// Decodes an envelope: the body strictly (decode_manifest), every source against its hash
// (kIntegrity). Signatures are not checked here: see trust::verify.
[[nodiscard]] result<release> decode_release(std::span<const std::byte> envelope);

// ---- revocation lists ----------------------------------------------------------------------------

// A channel's revoked floor: releases with this seq or a lower one are revoked (refused, stopped if
// they run, never fallen back to).
struct seq_floor {
    std::string channel;
    std::uint64_t seq = 0;

    [[nodiscard]] bool operator==(const seq_floor&) const = default;
};

// Releases and keys a host must stop trusting, and floors it must raise. A host adds every list it
// accepts to what it already revoked: a newer list (higher seq) can't take a revocation back, and a
// key any list revoked can't sign a later one. Repeating older entries is harmless.
struct revocation_list {
    std::uint64_t seq = 0;       // >= 1, increasing
    std::uint64_t issued_at = 0; // Unix seconds (informational)
    std::vector<release_id> releases;
    std::vector<security::ed25519_public_key> keys;
    std::vector<seq_floor> floors;

    [[nodiscard]] bool operator==(const revocation_list&) const = default;
};

// A revocation list as it travels (a ".rhprev" file, a kRevoke request):
//   {rhp = "revocations-envelope", body = <canonical list bytes>, signatures = [{signer, sig}]}
struct signed_revocations {
    revocation_list body;
    std::vector<std::byte> body_bytes;
    std::vector<signature> signatures;
};

[[nodiscard]] result<std::vector<std::byte>> encode_revocation_list(const revocation_list& list);
[[nodiscard]] result<revocation_list> decode_revocation_list(std::span<const std::byte> body);

[[nodiscard]] result<signed_revocations> make_revocations(revocation_list list);
[[nodiscard]] result<void> sign(signed_revocations& r, const security::signing_key& key);
[[nodiscard]] result<std::vector<std::byte>> encode_revocations(const signed_revocations& r);
[[nodiscard]] result<signed_revocations> decode_revocations(std::span<const std::byte> envelope);

} // namespace Rhp::release

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/release/trust.hpp>
#include <rhp/security/ed25519.hpp>

namespace Rhp::release {

// The root of trust (decision AL12): a versioned document, signed by an offline threshold of root
// keys, that names every key a host trusts for releases, revocation lists and operator
// certificates, with a threshold per role. Version N+1 must be signed by a threshold of version N's
// root keys and a threshold of its own; keys marked compromised drop what they signed (a manager
// throws their revocation lists away on restore: TUF's recover step), keys simply left out (retired)
// keep it.
//
// Body (canonical MessagePack, signed over kRootSignatureDomain || body):
//   {rhp = "root", version, expires,
//    keys = {<id> = {alg, pub, channels}, ...},                     (sorted by id)
//    roles = {root = {keys, threshold}, release = {...}, revocation = {...}, operator_ca = {...}},
//    compromised = [id, ...]}
// Envelope (a ".rhproot" file, a kTrust document): {rhp = "root-envelope", body, signatures = [{signer = key id, sig}]}.
inline constexpr std::string_view kRootSignatureDomain{"rhp/root\0", 9};

// The algorithm names keys carry. Only Ed25519 verifies today; a key of another algorithm (P-256
// later) is kept in the document but none of its signatures count.
inline constexpr std::string_view kEd25519Alg = "ed25519";

inline constexpr std::size_t kMaxRootKeys = 64;
inline constexpr std::size_t kMaxKeyId = 64;
inline constexpr std::size_t kMaxPublicKey = 133; // an uncompressed P-256 point with room to spare

// A key the root names. `channels` matter in the release role only (patterns as in trust;
// empty: every channel).
struct root_key {
    std::string alg{kEd25519Alg};
    std::vector<std::byte> pub;
    std::vector<std::string> channels;

    [[nodiscard]] bool operator==(const root_key&) const = default;
};

// What each role is for: root (signs the next root), release (signs releases), revocation (signs
// release revocation lists and identity revocations), operator_ca (signs operator certificates).
enum class root_role : std::uint8_t {
    kRoot,
    kRelease,
    kRevocation,
    kOperatorCa
};
inline constexpr std::array kRootRoles{root_role::kRoot, root_role::kRelease, root_role::kRevocation, root_role::kOperatorCa};

[[nodiscard]] constexpr std::string_view to_string(root_role r) noexcept {
    switch (r) {
    case root_role::kRoot: return "root";
    case root_role::kRelease: return "release";
    case root_role::kRevocation: return "revocation";
    case root_role::kOperatorCa: return "operator_ca";
    }
    return "unknown";
}

// The keys of one role and how many of them must sign. A role with no keys is unused (only the
// root role must have keys).
struct role_keys {
    std::vector<std::string> keys; // key ids
    std::uint32_t threshold = 1;

    [[nodiscard]] bool operator==(const role_keys&) const = default;
};

struct root_document {
    std::uint64_t version = 1;
    std::uint64_t expires = 0; // Unix seconds; 0: never
    std::map<std::string, root_key, std::less<>> keys;
    std::array<role_keys, kRootRoles.size()> roles{};
    std::vector<std::string> compromised; // key ids (still in `keys`, so their public keys are known; in no role)

    [[nodiscard]] role_keys& role(root_role r) noexcept { return roles[static_cast<std::size_t>(r)]; }
    [[nodiscard]] const role_keys& role(root_role r) const noexcept { return roles[static_cast<std::size_t>(r)]; }
    [[nodiscard]] bool operator==(const root_document&) const = default;
};

struct signed_root {
    root_document body;
    std::vector<std::byte> body_bytes; // canonical encoding of `body`
    std::vector<signature> signatures; // signer = key id
};

[[nodiscard]] result<void> validate(const root_document& doc);
[[nodiscard]] result<std::vector<std::byte>> encode_root_document(const root_document& doc);
// Strict: what encode_root_document writes and nothing else (kProtocol "not canonical" otherwise).
[[nodiscard]] result<root_document> decode_root_document(std::span<const std::byte> body);

[[nodiscard]] result<signed_root> make_root(root_document doc);
// Adds `key`'s signature (key.name is the key id the root knows it by).
[[nodiscard]] result<void> sign(signed_root& r, const security::signing_key& key);
[[nodiscard]] result<std::vector<std::byte>> encode_root(const signed_root& r);
// Decodes an envelope (signatures are not checked here: verify_root / verify_next_root).
[[nodiscard]] result<signed_root> decode_root(std::span<const std::byte> envelope);

// ---- verification -----------------------------------------------------------------------------------

// The ids of `doc`'s keys in role `r` whose signatures over r's body hold (distinct keys).
// kBadSignature unless the role's threshold is met.
[[nodiscard]] result<std::vector<std::string>> verify_role(const root_document& doc, root_role r, std::string_view domain, std::span<const std::byte> body,
                                                           std::span<const signature> sigs);

// A trust anchor the application supplies (the genesis root, or a later one it embeds): signed by a
// threshold of its own root keys. Its expiry is not checked (an app's embedded root may be old).
[[nodiscard]] result<void> verify_root(const signed_root& anchor);

// `next` follows `trusted`: version exactly trusted.version + 1 (kOutOfRange for a skip, kSuperseded
// for one not newer), signed by a threshold of trusted's root keys and a threshold of its own.
// Expiry is not checked here (see verify_chain).
[[nodiscard]] result<void> verify_next_root(const signed_root& trusted, const signed_root& next);

// Walks `newer` (consecutive versions, oldest first) from `trusted`: every step as verify_next_root.
// The newest must not have expired at `now_unix` (with `skew` seconds of allowance): an expired root
// is refused as an update (kExpired), while one a host already holds stays in force after it expires
// (a late operator must not lock devices out). Intermediate roots may have expired. Returns the
// newest root.
[[nodiscard]] result<signed_root> verify_chain(const signed_root& trusted, std::span<const signed_root> newer, std::uint64_t now_unix, std::uint64_t skew = 0);

// ---- what a root says -----------------------------------------------------------------------------

// The trust of a role: its Ed25519 keys under their ids (channels for the release role, "*" for
// the others) and its threshold. Compromised keys are in no role. kNotFound for a role without keys.
[[nodiscard]] result<trust> role_trust(const root_document& doc, root_role r);

// The Ed25519 public keys of a role (operator CAs, for the certificate checks) or of the
// compromised list.
[[nodiscard]] std::vector<security::ed25519_public_key> role_public_keys(const root_document& doc, root_role r);
[[nodiscard]] std::vector<security::ed25519_public_key> compromised_keys(const root_document& doc);
// Every Ed25519 key the root names that isn't compromised (any role, or none).
[[nodiscard]] std::vector<security::ed25519_public_key> trusted_keys(const root_document& doc);

// True when the signatures that hold over domain || body come only from `compromised` keys (at
// least one does, none from `others`): what a manager's recover step drops.
[[nodiscard]] bool signed_only_by(std::span<const security::ed25519_public_key> compromised, std::span<const security::ed25519_public_key> others,
                                  std::string_view domain, std::span<const std::byte> body, std::span<const signature> sigs);

} // namespace Rhp::release

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/hash.hpp>

namespace Rhp::release {

// A release's identity: BLAKE2b-256 of its signed body (signatures excluded).
using release_id = security::digest256;

// Signatures over a release body and a revocation list body are domain-separated from each
// other and from script signatures (security::kScriptSignatureDomain).
inline constexpr std::string_view kReleaseSignatureDomain{"rhp/release\0", 12};
inline constexpr std::string_view kRevocationSignatureDomain{"rhp/revocation\0", 15};

inline constexpr std::size_t kMaxModules = 256;
inline constexpr std::size_t kMaxSignatures = 16;
inline constexpr std::size_t kMaxChannelName = 64;
inline constexpr std::size_t kMaxListEntries = 1024;

// One module of a release: its name and the BLAKE2b-256 of its source.
struct module_entry {
    std::string name;
    security::digest256 hash{};

    [[nodiscard]] bool operator==(const module_entry&) const = default;
};

// What a release asks of the host it runs on, and what tells it is healthy.
struct health_policy {
    // Script events (rhp.publish) or rhp.handler_failed that mark the candidate unhealthy.
    std::vector<std::string> fail_events;
    // Handler failures the candidate may have while it is watched (0: none).
    std::uint32_t max_handler_failures = 0;

    [[nodiscard]] bool operator==(const health_policy&) const = default;
};

// The signed part of a release. Every field is part of the signature; the encoding is canonical
// (one byte sequence per manifest), so the body's bytes are its identity.
struct manifest {
    std::string channel;                // which slot it fills: dotted lowercase ("game.balance"), at most 64 bytes
    std::uint64_t seq = 0;              // >= 1; a channel only accepts a higher seq than any it accepted (anti-rollback)
    std::string label;                  // free text for status displays ("balance tweak 12")
    std::string app;                    // the host's app name; empty: any app
    std::vector<std::string> builds;    // host build strings accepted; empty: any build
    std::vector<std::string> platforms; // Rhp::platform OS names ("windows", "android", ...); empty: any
    std::uint64_t not_before = 0;       // Unix seconds; 0: none
    std::uint64_t not_after = 0;        // Unix seconds; 0: never expires
    role run_as = role::kPatch;         // the channel's sandbox runs with this role (kPatch or kAdmin)
    std::vector<std::string> libs;      // libs the host must have installed
    std::vector<module_entry> modules;  // loaded in this order (later ones may require earlier ones)
    health_policy health{};

    [[nodiscard]] bool operator==(const manifest&) const = default;
};

// Canonical MessagePack of a manifest (what is signed).
[[nodiscard]] result<std::vector<std::byte>> encode_manifest(const manifest& m);
// Strict: exactly the fields encode_manifest writes, in its order, with its types; the bytes must
// re-encode to themselves (kProtocol "not canonical" otherwise).
[[nodiscard]] result<manifest> decode_manifest(std::span<const std::byte> body);

// Checks the fields' own rules (channel name, seq, role, sizes, unique module names).
[[nodiscard]] result<void> validate(const manifest& m);

// One signature of a body: who signed (the name the host trusts the key by) and the 64 bytes.
struct signature {
    std::string signer;
    std::array<std::byte, security::ed25519_secret_key::kSignatureSize> bytes{};

    [[nodiscard]] bool operator==(const signature&) const = default;
};

[[nodiscard]] std::string to_hex(const release_id& id);
[[nodiscard]] result<release_id> id_from_hex(std::string_view hex);
// "1a2b3c4d" (the first 4 bytes): how status displays name a release.
[[nodiscard]] std::string short_id(const release_id& id);

} // namespace Rhp::release

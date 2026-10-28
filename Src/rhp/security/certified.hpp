#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key_handle.hpp>
#include <rhp/security/operator_cert.hpp>
#include <rhp/security/signer.hpp>

namespace Rhp::security {

// What a certified script signature covers: this prefix, the canonical claims, then the source.
inline constexpr std::string_view kScriptClaimsDomain{"rhp/script-claims\0", 18};

// Where and until when a signed script may run (decision AL11). Canonical MessagePack, in this
// order: {not_after, app, env, audience, nonce, identity}. Empty strings mean "any".
struct script_claims {
    std::uint64_t not_after = 0; // Unix seconds, exclusive
    std::string app;
    std::string env;
    std::string audience; // the host's host_options::host_id
    std::array<std::byte, 16> nonce{};
    std::string identity; // the session identity it is for

    [[nodiscard]] bool operator==(const script_claims&) const = default;
};

[[nodiscard]] result<std::vector<std::byte>> encode_claims(const script_claims& c);
// Strict: exactly the six fields, in order, re-encoding to the same bytes.
[[nodiscard]] result<script_claims> decode_claims(std::span<const std::byte> bytes);

// What a certified::key puts in the claims when the client doesn't say (signing_context wins where
// set). Outside `certified` so its default member initializers can serve as default arguments there.
struct certified_claim_options {
    std::chrono::seconds lifetime{600}; // claims.not_after = now + lifetime (at most the cert's not_after)
    std::string app{};
    std::string env{};
    std::string audience{};
    std::string identity{};
};

// How a certified::trust checks claims.
struct certified_trust_options {
    std::chrono::seconds max_lifetime{3600}; // how far ahead claims.not_after may be
    std::size_t replay_entries = 4096;       // live nonces kept
};

// The certified signer policy: config<>::signer<Rhp::security::certified>. Operators sign with a
// short-lived key their operator CA vouches for (an operator certificate); hosts trust the CA.
//
// The signature value is {cert = <encoded operator certificate>, claims = <canonical claims>,
// sig = the certificate's key's signature (Ed25519, or P-256 r || s) over kScriptClaimsDomain ||
// claims || source}.
//
// A host checks (trust::verify with the signature_context the host passes): the certificate chains
// to a trusted CA and is valid now; neither is tagged dev on a host at hardening production; its
// serial isn't revoked; the signature; claims.not_after is in the future, no later than the
// certificate's not_after and at most trust_options::max_lifetime ahead (kExpired); claims app / env
// / audience / identity match the host's app, env, host id and the session's identity, and the
// certificate's apps / envs list the host's (kOutOfScope); its max_role is at least the session's
// role (kForbidden); the nonce wasn't seen before (kBadSignature). The signer it names is
// "<principal>#<serial>". The certificate's scopes go to signature_context::scopes: the host runs
// the script under them as well as the identity's (decision AL13).
//
// Replay: each trust keeps the nonces it accepted until their claims expire. The cache holds at
// most trust_options::replay_entries live nonces; when it is full of unexpired ones, further
// signatures are refused (kLimitExceeded) rather than forgetting one that could then be replayed.
// Copies of a trust share the cache, the revoked serials and the revocation check.
struct certified {
    static constexpr std::string_view name = "certified";

    using claim_options = certified_claim_options;
    using trust_options = certified_trust_options;

    class key {
    public:
        key() = default;
        // `operator_key` must be the key the certificate names (sign reports kInvalidArgument otherwise).
        key(const ed25519_secret_key& operator_key, operator_cert cert, claim_options claims = {});
        // An operator key held anywhere (decision AL10): software Ed25519 or P-256, or a hardware key
        // behind a callback (a P-256 key needs the TLS backend's crypto: kDisabled without one).
        key(key_handle operator_key, operator_cert cert, claim_options claims = {});

        [[nodiscard]] result<value> sign(std::string_view source) const;
        [[nodiscard]] result<value> sign(std::string_view source, const signing_context& context) const;

        [[nodiscard]] const operator_cert& cert() const noexcept { return cert_; }
        [[nodiscard]] const claim_options& claims() const noexcept { return claims_; }

    private:
        key_handle key_;
        operator_cert cert_;
        std::vector<std::byte> cert_bytes_; // encoded once
        claim_options claims_;
    };

    class trust {
    public:
        trust();
        explicit trust(trusted_cas cas, trust_options options = {});

        // Without a context (a caller that isn't a host): now, any identity, the role admin, no app,
        // env or host id - so claims or certificates naming one don't match.
        [[nodiscard]] result<std::string> verify(std::string_view source, const value& signature) const;
        [[nodiscard]] result<std::string> verify(std::string_view source, const value& signature, const signature_context& context) const;

        // Refuses certificates with this serial from now on (kRevoked), in every copy.
        void revoke(std::uint64_t serial);
        // An extra check (a revocation list the app keeps): true refuses the certificate. Called on
        // the host's network thread: it must be thread-safe.
        void set_revocation_check(std::function<bool(const operator_cert&)> revoked);

        // What a root of trust says (decision AL12; host.serve sets it from a release manager, again
        // whenever its root changes): `cas`, when set, are the operator CAs from now on instead of
        // the ones the trust was made with (nullopt: the root names none, those stay); `revoked`
        // refuses certificates (kRevoked) besides revoke() and set_revocation_check's, and must be
        // thread-safe. In every copy.
        void set_root_of_trust(std::optional<trusted_cas> cas, std::function<bool(const operator_cert&)> revoked);

        // The CAs the trust was made with; root_cas() what set_root_of_trust replaced them with.
        [[nodiscard]] const trusted_cas& cas() const noexcept;
        [[nodiscard]] std::shared_ptr<const trusted_cas> root_cas() const;

    private:
        struct state;
        std::shared_ptr<state> state_;
    };
};

static_assert(signer<certified>);
static_assert(context_trust<certified::trust>);
static_assert(context_key<certified::key>);

} // namespace Rhp::security

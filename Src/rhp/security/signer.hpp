#pragma once

#include <chrono>
#include <concepts>
#include <string>
#include <string_view>

#include <rhp/core/hardening.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>

namespace Rhp::security {

// Script-signing policy for Rhp::config<>::signer<...>. A client's `key` signs the source of every
// exec / load / reload it sends; the host's `trust` checks that signature before anything runs and
// names who signed (the audit log records it). Signatures travel as an Rhp::value, so a policy
// chooses its own format.
//
//   S::name                                  "ed25519"
//   S::key::sign(source)       -> result<value>        the signature to attach (nil = none)
//   S::trust::verify(source, signature) -> result<std::string>   the signer's name, or kBadSignature
//
// The host runs unsigned code only for observe sessions (they can't mutate anything); a signature
// that is present must verify, whatever the role.
//
// Optional, detected with `requires` (context_trust / context_key below): a trust may also have
// verify(source, signature, signature_context) and a key sign(source, signing_context); the host and
// the client then call those instead.
//
// Threads: the host calls trust::verify on its network thread (one session at a time per thread,
// but different hosts sharing one trust object may call it concurrently), and key::sign on whichever
// thread sends. Both are const: keep them free of unsynchronized mutable state.
template <class S>
concept signer = std::copy_constructible<typename S::key> && std::copy_constructible<typename S::trust> &&
                 requires(const typename S::key& k, const typename S::trust& t, std::string_view source, const value& signature) {
                     { S::name } -> std::convertible_to<std::string_view>;
                     { k.sign(source) } -> std::same_as<result<value>>;
                     { t.verify(source, signature) } -> std::same_as<result<std::string>>;
                 };

// What every script signature covers: this prefix, then the source. The domain keeps a script
// signature from meaning anything else the same key might sign.
inline constexpr std::string_view kScriptSignatureDomain{"rhp/script\0", 11};

// Where a script is about to run, for a trust that checks more than the bytes (security::certified's
// claims). The host builds it for every exec / load / reload: the session's identity and role, the
// host's app, environment and id (host_options), the wall clock, and its effective hardening level.
// Views are valid during the verify call only.
struct signature_context {
    std::string_view identity; // the session's identity (key name)
    role granted = role::kAdmin;
    std::string_view app;     // host_options::app (empty: not set)
    std::string_view env;     // "dev" or "prod": host_options::env, else from the hardening level
    std::string_view host_id; // host_options::host_id (empty: not set)
    std::chrono::system_clock::time_point now{};
    hardening level = kBuildHardening;
};

// What a client knows when it signs, for a key that puts claims in its signature
// (security::certified): its identity name and client_options' app, env and audience (empty: not set).
struct signing_context {
    std::string_view identity;
    std::string_view app;
    std::string_view env;
    std::string_view audience;
};

// A trust that checks signatures against a signature_context. The host calls this overload when a
// trust has it, and verify(source, signature) otherwise: the signer concept stays the same.
template <class T>
concept context_trust = requires(const T& t, std::string_view source, const value& signature, const signature_context& context) {
    { t.verify(source, signature, context) } -> std::same_as<result<std::string>>;
};

// A key that puts what the client knows into its signature (the client calls this overload when a
// key has it).
template <class K>
concept context_key = requires(const K& k, std::string_view source, const signing_context& context) {
    { k.sign(source, context) } -> std::same_as<result<value>>;
};

// trust.verify with the context when the trust takes one.
template <class T>
[[nodiscard]] result<std::string> verify_in_context(const T& trust, std::string_view source, const value& signature, const signature_context& context) {
    if constexpr (context_trust<T>) {
        return trust.verify(source, signature, context);
    } else {
        (void)context;
        return trust.verify(source, signature);
    }
}

// key.sign with the context when the key takes one.
template <class K>
[[nodiscard]] result<value> sign_in_context(const K& key, std::string_view source, const signing_context& context) {
    if constexpr (context_key<K>) {
        return key.sign(source, context);
    } else {
        (void)context;
        return key.sign(source);
    }
}

// The explicit opt-out: no signatures, every authenticated role runs any code (Stage 3 behaviour).
// Typed on purpose - `Rhp::config<>::signer<Rhp::security::unsigned_scripts>` - so a host never
// runs unsigned code by accident.
struct unsigned_scripts {
    static constexpr std::string_view name = "unsigned";

    struct key {
        [[nodiscard]] result<value> sign(std::string_view) const { return value{}; }
    };

    struct trust {
        [[nodiscard]] result<std::string> verify(std::string_view, const value&) const { return std::string{}; }
    };
};

static_assert(signer<unsigned_scripts>);

} // namespace Rhp::security

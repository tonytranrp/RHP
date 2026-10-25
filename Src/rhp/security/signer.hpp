#pragma once

#include <concepts>
#include <string>
#include <string_view>

#include <rhp/core/result.hpp>
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

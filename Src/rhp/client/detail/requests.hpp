#pragma once

// Request bodies as clients send them: shared by client<Cfg> (blocking and async calls) and the
// fleet engine's broadcasts. Header-only: client.hpp uses them with RHP_ENABLE=0 too.

#include <cstddef>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <rhp/core/convert.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/security/signer.hpp>
#include <rhp/wire/messages.hpp>

namespace Rhp::client_detail {

// Signs a script's source (Cfg::signing_key_t::sign, type-erased); empty: scripts go unsigned.
using sign_fn = std::function<result<value>(std::string_view source)>;

// The sign_fn of a signing key. A key that puts claims in its signature (security::context_key,
// security::certified) gets the identity the client connects as and `claims`' app, env and audience.
template <class Key, class Claims>
[[nodiscard]] sign_fn make_sign(Key key, std::string identity, const Claims& claims) {
    if constexpr (security::context_key<Key>) {
        return [key = std::move(key), identity = std::move(identity), app = claims.app, env = claims.env, audience = claims.audience](std::string_view source) {
            return key.sign(source, security::signing_context{.identity = identity, .app = app, .env = env, .audience = audience});
        };
    } else {
        (void)identity;
        (void)claims;
        return [key = std::move(key)](std::string_view source) -> result<value> { return key.sign(source); };
    }
}

// A credential's name when it has one (psk_identity::name): what claims name as the identity.
template <class Credential>
[[nodiscard]] std::string credential_name(const Credential& c) {
    if constexpr (requires { std::string{c.name}; }) {
        return std::string{c.name};
    } else {
        (void)c;
        return {};
    }
}
// What `sign` makes of `source`: its signature, nil without a signer, or why it couldn't sign.
[[nodiscard]] inline result<value> signature(const sign_fn& sign, std::string_view source) {
    if (!sign) {
        return value{};
    }
    return sign(source);
}

// The code-carrying bodies (exec, load, reload) take the source's signature() and pass its error on.
[[nodiscard]] inline result<value> exec_body(result<value> signed_by, std::string_view source, std::string_view chunk) {
    if (!signed_by) {
        return std::unexpected{std::move(signed_by).error()};
    }
    return Rhp::to_value(wire::exec_request{std::string{source}, std::string{chunk}, std::move(*signed_by)});
}

[[nodiscard]] inline result<value> load_body(result<value> signed_by, std::string_view name, std::string_view source) {
    if (!signed_by) {
        return std::unexpected{std::move(signed_by).error()};
    }
    return Rhp::to_value(wire::load_request{std::string{name}, std::string{source}, std::move(*signed_by)});
}

[[nodiscard]] inline result<value> reload_body(result<value> signed_by, wire::module_ref mod, std::string_view source) {
    if (!signed_by) {
        return std::unexpected{std::move(signed_by).error()};
    }
    return Rhp::to_value(wire::reload_request{std::move(mod), std::string{source}, std::move(*signed_by)});
}

[[nodiscard]] inline value call_body(wire::module_ref mod, std::string_view function, std::span<const value> args) {
    return Rhp::to_value(wire::call_request{std::move(mod), std::string{function}, value::array(args.begin(), args.end())});
}

[[nodiscard]] inline value rollback_body(wire::module_ref mod, std::size_t steps) {
    return Rhp::to_value(wire::rollback_request{std::move(mod), steps});
}

[[nodiscard]] inline value unload_body(wire::module_ref mod, bool force) {
    return Rhp::to_value(wire::unload_request{std::move(mod), force});
}

// revert, status, pin and unpin: one module.
[[nodiscard]] inline value module_body(wire::module_ref mod) {
    return Rhp::to_value(wire::module_request{std::move(mod)});
}

} // namespace Rhp::client_detail

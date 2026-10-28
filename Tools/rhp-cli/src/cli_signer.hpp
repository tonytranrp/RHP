#pragma once

// rhp-cli's signer policy: one client type whose key is an identity's Ed25519 signing key or, with
// --cert-file, an operator certificate's (security::certified). The host checks with its own policy;
// rhp-cli never hosts, so `trust` is only there to satisfy the concept.

#include <functional>
#include <string_view>
#include <utility>

#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/security/certified.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/signer.hpp>

namespace rhp_cli {

struct cli_signer {
    static constexpr std::string_view name = "rhp-cli";

    class key {
    public:
        key() = default;
        explicit key(Rhp::security::signing_key k) : sign_(wrap(std::move(k))) {}
        explicit key(Rhp::security::certified::key k) : sign_(wrap(std::move(k))) {}

        [[nodiscard]] Rhp::result<Rhp::value> sign(std::string_view source) const { return sign(source, {}); }
        [[nodiscard]] Rhp::result<Rhp::value> sign(std::string_view source, const Rhp::security::signing_context& context) const {
            if (!sign_) {
                return Rhp::value{};
            }
            return sign_(source, context);
        }

    private:
        using sign_fn = std::function<Rhp::result<Rhp::value>(std::string_view, const Rhp::security::signing_context&)>;

        template <class K>
        static sign_fn wrap(K k) {
            return [k = std::move(k)](std::string_view source, const Rhp::security::signing_context& context) { return Rhp::security::sign_in_context(k, source, context); };
        }

        sign_fn sign_;
    };

    using trust = Rhp::security::trusted_signers;
};

static_assert(Rhp::security::signer<cli_signer>);
static_assert(Rhp::security::context_key<cli_signer::key>);

} // namespace rhp_cli

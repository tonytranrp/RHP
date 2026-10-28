// The certified signer policy (decision AL11): script claims, signing with an operator
// certificate's key, and the host's checks. Builds with RHP_ENABLE=OFF too: signing and checking
// then report kDisabled.
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <rhp/build_config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/hardening.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/security/certified.hpp>
#include <rhp/security/detail/canonical.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/operator_cert.hpp>
#include <rhp/security/signer.hpp>

namespace Rhp::security {

namespace {

constexpr bool kClaimSigning = RHP_ENABLE != 0;
constexpr std::string_view kCertifiedWhere = "security.certified";

#define RHP_TRY(var, expr)                                  \
    auto var##_r = (expr);                                  \
    if (!var##_r) {                                         \
        return std::unexpected{std::move(var##_r).error()}; \
    }                                                       \
    auto var = std::move(*var##_r)

[[nodiscard]] std::unexpected<error> refuse(errc code, std::string message) {
    return std::unexpected{make_error(code, std::move(message), std::string{kCertifiedWhere})};
}

[[nodiscard]] std::uint64_t claim_seconds(std::chrono::system_clock::time_point t) {
    const auto s = std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
    return s < 0 ? 0 : static_cast<std::uint64_t>(s);
}

[[nodiscard]] value claims_value(const script_claims& c) {
    value::map m;
    m.emplace_back(value{"not_after"}, value{c.not_after});
    m.emplace_back(value{"app"}, value{c.app});
    m.emplace_back(value{"env"}, value{c.env});
    m.emplace_back(value{"audience"}, value{c.audience});
    m.emplace_back(value{"nonce"}, value{value::bytes(c.nonce.begin(), c.nonce.end())});
    m.emplace_back(value{"identity"}, value{c.identity});
    return value{std::move(m)};
}

// kScriptClaimsDomain || claims || source.
[[nodiscard]] std::vector<std::byte> claims_message(std::span<const std::byte> claims, std::string_view source) {
    std::vector<std::byte> out;
    out.reserve(kScriptClaimsDomain.size() + claims.size() + source.size());
    for (const char c : kScriptClaimsDomain) {
        out.push_back(static_cast<std::byte>(c));
    }
    out.insert(out.end(), claims.begin(), claims.end());
    for (const char c : source) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

[[nodiscard]] const value::bytes* bytes_field(const value& v, std::string_view key) {
    const value* field = v.find(key);
    return field != nullptr ? field->get_if<value::bytes>() : nullptr;
}

[[nodiscard]] bool listed(const std::vector<std::string>& list, std::string_view item) {
    return std::ranges::find(list, item) != list.end();
}

} // namespace

result<std::vector<std::byte>> encode_claims(const script_claims& c) {
    return detail::encode_canonical(claims_value(c));
}

result<script_claims> decode_claims(std::span<const std::byte> bytes) {
    RHP_TRY(v, detail::decode_canonical(bytes));
    RHP_TRY(m, detail::fixed_map::of(v, 6, "script claims", kCertifiedWhere));
    script_claims c;
    RHP_TRY(not_after, m.count(0, "not_after"));
    c.not_after = not_after;
    RHP_TRY(app, m.text(1, "app", kMaxCertText));
    c.app = std::move(app);
    RHP_TRY(env, m.text(2, "env", kMaxCertText));
    c.env = std::move(env);
    RHP_TRY(audience, m.text(3, "audience", kMaxCertText));
    c.audience = std::move(audience);
    RHP_TRY(nonce, m.bytes(4, "nonce", c.nonce.size()));
    std::ranges::copy(*nonce, c.nonce.begin());
    RHP_TRY(identity, m.text(5, "identity", kMaxCertText));
    c.identity = std::move(identity);
    auto again = encode_claims(c);
    if (!again || !std::ranges::equal(*again, bytes)) {
        return std::unexpected{m.bad("the claims are not canonical")};
    }
    return c;
}

// ---- key --------------------------------------------------------------------------------------------

certified::key::key(ed25519_secret_key operator_key, operator_cert cert, claim_options claims)
    : secret_(std::move(operator_key)), cert_(std::move(cert)), claims_(std::move(claims)) {
    if (auto bytes = encode_operator_cert(cert_)) {
        cert_bytes_ = std::move(*bytes);
    }
}

result<value> certified::key::sign(std::string_view source) const {
    return sign(source, signing_context{});
}

result<value> certified::key::sign(std::string_view source, const signing_context& context) const {
    if constexpr (!kClaimSigning) {
        (void)source;
        (void)context;
        return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", std::string{kCertifiedWhere});
    } else {
        if (secret_.empty() || cert_bytes_.empty()) {
            return refuse(errc::kInvalidArgument, "a certified key needs an operator key and its certificate");
        }
        const auto pub = secret_.public_key().bytes();
        if (!std::ranges::equal(pub, cert_.fields.pub)) {
            return refuse(errc::kInvalidArgument, std::format("this key isn't the one certificate {} names", cert_.id()));
        }
        RHP_TRY(nonce, platform::random_array<16>());
        const auto pick = [](std::string_view given, const std::string& fallback) { return std::string{given.empty() ? std::string_view{fallback} : given}; };
        script_claims c;
        const std::uint64_t now = claim_seconds(std::chrono::system_clock::now());
        const auto lifetime = claims_.lifetime.count() > 0 ? static_cast<std::uint64_t>(claims_.lifetime.count()) : 1;
        c.not_after = (std::min)(now + lifetime, cert_.fields.not_after);
        c.app = pick(context.app, claims_.app);
        c.env = pick(context.env, claims_.env);
        c.audience = pick(context.audience, claims_.audience);
        c.nonce = nonce;
        c.identity = pick(context.identity, claims_.identity);
        RHP_TRY(claims_bytes, encode_claims(c));
        const auto sig = secret_.sign(claims_message(claims_bytes, source));
        value::map m;
        m.emplace_back(value{"cert"}, value{value::bytes(cert_bytes_.begin(), cert_bytes_.end())});
        m.emplace_back(value{"claims"}, value{std::move(claims_bytes)});
        m.emplace_back(value{"sig"}, value{value::bytes(sig.begin(), sig.end())});
        return value{std::move(m)};
    }
}

// ---- trust ------------------------------------------------------------------------------------------

struct certified::trust::state {
    trusted_cas cas;
    trust_options options;
    std::mutex mutex;
    std::unordered_map<std::string, std::uint64_t> nonces; // nonce bytes -> claims.not_after (guarded by mutex)
    std::vector<std::uint64_t> revoked;                    // serials (guarded by mutex)
    std::function<bool(const operator_cert&)> revocation_check;

    // Records a nonce until `not_after`; false if it was seen. kLimitExceeded when the cache is full
    // of live nonces.
    result<bool> remember(const std::array<std::byte, 16>& nonce, std::uint64_t not_after, std::uint64_t now) {
        const std::scoped_lock lock{mutex};
        std::string k(reinterpret_cast<const char*>(nonce.data()), nonce.size());
        if (const auto it = nonces.find(k); it != nonces.end()) {
            if (it->second > now) {
                return false;
            }
            nonces.erase(it);
        }
        if (nonces.size() >= options.replay_entries) {
            std::erase_if(nonces, [now](const auto& entry) { return entry.second <= now; });
            if (nonces.size() >= options.replay_entries) {
                return refuse(errc::kLimitExceeded, std::format("{} certified signatures are live at once; try again when some expire", nonces.size()));
            }
        }
        nonces.emplace(std::move(k), not_after);
        return true;
    }

    [[nodiscard]] bool is_revoked(const operator_cert& cert) {
        std::function<bool(const operator_cert&)> check;
        {
            const std::scoped_lock lock{mutex};
            if (std::ranges::find(revoked, cert.fields.serial) != revoked.end()) {
                return true;
            }
            check = revocation_check;
        }
        return check && check(cert);
    }
};

certified::trust::trust() : trust(trusted_cas{}) {}

certified::trust::trust(trusted_cas cas, trust_options options) : state_(std::make_shared<state>()) {
    state_->cas = std::move(cas);
    state_->options = options;
}

void certified::trust::revoke(std::uint64_t serial) {
    const std::scoped_lock lock{state_->mutex};
    state_->revoked.push_back(serial);
}

void certified::trust::set_revocation_check(std::function<bool(const operator_cert&)> revoked) {
    const std::scoped_lock lock{state_->mutex};
    state_->revocation_check = std::move(revoked);
}

const trusted_cas& certified::trust::cas() const noexcept {
    return state_->cas;
}

result<std::string> certified::trust::verify(std::string_view source, const value& signature) const {
    signature_context context;
    context.now = std::chrono::system_clock::now();
    return verify(source, signature, context);
}

result<std::string> certified::trust::verify(std::string_view source, const value& signature, const signature_context& context) const {
    if constexpr (!kClaimSigning) {
        (void)source;
        (void)signature;
        (void)context;
        return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", std::string{kCertifiedWhere});
    } else {
        if (signature.is_nil()) {
            return refuse(errc::kBadSignature, "the script is not signed");
        }
        const value::bytes* cert_bytes = bytes_field(signature, "cert");
        const value::bytes* claims_bytes = bytes_field(signature, "claims");
        const value::bytes* sig = bytes_field(signature, "sig");
        if (cert_bytes == nullptr || claims_bytes == nullptr || sig == nullptr) {
            return refuse(errc::kBadSignature, "malformed certified signature (expected cert, claims and sig)");
        }
        auto cert = decode_operator_cert(*cert_bytes);
        if (!cert) {
            return refuse(errc::kBadSignature, std::format("malformed operator certificate: {}", cert.error().message));
        }
        RHP_TRY(ca, verify_operator_cert(*cert, state_->cas, context.now));
        const std::string who = cert->id();
        if (context.level == hardening::kProduction && (ca->env == kEnvDev || listed(cert->fields.envs, kEnvDev))) {
            return refuse(errc::kForbidden, std::format("certificate {} (CA '{}') is tagged dev; a production host refuses dev keys", who, ca->name));
        }
        if (state_->is_revoked(*cert)) {
            return refuse(errc::kRevoked, std::format("certificate {} is revoked", who));
        }
        RHP_TRY(operator_key, cert->operator_key());
        if (!ed25519_check(operator_key, *sig, claims_message(*claims_bytes, source))) {
            return refuse(errc::kBadSignature, std::format("the signature by {} doesn't match the script and its claims", who));
        }
        auto claims = decode_claims(*claims_bytes);
        if (!claims) {
            return refuse(errc::kBadSignature, std::format("malformed claims signed by {}: {}", who, claims.error().message));
        }
        const std::uint64_t now = claim_seconds(context.now);
        const auto max_lifetime = static_cast<std::uint64_t>((std::max)(state_->options.max_lifetime.count(), std::chrono::seconds::rep{0}));
        if (claims->not_after <= now) {
            return refuse(errc::kExpired, std::format("the claims signed by {} expired at {} (Unix seconds), now is {}", who, claims->not_after, now));
        }
        if (claims->not_after > cert->fields.not_after || claims->not_after - now > max_lifetime) {
            return refuse(errc::kExpired, std::format("the claims signed by {} run past its certificate or more than {} s ahead", who, max_lifetime));
        }
        const auto out_of_scope = [&](std::string_view what, std::string_view wanted, std::string_view here) {
            return refuse(errc::kOutOfScope, std::format("the script signed by {} is for {} '{}', this host's is '{}'", who, what, wanted, here));
        };
        if (!claims->app.empty() && claims->app != context.app) {
            return out_of_scope("app", claims->app, context.app);
        }
        if (!claims->env.empty() && claims->env != context.env) {
            return out_of_scope("environment", claims->env, context.env);
        }
        if (!claims->audience.empty() && claims->audience != context.host_id) {
            return out_of_scope("host", claims->audience, context.host_id);
        }
        if (!claims->identity.empty() && claims->identity != context.identity) {
            return out_of_scope("identity", claims->identity, context.identity);
        }
        if (!cert->fields.apps.empty() && !listed(cert->fields.apps, context.app)) {
            return refuse(errc::kOutOfScope, std::format("certificate {} isn't for app '{}'", who, context.app));
        }
        if (!cert->fields.envs.empty() && !listed(cert->fields.envs, context.env)) {
            return refuse(errc::kOutOfScope, std::format("certificate {} isn't for environment '{}'", who, context.env));
        }
        if (!allows(cert->fields.max_role, context.granted)) {
            return refuse(errc::kForbidden, std::format("certificate {} allows at most {}, and this session is {}", who, cert->fields.max_role, context.granted));
        }
        RHP_TRY(fresh, state_->remember(claims->nonce, claims->not_after, now));
        if (!fresh) {
            return refuse(errc::kBadSignature, std::format("the signature by {} was already used (replayed nonce)", who));
        }
        return who;
    }
}

#undef RHP_TRY

} // namespace Rhp::security

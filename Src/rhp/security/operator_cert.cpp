// Operator certificates (decision AL11): the canonical body, the encoded certificate, its .rhpcert
// text, the trusted-CA file, and the CA key file. Builds with RHP_ENABLE=OFF too: issuing and
// checking then report kDisabled (Ed25519 isn't there).
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/build_config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/security/detail/canonical.hpp>
#include <rhp/security/detail/text.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/operator_cert.hpp>
#include <rhp/utils/scope_guard.hpp>

namespace Rhp::security {

namespace {

constexpr bool kSigning = RHP_ENABLE != 0;
constexpr std::string_view kWhere = "security.operator_cert";
constexpr std::string_view kBegin = "-----BEGIN RHP OPERATOR CERTIFICATE-----";
constexpr std::string_view kEnd = "-----END RHP OPERATOR CERTIFICATE-----";

[[nodiscard]] std::unexpected<error> invalid(std::string message) {
    return std::unexpected{make_error(errc::kInvalidArgument, std::move(message), std::string{kWhere})};
}

[[nodiscard]] bool fits(std::uint64_t n) {
    return n <= static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
}

[[nodiscard]] bool valid_env(std::string_view env) {
    return env == kEnvDev || env == kEnvProd;
}

[[nodiscard]] std::uint64_t unix_seconds(std::chrono::system_clock::time_point t) {
    const auto s = std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
    return s < 0 ? 0 : static_cast<std::uint64_t>(s);
}

[[nodiscard]] value body_value(const operator_cert_fields& f) {
    value::map m;
    m.emplace_back(value{"serial"}, value{f.serial});
    m.emplace_back(value{"principal"}, value{f.principal});
    m.emplace_back(value{"alg"}, value{f.alg});
    m.emplace_back(value{"pub"}, value{value::bytes(f.pub.begin(), f.pub.end())});
    m.emplace_back(value{"not_before"}, value{f.not_before});
    m.emplace_back(value{"not_after"}, value{f.not_after});
    m.emplace_back(value{"max_role"}, value{to_string(f.max_role)});
    m.emplace_back(value{"apps"}, detail::strings_value(detail::canonical_set(f.apps)));
    m.emplace_back(value{"envs"}, detail::strings_value(detail::canonical_set(f.envs)));
    m.emplace_back(value{"scopes"}, detail::strings_value(detail::canonical_set(f.scopes)));
    m.emplace_back(value{"critical"}, detail::strings_value(detail::canonical_set(f.critical)));
    return value{std::move(m)};
}

#define RHP_TRY(var, expr)                                  \
    auto var##_r = (expr);                                  \
    if (!var##_r) {                                         \
        return std::unexpected{std::move(var##_r).error()}; \
    }                                                       \
    auto var = std::move(*var##_r)

[[nodiscard]] result<operator_cert_fields> fields_from(const value& v) {
    RHP_TRY(m, detail::fixed_map::of(v, 11, "a certificate body", kWhere));
    operator_cert_fields f;
    RHP_TRY(serial, m.count(0, "serial"));
    f.serial = serial;
    RHP_TRY(principal, m.text(1, "principal", kMaxCertText));
    f.principal = std::move(principal);
    RHP_TRY(alg, m.text(2, "alg", kMaxCertText));
    f.alg = std::move(alg);
    RHP_TRY(pub, m.bytes(3, "pub", 0, kMaxCertText));
    f.pub = *pub;
    RHP_TRY(not_before, m.count(4, "not_before"));
    f.not_before = not_before;
    RHP_TRY(not_after, m.count(5, "not_after"));
    f.not_after = not_after;
    RHP_TRY(role_text, m.text(6, "max_role", kMaxCertText));
    const auto r = parse_role(role_text);
    if (!r) {
        return std::unexpected{m.bad(std::format("unknown role '{}'", role_text))};
    }
    f.max_role = *r;
    RHP_TRY(apps, m.texts(7, "apps", kMaxCertListEntries, kMaxCertText));
    f.apps = std::move(apps);
    RHP_TRY(envs, m.texts(8, "envs", kMaxCertListEntries, kMaxCertText));
    f.envs = std::move(envs);
    RHP_TRY(scopes, m.texts(9, "scopes", kMaxCertListEntries, kMaxCertText));
    f.scopes = std::move(scopes);
    RHP_TRY(critical, m.texts(10, "critical", kMaxCertListEntries, kMaxCertText));
    f.critical = std::move(critical);
    return f;
}

[[nodiscard]] std::vector<std::byte> signed_message(std::span<const std::byte> body) {
    std::vector<std::byte> out;
    out.reserve(kOperatorCertDomain.size() + body.size());
    for (const char c : kOperatorCertDomain) {
        out.push_back(static_cast<std::byte>(c));
    }
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

} // namespace

std::string operator_cert::id() const {
    return std::format("{}#{}", fields.principal, fields.serial);
}

result<ed25519_public_key> operator_cert::operator_key() const {
    if (fields.alg != kAlgEd25519) {
        return invalid(std::format("certificate {} has a '{}' key; this build checks ed25519 keys", id(), fields.alg));
    }
    return ed25519_public_key::from_bytes(fields.pub);
}

result<void> validate_operator_cert(const operator_cert_fields& f) {
    if (f.serial == 0 || !fits(f.serial)) {
        return invalid("a certificate needs a serial from 1 to 2^63 - 1");
    }
    if (f.principal.empty() || f.principal.size() > kMaxCertText) {
        return invalid(std::format("a certificate needs a principal of 1 to {} bytes", kMaxCertText));
    }
    if (f.alg != kAlgEd25519) {
        return invalid(std::format("unknown key algorithm '{}' (ed25519)", f.alg));
    }
    if (f.pub.size() != ed25519_public_key::kSize) {
        return invalid(std::format("an ed25519 public key is {} bytes, got {}", ed25519_public_key::kSize, f.pub.size()));
    }
    if (!fits(f.not_before) || !fits(f.not_after) || f.not_after <= f.not_before) {
        return invalid("not_after must come after not_before (Unix seconds below 2^63)");
    }
    for (const auto* list : {&f.apps, &f.envs, &f.scopes, &f.critical}) {
        if (list->size() > kMaxCertListEntries) {
            return invalid(std::format("certificate lists hold at most {} entries", kMaxCertListEntries));
        }
        for (const std::string& item : *list) {
            if (item.empty() || item.size() > kMaxCertText) {
                return invalid(std::format("certificate list entries are 1 to {} bytes", kMaxCertText));
            }
        }
    }
    for (const std::string& env : f.envs) {
        if (!valid_env(env)) {
            return invalid(std::format("unknown environment '{}' (dev or prod)", env));
        }
    }
    return {};
}

result<operator_cert> issue_operator_cert(const ed25519_secret_key& ca_key, operator_cert_fields f) {
    if constexpr (!kSigning) {
        (void)ca_key;
        (void)f;
        return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", std::string{kWhere});
    } else {
        if (ca_key.empty()) {
            return invalid("issuing needs the CA's private key");
        }
        if (auto ok = validate_operator_cert(f); !ok) {
            return std::unexpected{std::move(ok).error()};
        }
        for (auto* list : {&f.apps, &f.envs, &f.scopes, &f.critical}) {
            *list = detail::canonical_set(std::move(*list));
        }
        RHP_TRY(body, detail::encode_canonical(body_value(f)));
        operator_cert out;
        out.sig = ca_key.sign(signed_message(body));
        out.fields = std::move(f);
        out.body = std::move(body);
        out.ca = ca_key.public_key();
        return out;
    }
}

result<std::vector<std::byte>> encode_operator_cert(const operator_cert& cert) {
    value::map m;
    m.emplace_back(value{"rhp"}, value{"opcert"});
    m.emplace_back(value{"body"}, value{value::bytes(cert.body.begin(), cert.body.end())});
    m.emplace_back(value{"ca"}, value{value::bytes(cert.ca.bytes().begin(), cert.ca.bytes().end())});
    m.emplace_back(value{"sig"}, value{value::bytes(cert.sig.begin(), cert.sig.end())});
    return detail::encode_canonical(value{std::move(m)});
}

result<operator_cert> decode_operator_cert(std::span<const std::byte> bytes) {
    if (bytes.size() > kMaxCertBytes) {
        return fail(errc::kProtocol, std::format("a certificate is at most {} bytes", kMaxCertBytes), std::string{kWhere});
    }
    RHP_TRY(outer, detail::decode_canonical(bytes));
    RHP_TRY(m, detail::fixed_map::of(outer, 4, "a certificate", kWhere));
    RHP_TRY(tag, m.text(0, "rhp", kMaxCertText));
    if (tag != "opcert") {
        return std::unexpected{m.bad(std::format("this is a '{}' document, not an operator certificate", tag))};
    }
    RHP_TRY(body, m.bytes(1, "body", 0, kMaxCertBytes));
    RHP_TRY(ca, m.bytes(2, "ca", ed25519_public_key::kSize));
    RHP_TRY(sig, m.bytes(3, "sig", ed25519_secret_key::kSignatureSize));
    operator_cert out;
    out.body = *body;
    RHP_TRY(ca_key, ed25519_public_key::from_bytes(*ca));
    out.ca = ca_key;
    std::ranges::copy(*sig, out.sig.begin());
    RHP_TRY(inner, detail::decode_canonical(out.body));
    RHP_TRY(f, fields_from(inner));
    if (auto ok = validate_operator_cert(f); !ok) {
        return fail(errc::kProtocol, ok.error().message, std::string{kWhere});
    }
    // Canonical: the body re-encodes to itself (sorted lists, smallest integer forms), so one
    // certificate has one encoding.
    auto again = detail::encode_canonical(body_value(f));
    if (!again || !std::ranges::equal(*again, out.body)) {
        return fail(errc::kProtocol, "the certificate body is not canonical", std::string{kWhere});
    }
    out.fields = std::move(f);
    return out;
}

result<std::string> operator_cert_to_text(const operator_cert& cert) {
    RHP_TRY(bytes, encode_operator_cert(cert));
    const std::string b64 = base64_encode(bytes);
    std::string text = std::format("# RHP operator certificate {} (max role {}, valid {} to {})\n{}\n", cert.id(), cert.fields.max_role, cert.fields.not_before,
                                   cert.fields.not_after, kBegin);
    for (std::size_t i = 0; i < b64.size(); i += 64) {
        text += b64.substr(i, 64);
        text += '\n';
    }
    text += kEnd;
    text += '\n';
    return text;
}

result<operator_cert> operator_cert_from_text(std::string_view text) {
    std::string b64;
    bool inside = false;
    bool ended = false;
    for (const detail::text_line& line : detail::content_lines(text)) {
        if (line.text == kBegin) {
            inside = true;
        } else if (line.text == kEnd) {
            ended = inside;
            break;
        } else if (inside) {
            b64 += line.text;
        }
    }
    if (!ended) {
        return invalid(std::format("expected the certificate between `{}` and `{}`", kBegin, kEnd));
    }
    RHP_TRY(bytes, base64_decode(b64));
    return decode_operator_cert(bytes);
}

result<operator_cert> load_operator_cert(const std::string& path) {
    const auto text = detail::read_file(path);
    if (!text) {
        return fail(errc::kNotFound, std::format("can't read certificate file {}", path), std::string{kWhere});
    }
    return operator_cert_from_text(*text);
}

result<void> save_operator_cert(const std::string& path, const operator_cert& cert) {
    RHP_TRY(text, operator_cert_to_text(cert));
    const auto* data = reinterpret_cast<const std::byte*>(text.data());
    return platform::replace_file(path, std::span<const std::byte>{data, text.size()});
}

// ---- trusted CAs ------------------------------------------------------------------------------------

result<void> trusted_cas::add(trusted_ca ca) {
    if (ca.name.empty()) {
        return invalid("a trusted CA needs a name");
    }
    if (!ca.env.empty() && !valid_env(ca.env)) {
        return invalid(std::format("unknown environment '{}' (dev or prod)", ca.env));
    }
    for (const trusted_ca& known : cas_) {
        if (known.name == ca.name || known.key == ca.key) {
            return fail(errc::kAlreadyLoaded, std::format("CA '{}' is already trusted", known.name), "security.trusted_cas");
        }
    }
    cas_.push_back(std::move(ca));
    return {};
}

result<trusted_cas> trusted_cas::parse(std::string_view text) {
    trusted_cas out;
    for (const detail::text_line& line : detail::content_lines(text)) {
        const auto f = detail::fields(line.text);
        const auto bad = [&](std::string_view what) { return fail(errc::kInvalidArgument, std::format("line {}: {}", line.number, what), "security.trusted_cas"); };
        if (f.size() != 2 && f.size() != 3) {
            return bad("expected `name base64-public-key [env=dev|prod]`");
        }
        trusted_ca ca;
        ca.name = f[0];
        auto key = ed25519_public_key::from_base64(f[1]);
        if (!key) {
            return bad(key.error().message);
        }
        ca.key = *key;
        if (f.size() == 3) {
            if (!f[2].starts_with("env=")) {
                return bad("the third field is env=dev or env=prod");
            }
            ca.env = f[2].substr(4);
        }
        if (auto added = out.add(std::move(ca)); !added) {
            return bad(added.error().message);
        }
    }
    return out;
}

result<trusted_cas> trusted_cas::from_file(const std::string& path) {
    const auto text = detail::read_file(path);
    if (!text) {
        return fail(errc::kNotFound, std::format("can't read trusted CA file {}", path), "security.trusted_cas");
    }
    return parse(*text);
}

const trusted_ca* trusted_cas::find(const ed25519_public_key& key) const noexcept {
    for (const trusted_ca& ca : cas_) {
        if (ca.key == key) {
            return &ca;
        }
    }
    return nullptr;
}

std::string trusted_ca_line(std::string_view name, const ed25519_public_key& key, std::string_view env) {
    return env.empty() ? std::format("{} {}", name, key.to_base64()) : std::format("{} {} env={}", name, key.to_base64(), env);
}

result<const trusted_ca*> verify_operator_cert(const operator_cert& cert, const trusted_cas& cas, std::chrono::system_clock::time_point now) {
    if constexpr (!kSigning) {
        (void)cert;
        (void)cas;
        (void)now;
        return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", std::string{kWhere});
    } else {
        const trusted_ca* ca = cas.find(cert.ca);
        if (ca == nullptr) {
            return fail(errc::kBadSignature, std::format("certificate {} is signed by a CA this host doesn't trust", cert.id()), std::string{kWhere});
        }
        if (!ed25519_check(ca->key, cert.sig, signed_message(cert.body))) {
            return fail(errc::kBadSignature, std::format("certificate {}'s signature by CA '{}' doesn't match", cert.id(), ca->name), std::string{kWhere});
        }
        // The fields are what was signed: decode_operator_cert read them from this body. A cert
        // built by hand must be re-read from its body.
        RHP_TRY(signed_fields, detail::decode_canonical(cert.body));
        RHP_TRY(f, fields_from(signed_fields));
        if (f != cert.fields) {
            return fail(errc::kBadSignature, std::format("certificate {}'s fields differ from its signed body", cert.id()), std::string{kWhere});
        }
        const std::uint64_t t = unix_seconds(now);
        if (t < f.not_before || t >= f.not_after) {
            return fail(errc::kExpired, std::format("certificate {} is valid from {} to {} (Unix seconds), now is {}", cert.id(), f.not_before, f.not_after, t),
                        std::string{kWhere});
        }
        if (!f.critical.empty()) {
            return fail(errc::kForbidden, std::format("certificate {} has a critical option this host doesn't understand: '{}'", cert.id(), f.critical.front()),
                        std::string{kWhere});
        }
        return ca;
    }
}

// ---- the CA key file ------------------------------------------------------------------------------------

result<operator_ca_key> operator_ca_key::generate(std::string name, std::string env) {
    if (name.empty() || detail::fields(name).size() != 1) {
        return invalid("a CA needs a name without spaces");
    }
    if (!env.empty() && !valid_env(env)) {
        return invalid(std::format("unknown environment '{}' (dev or prod)", env));
    }
    RHP_TRY(secret, ed25519_secret_key::generate());
    return operator_ca_key{std::move(name), std::move(secret), std::move(env)};
}

result<operator_ca_key> operator_ca_key::parse(std::string_view text) {
    operator_ca_key out;
    for (const detail::text_line& line : detail::content_lines(text)) {
        const auto bad = [&](std::string_view what) { return fail(errc::kInvalidArgument, std::format("line {}: {}", line.number, what), "security.operator_ca_key"); };
        const auto eq = line.text.find('=');
        if (eq == std::string_view::npos) {
            return bad("expected `key = \"value\"`");
        }
        const std::string_view field = detail::trim(line.text.substr(0, eq));
        std::string_view v = detail::trim(line.text.substr(eq + 1));
        if (v.size() < 2 || v.front() != '"' || v.back() != '"') {
            return bad("the value must be in double quotes");
        }
        v = v.substr(1, v.size() - 2);
        if (field == "name") {
            out.name = v;
        } else if (field == "env") {
            if (!valid_env(v)) {
                return bad("env is dev or prod");
            }
            out.env = v;
        } else if (field == "ca_key") {
            auto k = ed25519_secret_key::from_base64(v);
            if (!k) {
                return bad(k.error().message);
            }
            out.secret = std::move(*k);
        } else {
            return bad(std::format("unknown key '{}'", field));
        }
    }
    if (out.name.empty() || out.secret.empty()) {
        return invalid("a CA key file needs a name and a ca_key");
    }
    return out;
}

result<operator_ca_key> operator_ca_key::load(const std::string& path) {
    auto text = detail::read_file(path);
    if (!text) {
        return fail(errc::kNotFound, std::format("can't read CA key file {}", path), "security.operator_ca_key");
    }
    auto out = parse(*text);
    secure_wipe(text->data(), text->size());
    return out;
}

std::string operator_ca_key::to_text() const {
    std::string seed = secret.to_base64();
    const utils::scope_guard wipe{[&]() noexcept { secure_wipe(seed.data(), seed.size()); }};
    std::string text;
    text.reserve(256 + name.size());
    text += "# RHP operator CA: keep it offline and private\n";
    text += "name   = \"" + name + "\"\n";
    text += "ca_key = \"";
    text += seed;
    text += "\"\n";
    if (!env.empty()) {
        text += "env    = \"" + env + "\"\n";
    }
    return text;
}

result<void> operator_ca_key::save(const std::string& path) const {
    std::string text = to_text();
    const utils::scope_guard wipe{[&]() noexcept { secure_wipe(text.data(), text.size()); }};
    const auto* data = reinterpret_cast<const std::byte*>(text.data());
    return platform::write_private_file(path, std::span<const std::byte>{data, text.size()});
}

std::string operator_ca_key::trusted_line() const {
    return trusted_ca_line(name, secret.public_key(), env);
}

#undef RHP_TRY

} // namespace Rhp::security

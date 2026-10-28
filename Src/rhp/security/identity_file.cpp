#include <array>
#include <cstddef>
#include <filesystem>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/security/detail/text.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/identity_file.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/key_handle.hpp>
#include <rhp/security/key_store.hpp>
#include <rhp/utils/scope_guard.hpp>

namespace Rhp::security {

namespace {

[[nodiscard]] error bad_line(std::size_t number, std::string_view what, const char* where) {
    return make_error(errc::kInvalidArgument, std::format("line {}: {}", number, what), where);
}

// One `field = "value"` line of a key file.
struct quoted_field {
    std::size_t number = 0;
    std::string_view field;
    std::string_view value;
};

[[nodiscard]] result<std::vector<quoted_field>> quoted_fields(std::string_view text, const char* where) {
    std::vector<quoted_field> out;
    for (const detail::text_line& line : detail::content_lines(text)) {
        const auto eq = line.text.find('=');
        if (eq == std::string_view::npos) {
            return std::unexpected{bad_line(line.number, "expected `key = \"value\"`", where)};
        }
        const std::string_view v = detail::trim(line.text.substr(eq + 1));
        if (v.size() < 2 || v.front() != '"' || v.back() != '"') {
            return std::unexpected{bad_line(line.number, "the value must be in double quotes", where)};
        }
        out.push_back({line.number, detail::trim(line.text.substr(0, eq)), v.substr(1, v.size() - 2)});
    }
    return out;
}

[[nodiscard]] result<key_env> env_value(const quoted_field& f, const char* where) {
    const auto env = parse_key_env(f.value);
    if (!env) {
        return std::unexpected{bad_line(f.number, std::format("unknown env '{}' (dev or prod)", f.value), where)};
    }
    return *env;
}

[[nodiscard]] std::string env_suffix(std::optional<key_env> env) {
    return env ? std::format(" env={}", to_string(*env)) : std::string{};
}

// `field = "value"` lines in one allocation of their final size (secrets' text leaves no
// reallocated copy behind), after `header`.
struct text_line_out {
    std::string_view field; // padded, up to the opening quote
    std::string_view value;
    bool present;
};

[[nodiscard]] std::string join_lines(std::string_view header, std::span<const text_line_out> lines) {
    constexpr std::string_view kEnd = "\"\n";
    std::size_t size = header.size();
    for (const text_line_out& l : lines) {
        size += l.present ? l.field.size() + l.value.size() + kEnd.size() : 0;
    }
    std::string text;
    text.reserve(size);
    text += header;
    for (const text_line_out& l : lines) {
        if (l.present) {
            text += l.field;
            text += l.value;
            text += kEnd;
        }
    }
    return text;
}

[[nodiscard]] result<void> save_private(const std::string& path, std::string text, std::string_view what) {
    auto saved = platform::write_private_file(path, std::as_bytes(std::span{text}));
    secure_wipe(text.data(), text.size());
    if (!saved) {
        return fail(errc::kInvalidArgument, std::format("can't write {} {}: {}", what, path, saved.error().message), "security.identity_file");
    }
    return {};
}

} // namespace

// ---- identity files -------------------------------------------------------------------------------

result<identity_file> identity_file::parse(std::string_view text, const field_reader& extra) {
    constexpr const char* kIdentityWhere = "security.identity_file";
    auto fields = quoted_fields(text, kIdentityWhere);
    if (!fields) {
        return std::unexpected{std::move(fields).error()};
    }
    identity_file out;
    std::optional<key_algorithm> alg;
    std::optional<key> device;
    for (const quoted_field& f : *fields) {
        if (f.field == "name") {
            out.name = f.value;
        } else if (f.field == "signer") {
            out.signer = f.value;
        } else if (f.field == "psk") {
            auto k = key::from_base64(f.value);
            if (!k) {
                return std::unexpected{bad_line(f.number, k.error().message, kIdentityWhere)};
            }
            out.psk = std::move(*k);
        } else if (f.field == "signing_key") {
            if (is_passphrase_sealed(f.value)) {
                return fail(errc::kAuth, std::format("line {}: the signing key is sealed with a passphrase: keep it in a signing key file (.rhpsign)", f.number),
                            kIdentityWhere);
            }
            auto k = ed25519_secret_key::from_base64(f.value);
            if (!k) {
                return std::unexpected{bad_line(f.number, k.error().message, kIdentityWhere)};
            }
            out.signing = std::move(*k);
        } else if (f.field == "alg") {
            alg = parse_key_algorithm(f.value);
            if (!alg) {
                return std::unexpected{bad_line(f.number, std::format("unknown alg '{}' (ed25519 or p256)", f.value), kIdentityWhere)};
            }
        } else if (f.field == "device_key") {
            auto k = key::from_base64(f.value);
            if (!k || k->bytes().size() != key_handle::kPrivateKeySize) {
                return std::unexpected{bad_line(f.number, std::format("a device key is {} bytes of base64", key_handle::kPrivateKeySize), kIdentityWhere)};
            }
            device = std::move(*k);
        } else if (f.field == "env") {
            auto env = env_value(f, kIdentityWhere);
            if (!env) {
                return std::unexpected{std::move(env).error()};
            }
            out.env = *env;
        } else if (auto taken = extra ? extra(f.field, f.value) : result<bool>{false}; !taken) {
            return std::unexpected{bad_line(f.number, taken.error().message, kIdentityWhere)};
        } else if (!*taken) {
            return std::unexpected{bad_line(f.number, std::format("unknown key '{}'", f.field), kIdentityWhere)};
        }
    }
    if (out.name.empty()) {
        return fail(errc::kInvalidArgument, "an identity file needs a name", kIdentityWhere);
    }
    if (alg && !device) {
        return fail(errc::kInvalidArgument, "an identity file with an alg needs a device_key", kIdentityWhere);
    }
    if (device) {
        out.device = device_secret{alg.value_or(key_algorithm::kEd25519), std::move(*device)};
    }
    if (out.psk.empty() && !out.device) {
        return fail(errc::kInvalidArgument, "an identity file needs a psk or a device_key", kIdentityWhere);
    }
    if (!out.psk.empty() && out.psk.looks_weak()) {
        out.warnings.emplace_back("the psk looks chosen by a person (printable text or a repeated pattern), not random: rhp-cli keygen makes a random one");
    }
    return out;
}

result<identity_file> identity_file::load(const std::string& path, std::string_view passphrase) {
    auto text = detail::read_file(path);
    if (!text) {
        return fail(errc::kNotFound, std::format("can't read identity file {}", path), "security.identity_file");
    }
    auto id = parse(*text);
    secure_wipe(text->data(), text->size());
    if (!id) {
        return id;
    }
    if (auto warning = detail::exposure_warning(path)) {
        id->warnings.push_back(std::move(*warning));
    }
    if (id->signing) {
        return id;
    }
    const std::string signing_path = signing_key_file::beside(path);
    std::error_code ec;
    if (!std::filesystem::exists(std::filesystem::path{signing_path}, ec)) {
        return id;
    }
    if (passphrase.empty() && signing_key_file::sealed(signing_path)) {
        id->warnings.push_back(std::format("{} is sealed with a passphrase: without it this identity signs nothing", signing_path));
        return id;
    }
    auto signing_file = signing_key_file::load(signing_path, passphrase);
    if (!signing_file) {
        return std::unexpected{std::move(signing_file).error()};
    }
    id->attach(*signing_file);
    return id;
}

result<identity_file> identity_file::generate(std::string name) {
    if (name.empty()) {
        return fail(errc::kInvalidArgument, "an identity needs a name", "security.identity_file");
    }
    auto psk = key::generate();
    if (!psk) {
        return std::unexpected{std::move(psk).error()};
    }
    auto signing = ed25519_secret_key::generate();
    if (!signing) {
        return std::unexpected{std::move(signing).error()};
    }
    identity_file out;
    out.name = std::move(name);
    out.psk = std::move(*psk);
    out.signing = std::move(*signing);
    return out;
}

result<identity_file> identity_file::generate_device(std::string name, key_algorithm alg) {
    if (name.empty()) {
        return fail(errc::kInvalidArgument, "an identity needs a name", "security.identity_file");
    }
    auto device = generate_private_key(alg);
    if (!device) {
        return std::unexpected{std::move(device).error()};
    }
    auto signing = ed25519_secret_key::generate();
    if (!signing) {
        return std::unexpected{std::move(signing).error()};
    }
    identity_file out;
    out.name = std::move(name);
    out.device = device_secret{alg, std::move(*device)};
    out.signing = std::move(*signing);
    return out;
}

std::string identity_file::to_text() const {
    // The secrets' base64 stays in these (wiped on the way out).
    std::string psk_text = psk.empty() ? std::string{} : psk.to_base64();
    std::string device_text = device ? device->secret.to_base64() : std::string{};
    std::string signing_text = signing ? signing->to_base64() : std::string{};
    const utils::scope_guard wipe{[&]() noexcept {
        secure_wipe(psk_text.data(), psk_text.size());
        secure_wipe(device_text.data(), device_text.size());
        secure_wipe(signing_text.data(), signing_text.size());
    }};
    const std::array<text_line_out, 7> lines{{
        {"name        = \"", name, true},
        {"psk         = \"", psk_text, !psk.empty()},
        {"alg         = \"", device ? to_string(device->alg) : std::string_view{}, device.has_value()},
        {"device_key  = \"", device_text, device.has_value()},
        {"signing_key = \"", signing_text, signing.has_value()},
        {"signer      = \"", signer, signing.has_value() && !signer.empty() && signer != name},
        {"env         = \"", env ? to_string(*env) : std::string_view{}, env.has_value()},
    }};
    return join_lines("# RHP identity: keep it private (like an SSH key)\n", lines);
}

result<void> identity_file::save(const std::string& path) const {
    return save_private(path, to_text(), "identity file");
}

void identity_file::attach(const signing_key_file& signing_file) {
    signing = signing_file.secret;
    signer = signing_file.signer;
    signing_env = signing_file.env;
    warnings.insert(warnings.end(), signing_file.warnings.begin(), signing_file.warnings.end());
}

std::optional<signing_key> identity_file::signer_key() const {
    if (!signing) {
        return std::nullopt;
    }
    return signing_key{signer.empty() ? name : signer, *signing};
}

result<key_handle> identity_file::device_key() const {
    if (!device) {
        return fail(errc::kNotFound, std::format("identity '{}' has no device key", name), "security.identity_file");
    }
    return key_handle::from_private_key(device->alg, device->secret.bytes());
}

std::string identity_file::keyring_line(role granted) const {
    return std::format("{} {} {}{}", name, granted, psk.to_base64(), env_suffix(env));
}

std::optional<std::string> identity_file::signers_line() const {
    if (!signing) {
        return std::nullopt;
    }
    return std::format("{} {}{}", signer.empty() ? name : signer, signing->public_key().to_base64(), env_suffix(signing_env ? signing_env : env));
}

result<std::string> identity_file::device_line(role granted) const {
    auto handle = device_key();
    if (!handle) {
        return std::unexpected{std::move(handle).error()};
    }
    return std::format("{} {} {} {}{}", name, granted, to_string(handle->alg()), base64_encode(handle->public_key()), env_suffix(env));
}

// ---- signing key files ----------------------------------------------------------------------------

result<signing_key_file> signing_key_file::parse(std::string_view text, std::string_view passphrase) {
    constexpr const char* kSigningWhere = "security.signing_key_file";
    auto fields = quoted_fields(text, kSigningWhere);
    if (!fields) {
        return std::unexpected{std::move(fields).error()};
    }
    signing_key_file out;
    bool have_key = false;
    for (const quoted_field& f : *fields) {
        if (f.field == "signer") {
            out.signer = f.value;
        } else if (f.field == "env") {
            auto env = env_value(f, kSigningWhere);
            if (!env) {
                return std::unexpected{std::move(env).error()};
            }
            out.env = *env;
        } else if (f.field == "signing_key") {
            if (is_passphrase_sealed(f.value) && passphrase.empty()) {
                return fail(errc::kAuth, "the signing key is sealed with a passphrase", kSigningWhere);
            }
            auto k = [&]() -> result<ed25519_secret_key> {
                if (!is_passphrase_sealed(f.value)) {
                    return ed25519_secret_key::from_base64(f.value);
                }
                auto opened = open_with_passphrase(f.value, passphrase); // kAuth for a wrong passphrase
                if (!opened) {
                    return std::unexpected{std::move(opened).error()};
                }
                return ed25519_secret_key::from_bytes(opened->bytes());
            }();
            if (!k) {
                return k.error().code == errc::kInvalidArgument ? std::unexpected{bad_line(f.number, k.error().message, kSigningWhere)} : std::unexpected{k.error()};
            }
            out.secret = std::move(*k);
            have_key = true;
        } else {
            return std::unexpected{bad_line(f.number, std::format("unknown key '{}'", f.field), kSigningWhere)};
        }
    }
    if (out.signer.empty()) {
        return fail(errc::kInvalidArgument, "a signing key file needs a signer", kSigningWhere);
    }
    if (!have_key) {
        return fail(errc::kInvalidArgument, "a signing key file needs a signing_key", kSigningWhere);
    }
    return out;
}

result<signing_key_file> signing_key_file::load(const std::string& path, std::string_view passphrase) {
    auto text = detail::read_file(path);
    if (!text) {
        return fail(errc::kNotFound, std::format("can't read signing key file {}", path), "security.signing_key_file");
    }
    auto out = parse(*text, passphrase);
    secure_wipe(text->data(), text->size());
    if (!out) {
        return fail(out.error().code, std::format("{}: {}", path, out.error().message), "security.signing_key_file");
    }
    if (auto warning = detail::exposure_warning(path)) {
        out->warnings.push_back(std::move(*warning));
    }
    return out;
}

bool signing_key_file::sealed(const std::string& path) {
    auto text = detail::read_file(path);
    if (!text) {
        return false;
    }
    bool found = false;
    if (auto fields = quoted_fields(*text, "security.signing_key_file")) {
        for (const quoted_field& f : *fields) {
            found = found || (f.field == "signing_key" && is_passphrase_sealed(f.value));
        }
    }
    secure_wipe(text->data(), text->size());
    return found;
}

std::string signing_key_file::beside(const std::string& identity_path) {
    return std::filesystem::path{identity_path}.replace_extension(".rhpsign").string();
}

result<std::string> signing_key_file::to_text(std::string_view passphrase, const passphrase_kdf& kdf) const {
    std::string key_text = secret.to_base64();
    const utils::scope_guard wipe{[&]() noexcept { secure_wipe(key_text.data(), key_text.size()); }};
    if (!passphrase.empty()) {
        auto seed = base64_decode(key_text);
        if (!seed) {
            return std::unexpected{std::move(seed).error()};
        }
        auto sealed_text = seal_with_passphrase(*seed, passphrase, kdf);
        secure_wipe(seed->data(), seed->size());
        if (!sealed_text) {
            return std::unexpected{std::move(sealed_text).error()};
        }
        secure_wipe(key_text.data(), key_text.size());
        key_text = std::move(*sealed_text);
    }
    const std::array<text_line_out, 3> lines{{
        {"signer      = \"", signer, true},
        {"signing_key = \"", key_text, true},
        {"env         = \"", env ? to_string(*env) : std::string_view{}, env.has_value()},
    }};
    return join_lines("# RHP signing key: keep it private (like an SSH key)\n", lines);
}

result<void> signing_key_file::save(const std::string& path, std::string_view passphrase, const passphrase_kdf& kdf) const {
    auto text = to_text(passphrase, kdf);
    if (!text) {
        return std::unexpected{std::move(text).error()};
    }
    return save_private(path, std::move(*text), "signing key file");
}

std::string signing_key_file::signers_line() const {
    return std::format("{} {}{}", signer, secret.public_key().to_base64(), env_suffix(env));
}

} // namespace Rhp::security

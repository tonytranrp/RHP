#include <format>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/security/detail/text.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/identity_file.hpp>
#include <rhp/security/key.hpp>

namespace Rhp::security {

namespace {

[[nodiscard]] error bad_line(std::size_t number, std::string_view what) {
    return make_error(errc::kInvalidArgument, std::format("line {}: {}", number, what), "security.identity_file");
}

} // namespace

result<identity_file> identity_file::parse(std::string_view text) {
    identity_file out;
    for (const detail::text_line& line : detail::content_lines(text)) {
        const auto eq = line.text.find('=');
        if (eq == std::string_view::npos) {
            return std::unexpected{bad_line(line.number, "expected `key = \"value\"`")};
        }
        const std::string_view field = detail::trim(line.text.substr(0, eq));
        std::string_view v = detail::trim(line.text.substr(eq + 1));
        if (v.size() < 2 || v.front() != '"' || v.back() != '"') {
            return std::unexpected{bad_line(line.number, "the value must be in double quotes")};
        }
        v = v.substr(1, v.size() - 2);
        if (field == "name") {
            out.name = v;
        } else if (field == "signer") {
            out.signer = v;
        } else if (field == "psk") {
            auto k = key::from_base64(v);
            if (!k) {
                return std::unexpected{bad_line(line.number, k.error().message)};
            }
            out.psk = std::move(*k);
        } else if (field == "signing_key") {
            auto k = ed25519_secret_key::from_base64(v);
            if (!k) {
                return std::unexpected{bad_line(line.number, k.error().message)};
            }
            out.signing = std::move(*k);
        } else {
            return std::unexpected{bad_line(line.number, std::format("unknown key '{}'", field))};
        }
    }
    if (out.name.empty()) {
        return fail(errc::kInvalidArgument, "an identity file needs a name", "security.identity_file");
    }
    if (out.psk.empty()) {
        return fail(errc::kInvalidArgument, "an identity file needs a psk", "security.identity_file");
    }
    return out;
}

result<identity_file> identity_file::load(const std::string& path) {
    auto text = detail::read_file(path);
    if (!text) {
        return fail(errc::kNotFound, std::format("can't read identity file {}", path), "security.identity_file");
    }
    auto id = parse(*text);
    secure_wipe(text->data(), text->size());
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

std::string identity_file::to_text() const {
    std::string text = std::format("# RHP identity: keep it private (like an SSH key)\nname        = \"{}\"\npsk         = \"{}\"\n", name, psk.to_base64());
    if (signing) {
        text += std::format("signing_key = \"{}\"\n", signing->to_base64());
    }
    if (!signer.empty() && signer != name) {
        text += std::format("signer      = \"{}\"\n", signer);
    }
    return text;
}

result<void> identity_file::save(const std::string& path) const {
    std::ofstream out{path, std::ios::binary | std::ios::trunc};
    if (!out) {
        return fail(errc::kInvalidArgument, std::format("can't write identity file {}", path), "security.identity_file");
    }
    std::string text = to_text();
    out << text;
    secure_wipe(text.data(), text.size());
    if (!out.flush()) {
        return fail(errc::kInvalidArgument, std::format("can't write identity file {}", path), "security.identity_file");
    }
    return {};
}

std::optional<signing_key> identity_file::signer_key() const {
    if (!signing) {
        return std::nullopt;
    }
    return signing_key{signer.empty() ? name : signer, *signing};
}

std::string identity_file::keyring_line(role granted) const {
    return std::format("{} {} {}", name, granted, psk.to_base64());
}

std::optional<std::string> identity_file::signers_line() const {
    if (!signing) {
        return std::nullopt;
    }
    return std::format("{} {}", signer.empty() ? name : signer, signing->public_key().to_base64());
}

} // namespace Rhp::security

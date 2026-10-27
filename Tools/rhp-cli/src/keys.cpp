// rhp-cli keygen / pubkey / sign: identity files and script signatures, no network.
#include <filesystem>
#include <format>
#include <print>
#include <string>
#include <system_error>

#include "commands.hpp"
#include "shell.hpp"

#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/security/identity_file.hpp>
#include <rhp/security/key.hpp>

namespace rhp_cli {

int keygen(const std::string& name, const std::string& out_path, const std::string& role_text, bool force) {
    const auto granted = Rhp::parse_role(role_text);
    if (!granted) {
        std::println(stderr, "unknown role '{}' (observe, patch or admin)", role_text);
        return 2;
    }
    const std::string path = out_path.empty() ? name + ".rhpid" : out_path;
    std::error_code ec;
    if (!force && std::filesystem::exists(path, ec)) {
        std::println(stderr, "{} exists (use --force to replace it)", path);
        return 1;
    }
    auto id = Rhp::security::identity_file::generate(name);
    if (!id) {
        std::println(stderr, "{}", id.error());
        return 1;
    }
    if (auto saved = id->save(path); !saved) {
        std::println(stderr, "{}", saved.error());
        return 1;
    }
    std::println("wrote {} (keep it private)", path);
    std::println("add to the host's keyring file:   {}", id->keyring_line(*granted));
    std::println("add to the host's signers file:   {}", *id->signers_line());
    return 0;
}

int pubkey(const std::string& identity, const std::string& role_text) {
    const auto granted = Rhp::parse_role(role_text);
    auto id = Rhp::security::identity_file::load(identity);
    if (!id || !granted) {
        std::println(stderr, "{}", id ? std::string{"unknown role"} : std::format("{}", id.error()));
        return 1;
    }
    std::println("{}", id->keyring_line(*granted));
    if (auto line = id->signers_line()) {
        std::println("{}", *line);
    }
    return 0;
}

int sign(const std::string& file, const std::string& identity) {
    auto id = Rhp::security::identity_file::load(identity);
    if (!id) {
        std::println(stderr, "{}", id.error());
        return 1;
    }
    auto key = id->signer_key();
    if (!key) {
        std::println(stderr, "{} has no signing_key", identity);
        return 1;
    }
    const auto source = rhp_cli::read_text_file(file);
    if (!source) {
        std::println(stderr, "can't read {}", file);
        return 1;
    }
    auto signature = key->sign(*source);
    if (!signature) {
        std::println(stderr, "{}", signature.error());
        return 1;
    }
    const auto* sig = signature->find("sig");
    std::println("{} {}", key->name, Rhp::security::base64_encode(*sig->get_if<Rhp::value::bytes>()));
    return 0;
}

} // namespace rhp_cli

// rhp-cli keygen / pubkey / sign: identity files and script signatures, no network.
#include <filesystem>
#include <format>
#include <memory>
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

namespace {

struct keygen_options {
    std::string name;
    std::string out_path;
    std::string role = "admin";
    bool force = false;
};

int run_keygen(const keygen_options& o) {
    const auto granted = Rhp::parse_role(o.role);
    if (!granted) {
        std::println(stderr, "unknown role '{}' (observe, patch or admin)", o.role);
        return 2;
    }
    const std::string path = o.out_path.empty() ? o.name + ".rhpid" : o.out_path;
    std::error_code ec;
    if (!o.force && std::filesystem::exists(path, ec)) {
        std::println(stderr, "{} exists (use --force to replace it)", path);
        return 1;
    }
    auto id = Rhp::security::identity_file::generate(o.name);
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

struct pubkey_options {
    std::string identity;
    std::string role = "admin";
};

int run_pubkey(const pubkey_options& o) {
    const auto granted = Rhp::parse_role(o.role);
    auto id = Rhp::security::identity_file::load(o.identity);
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

struct sign_options {
    std::string file;
    std::string identity;
};

int run_sign(const sign_options& o) {
    auto id = Rhp::security::identity_file::load(o.identity);
    if (!id) {
        std::println(stderr, "{}", id.error());
        return 1;
    }
    auto key = id->signer_key();
    if (!key) {
        std::println(stderr, "{} has no signing_key", o.identity);
        return 1;
    }
    const auto source = read_text_file(o.file);
    if (!source) {
        std::println(stderr, "can't read {}", o.file);
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

} // namespace

void add_keygen(CLI::App& app, command_list& out) {
    auto o = std::make_shared<keygen_options>();
    auto* cmd = app.add_subcommand("keygen", "create an identity file (PSK + Ed25519 signing key)");
    cmd->add_option("name", o->name, "the key name the host will know")->required();
    cmd->add_option("-o,--out", o->out_path, "identity file to write (default <name>.rhpid)");
    cmd->add_option("--role", o->role, "role printed in the keyring line (observe, patch, admin)");
    cmd->add_flag("--force", o->force, "replace an existing file");
    out.emplace_back(cmd, [o] { return run_keygen(*o); });
}

void add_pubkey(CLI::App& app, command_list& out) {
    auto o = std::make_shared<pubkey_options>();
    auto* cmd = app.add_subcommand("pubkey", "print the host's keyring and signers lines for an identity");
    cmd->add_option("-i,--identity", o->identity, "identity file")->required()->envname("RHP_IDENTITY");
    cmd->add_option("--role", o->role, "role for the keyring line");
    out.emplace_back(cmd, [o] { return run_pubkey(*o); });
}

void add_sign(CLI::App& app, command_list& out) {
    auto o = std::make_shared<sign_options>();
    auto* cmd = app.add_subcommand("sign", "print the signature of a script (`signer base64`)");
    cmd->add_option("file", o->file, "the .lua file")->required();
    cmd->add_option("-i,--identity", o->identity, "identity file")->required()->envname("RHP_IDENTITY");
    out.emplace_back(cmd, [o] { return run_sign(*o); });
}

} // namespace rhp_cli

// rhp-cli keygen / pubkey / sign: identity files and script signatures, no network.
#include <filesystem>
#include <format>
#include <memory>
#include <print>
#include <string>
#include <system_error>

#include "commands.hpp"
#include "connection.hpp"
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
    std::string role = "patch";
    bool force = false;
    bool show_secret = false;
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
    if (*granted == Rhp::role::kAdmin) {
        std::println(stderr, "warning: an admin identity may use the host's whole Lua library (io, os) and admin operations (revert_all, pin); patch loads and calls modules");
    }
    // The keyring line holds the PSK: it stays in the file (off the screen and the scrollback) unless
    // asked for; pubkey prints it whole for scripts that write the host's files.
    std::println("wrote {} (keep it private)", path);
    if (o.show_secret) {
        std::println("add to the host's keyring file:   {}", id->keyring_line(*granted));
    } else {
        std::println("add to the host's keyring file:   {} {} <psk from {}>   (rhp-cli pubkey -i {} --role {} prints it whole)", id->name, *granted, path, path, *granted);
    }
    std::println("add to the host's signers file:   {}", *id->signers_line());
    return 0;
}

struct pubkey_options {
    std::string identity;
    std::string role = "patch";
};

int run_pubkey(const pubkey_options& o) {
    const auto granted = Rhp::parse_role(o.role);
    if (!granted) {
        std::println(stderr, "unknown role '{}' (observe, patch or admin)", o.role);
        return 2;
    }
    auto id = load_identity(o.identity);
    if (!id) {
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
    const auto s = load_signer(o.identity);
    if (!s) {
        return 1;
    }
    const auto source = read_text_file(o.file);
    if (!source) {
        std::println(stderr, "can't read {}", o.file);
        return 1;
    }
    auto signature = s->key.sign(*source);
    if (!signature) {
        std::println(stderr, "{}", signature.error());
        return 1;
    }
    const Rhp::value* sig = signature->find("sig");
    const auto* bytes = sig != nullptr ? sig->get_if<Rhp::value::bytes>() : nullptr;
    if (bytes == nullptr) {
        std::println(stderr, "the signature has no sig bytes");
        return 1;
    }
    std::println("{} {}", s->key.name, Rhp::security::base64_encode(*bytes));
    return 0;
}

} // namespace

void add_keygen(CLI::App& app, command_list& out) {
    auto o = std::make_shared<keygen_options>();
    auto* cmd = app.add_subcommand("keygen", "create an identity file (PSK + Ed25519 signing key)");
    cmd->add_option("name", o->name, "the key name the host will know")->required();
    cmd->add_option("-o,--out", o->out_path, "identity file to write (default <name>.rhpid)");
    cmd->add_option("--role", o->role, "role for the keyring line (observe, patch, admin; default patch)");
    cmd->add_flag("--force", o->force, "replace an existing file");
    cmd->add_flag("--show-secret", o->show_secret, "print the keyring line with the PSK (default: it stays in the file)");
    out.emplace_back(cmd, [o] { return run_keygen(*o); });
}

void add_pubkey(CLI::App& app, command_list& out) {
    auto o = std::make_shared<pubkey_options>();
    auto* cmd = app.add_subcommand("pubkey", "print the host's keyring line (it holds the PSK) and signers line for an identity");
    cmd->add_option("-i,--identity", o->identity, "identity file")->required()->envname("RHP_IDENTITY");
    cmd->add_option("--role", o->role, "role for the keyring line (default patch)");
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

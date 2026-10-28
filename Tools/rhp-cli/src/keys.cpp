// rhp-cli keygen / pubkey / sign: identity and signing key files and script signatures, no network.
#include <filesystem>
#include <format>
#include <memory>
#include <optional>
#include <print>
#include <string>
#include <system_error>

#include "commands.hpp"
#include "connection.hpp"
#include "shell.hpp"

#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/platform/key_storage.hpp>
#include <rhp/platform/process.hpp>
#include <rhp/security/identity_file.hpp>
#include <rhp/security/key.hpp>
#include <rhp/utils/scope_guard.hpp>

namespace rhp_cli {

namespace {

struct keygen_options {
    std::string name;
    std::string out_path;
    std::string role = "patch";
    std::string env = "dev";
    bool force = false;
    bool show_secret = false;
    bool passphrase = false;
    bool device = false;
};

// --passphrase: RHP_PASSPHRASE, else typed twice on the terminal; nullopt after saying why not.
std::optional<std::string> new_passphrase() {
    std::string passphrase = Rhp::platform::environment_variable("RHP_PASSPHRASE");
    if (!passphrase.empty()) {
        return passphrase;
    }
    auto first = Rhp::platform::read_secret_line("passphrase for the signing key: ");
    if (!first) {
        std::println(stderr, "--passphrase needs a terminal to type it on, or RHP_PASSPHRASE");
        return std::nullopt;
    }
    auto again = Rhp::platform::read_secret_line("again: ");
    const bool same = again && *again == *first;
    if (again) {
        Rhp::security::secure_wipe(again->data(), again->size());
    }
    if (!same || first->empty()) {
        Rhp::security::secure_wipe(first->data(), first->size());
        std::println(stderr, "{}", first->empty() ? "an empty passphrase protects nothing" : "the passphrases don't match");
        return std::nullopt;
    }
    return std::move(*first);
}

int run_keygen(const keygen_options& o) {
    const auto granted = Rhp::parse_role(o.role);
    if (!granted) {
        std::println(stderr, "unknown role '{}' (observe, patch or admin)", o.role);
        return 2;
    }
    const auto env = Rhp::security::parse_key_env(o.env);
    if (!env) {
        std::println(stderr, "unknown env '{}' (dev or prod)", o.env);
        return 2;
    }
    const std::string path = o.out_path.empty() ? o.name + ".rhpid" : o.out_path;
    const std::string signing_path = Rhp::security::signing_key_file::beside(path);
    for (const std::string& p : {path, signing_path}) {
        std::error_code ec;
        if (!o.force && std::filesystem::exists(p, ec)) {
            std::println(stderr, "{} exists (use --force to replace it)", p);
            return 1;
        }
    }
    std::string passphrase;
    const Rhp::utils::scope_guard wipe{[&]() noexcept { Rhp::security::secure_wipe(passphrase.data(), passphrase.size()); }};
    if (o.passphrase) {
        auto typed = new_passphrase();
        if (!typed) {
            return 1;
        }
        passphrase = std::move(*typed);
    }
    auto id = o.device ? Rhp::security::identity_file::generate_device(o.name) : Rhp::security::identity_file::generate(o.name);
    if (!id) {
        std::println(stderr, "{}", id.error());
        return 1;
    }
    // Two files (decision AL11): the connection identity, and the signing key beside it.
    const Rhp::security::signing_key_file signing{id->name, *id->signing, *env, {}};
    id->signing.reset();
    id->env = *env;
    if (auto saved = signing.save(signing_path, passphrase); !saved) {
        std::println(stderr, "{}", saved.error());
        return 1;
    }
    if (auto saved = id->save(path); !saved) {
        std::println(stderr, "{}", saved.error());
        return 1;
    }
    if (*granted == Rhp::role::kAdmin) {
        std::println(stderr, "warning: an admin identity may use the host's whole Lua library (io, os) and admin operations (revert_all, pin); patch loads and calls modules");
    }
    std::println("wrote {} (connection identity) and {} (signing key{}): keep them private", path, signing_path, passphrase.empty() ? "" : ", sealed with your passphrase");
    if (o.device) {
        // The public half only: nothing secret in the allow-list line.
        auto line = id->device_line(*granted);
        if (!line) {
            std::println(stderr, "{}", line.error());
            return 1;
        }
        std::println("add to the host's device allow-list: {}", *line);
    } else if (o.show_secret) {
        // The keyring line holds the PSK: it stays in the file (off the screen and the scrollback)
        // unless asked for; pubkey prints it whole for scripts that write the host's files.
        std::println("add to the host's keyring file:   {}", id->keyring_line(*granted));
    } else {
        std::println("add to the host's keyring file:   {} {} <psk from {}> env={}   (rhp-cli pubkey -i {} --role {} prints it whole)", id->name, *granted, path,
                     Rhp::security::to_string(*env), path, *granted);
    }
    std::println("add to the host's signers file:   {}", signing.signers_line());
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
    if (id->device) {
        auto line = id->device_line(*granted);
        if (!line) {
            std::println(stderr, "{}", line.error());
            return 1;
        }
        std::println("{}", *line);
    } else {
        std::println("{}", id->keyring_line(*granted));
    }
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
    auto* cmd = app.add_subcommand("keygen", "create a connection identity (<name>.rhpid: PSK or device key) and a signing key (<name>.rhpsign: Ed25519)");
    cmd->add_option("name", o->name, "the key name the host will know")->required();
    cmd->add_option("-o,--out", o->out_path, "identity file to write (default <name>.rhpid; the signing key goes beside it as .rhpsign)");
    cmd->add_option("--role", o->role, "role for the keyring line (observe, patch, admin; default patch)");
    cmd->add_option("--env", o->env, "tag both keys for this environment (dev or prod; default dev)");
    cmd->add_flag("--passphrase", o->passphrase, "seal the signing key with a passphrase (typed twice, or RHP_PASSPHRASE)");
    cmd->add_flag("--device", o->device, "an Ed25519 device key instead of a PSK (for hosts with device-key authentication)");
    cmd->add_flag("--force", o->force, "replace existing files");
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

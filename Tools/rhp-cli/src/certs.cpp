// rhp-cli ca / cert: operator CAs and operator certificates (decision AL11), no network.
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <memory>
#include <print>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "commands.hpp"
#include "connection.hpp"
#include "text.hpp"

#include <rhp/core/role.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/identity_file.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/key_handle.hpp>
#include <rhp/security/operator_cert.hpp>

namespace rhp_cli {

namespace {

namespace sec = Rhp::security;

[[nodiscard]] bool refuse_existing(const std::string& path, bool force) {
    std::error_code ec;
    if (!force && std::filesystem::exists(path, ec)) {
        std::println(stderr, "{} exists (use --force to replace it)", path);
        return true;
    }
    return false;
}

struct ca_init_options {
    std::string name;
    std::string out_path;
    std::string env;
    bool force = false;
};

int run_ca_init(const ca_init_options& o) {
    const std::string path = o.out_path.empty() ? o.name + ".rhpca" : o.out_path;
    if (refuse_existing(path, o.force)) {
        return 1;
    }
    auto ca = sec::operator_ca_key::generate(o.name, o.env);
    if (!ca) {
        std::println(stderr, "{}", ca.error());
        return 1;
    }
    if (auto saved = ca->save(path); !saved) {
        std::println(stderr, "{}", saved.error());
        return 1;
    }
    std::println("wrote {} (keep it offline and private)", path);
    std::println("add to the host's trusted CA file:   {}", ca->trusted_line());
    return 0;
}

struct operator_public {
    sec::key_algorithm alg = sec::key_algorithm::kEd25519;
    std::vector<std::byte> pub;
};

[[nodiscard]] Rhp::result<operator_public> ed25519_public(std::string_view base64) {
    auto key = sec::ed25519_public_key::from_base64(base64);
    if (!key) {
        return std::unexpected{std::move(key).error()};
    }
    return operator_public{sec::key_algorithm::kEd25519, std::vector<std::byte>(key->bytes().begin(), key->bytes().end())};
}

// `[name] [alg] base64-public-key`: Ed25519 unless the word before the key names an algorithm.
[[nodiscard]] Rhp::result<operator_public> public_from_words(const std::vector<std::string>& words) {
    if (words.empty()) {
        return Rhp::fail(Rhp::errc::kInvalidArgument, "no public key", "rhp-cli.cert");
    }
    if (words.size() >= 2) {
        if (const auto alg = sec::parse_key_algorithm(words[words.size() - 2]); alg && *alg != sec::key_algorithm::kEd25519) {
            auto pub = sec::base64_decode(words.back());
            if (!pub) {
                return std::unexpected{std::move(pub).error()};
            }
            return operator_public{*alg, std::move(*pub)};
        }
    }
    return ed25519_public(words.back());
}

// The operator's public key from --key: an identity file's signing key (with --device, its device
// key, Ed25519 or P-256: a hardware-backed operator key), or a file (or the text itself) holding
// `[name] [alg] base64-public-key`, as `rhp-cli pubkey` prints it.
[[nodiscard]] Rhp::result<operator_public> operator_public_key(const std::string& from, bool device) {
    std::error_code ec;
    if (std::filesystem::is_regular_file(from, ec)) {
        if (auto id = sec::identity_file::load(from)) {
            if (device) {
                auto handle = id->device_key();
                if (!handle) {
                    return Rhp::fail(Rhp::errc::kInvalidArgument, std::format("{} has no device key: {}", from, handle.error().message), "rhp-cli.cert");
                }
                return operator_public{handle->alg(), std::vector<std::byte>(handle->public_key().begin(), handle->public_key().end())};
            }
            if (!id->signing) {
                return Rhp::fail(Rhp::errc::kInvalidArgument, std::format("{} has no signing_key (--device takes its device key)", from), "rhp-cli.cert");
            }
            return ed25519_public(id->signing->public_key().to_base64());
        }
        const auto text = read_text_file(from);
        if (!text) {
            return Rhp::fail(Rhp::errc::kNotFound, std::format("can't read {}", from), "rhp-cli.cert");
        }
        const auto words = split_words(*text);
        if (!words.empty()) {
            return public_from_words(words);
        }
    }
    return public_from_words(split_words(from));
}

struct cert_issue_options {
    std::string ca;
    std::string principal;
    std::string key;
    std::string out_path;
    double hours = 8;
    std::string max_role = "patch";
    std::vector<std::string> apps;
    std::vector<std::string> envs;
    std::vector<std::string> scopes;
    std::uint64_t serial = 0;
    bool device = false;
    bool force = false;
};

int run_cert_issue(const cert_issue_options& o) {
    const auto role = Rhp::parse_role(o.max_role);
    if (!role) {
        std::println(stderr, "unknown role '{}' (observe, patch or admin)", o.max_role);
        return 2;
    }
    if (o.hours <= 0) {
        std::println(stderr, "--hours must be positive");
        return 2;
    }
    const std::string path = o.out_path.empty() ? o.principal + ".rhpcert" : o.out_path;
    if (refuse_existing(path, o.force)) {
        return 1;
    }
    auto ca = sec::operator_ca_key::load(o.ca);
    if (!ca) {
        std::println(stderr, "{}", ca.error());
        return 1;
    }
    auto pub = operator_public_key(o.key, o.device);
    if (!pub) {
        std::println(stderr, "--key {}: {}", o.key, pub.error().message);
        return 1;
    }
    sec::operator_cert_fields f;
    f.serial = o.serial;
    if (f.serial == 0) { // random, below 2^63
        const auto bytes = Rhp::platform::random_array<8>();
        if (!bytes) {
            std::println(stderr, "{}", bytes.error());
            return 1;
        }
        for (const std::byte b : *bytes) {
            f.serial = (f.serial << 8) | static_cast<std::uint64_t>(b);
        }
        f.serial = (f.serial >> 1) | 1u;
    }
    f.principal = o.principal;
    f.alg = std::string{sec::to_string(pub->alg)};
    f.pub = std::move(pub->pub);
    const auto now = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    f.not_before = now - 60; // a little clock skew
    f.not_after = now + static_cast<std::uint64_t>(o.hours * 3600);
    f.max_role = *role;
    f.apps = o.apps;
    f.envs = o.envs;
    // A dev CA issues dev certificates.
    if (ca->env == sec::kEnvDev && f.envs.empty()) {
        f.envs.emplace_back(sec::kEnvDev);
    }
    f.scopes = o.scopes;
    auto cert = sec::issue_operator_cert(ca->secret, std::move(f));
    if (!cert) {
        std::println(stderr, "{}", cert.error());
        return 1;
    }
    if (auto saved = sec::save_operator_cert(path, *cert); !saved) {
        std::println(stderr, "{}", saved.error());
        return 1;
    }
    std::println("wrote {}: {} (max role {}, {} h)", path, cert->id(), cert->fields.max_role, o.hours);
    return 0;
}

[[nodiscard]] std::string joined(const std::vector<std::string>& list) {
    if (list.empty()) {
        return "(any)";
    }
    std::string out;
    for (const std::string& s : list) {
        out += out.empty() ? s : ", " + s;
    }
    return out;
}

struct cert_show_options {
    std::string file;
    std::string trusted;
};

int run_cert_show(const cert_show_options& o) {
    auto cert = sec::load_operator_cert(o.file);
    if (!cert) {
        std::println(stderr, "{}", cert.error());
        return 1;
    }
    const auto& f = cert->fields;
    std::println("certificate  {}", cert->id());
    std::println("principal    {}", f.principal);
    std::println("serial       {}", f.serial);
    std::println("key          {} {}", f.alg, sec::base64_encode(f.pub));
    std::println("valid        {} to {} (Unix seconds)", f.not_before, f.not_after);
    std::println("max role     {}", f.max_role);
    std::println("apps         {}", joined(f.apps));
    std::println("envs         {}", joined(f.envs));
    std::println("scopes       {}", joined(f.scopes));
    if (!f.critical.empty()) {
        std::println("critical     {}", joined(f.critical));
    }
    std::println("ca           {}", cert->ca.to_base64());
    if (o.trusted.empty()) {
        return 0;
    }
    auto cas = sec::trusted_cas::from_file(o.trusted);
    if (!cas) {
        std::println(stderr, "{}", cas.error());
        return 1;
    }
    auto ok = sec::verify_operator_cert(*cert, *cas, std::chrono::system_clock::now());
    if (!ok) {
        std::println("check        {}", ok.error().message);
        return 1;
    }
    std::println("check        valid now, signed by CA '{}'", (*ok)->name);
    return 0;
}

} // namespace

void add_ca(CLI::App& app, command_list& out) {
    auto* ca = app.add_subcommand("ca", "operator certificate authorities");
    ca->require_subcommand(1);
    auto o = std::make_shared<ca_init_options>();
    auto* init = ca->add_subcommand("init", "create an operator CA key (keep it offline) and print the host's trusted-CA line");
    init->add_option("name", o->name, "the CA's name (hosts name it in messages)")->required();
    init->add_option("-o,--out", o->out_path, "CA key file to write (default <name>.rhpca)");
    init->add_option("--env", o->env, "tag it dev or prod: production hosts refuse dev CAs");
    init->add_flag("--force", o->force, "replace an existing file");
    out.emplace_back(init, [o] { return run_ca_init(*o); });
}

void add_cert(CLI::App& app, command_list& out) {
    auto* cert = app.add_subcommand("cert", "operator certificates");
    cert->require_subcommand(1);
    auto issue = std::make_shared<cert_issue_options>();
    auto* cmd = cert->add_subcommand("issue", "issue a short-lived operator certificate (.rhpcert)");
    cmd->add_option("--ca", issue->ca, "the CA key file (rhp-cli ca init)")->required();
    cmd->add_option("--principal", issue->principal, "who it is for (alice@ops)")->required();
    cmd->add_option("--key", issue->key, "the operator's key: an identity file, or `[name] [p256] base64-public-key`")->required();
    cmd->add_flag("--device", issue->device, "certify the identity file's device key (ed25519 or p256) instead of its signing key");
    cmd->add_option("-o,--out", issue->out_path, "certificate file to write (default <principal>.rhpcert)");
    cmd->add_option("--hours", issue->hours, "validity in hours (default 8)");
    cmd->add_option("--max-role", issue->max_role, "the most its scripts may run as: observe, patch or admin (default patch)");
    cmd->add_option("--app", issue->apps, "an app it is good for (repeat; default any)");
    cmd->add_option("--env", issue->envs, "an environment it is good for, dev or prod (repeat; default any, dev from a dev CA)");
    cmd->add_option("--scope", issue->scopes, "a capability pattern (repeat; lib:, cap:, patch:, event:, op:)");
    cmd->add_option("--serial", issue->serial, "its serial (default random)");
    cmd->add_flag("--force", issue->force, "replace an existing file");
    out.emplace_back(cmd, [issue] { return run_cert_issue(*issue); });

    auto show = std::make_shared<cert_show_options>();
    auto* shown = cert->add_subcommand("show", "print an operator certificate (and check it against a trusted-CA file)");
    shown->add_option("file", show->file, "the .rhpcert file")->required();
    shown->add_option("--trusted", show->trusted, "check it against this trusted-CA file now");
    out.emplace_back(shown, [show] { return run_cert_show(*show); });
}

} // namespace rhp_cli

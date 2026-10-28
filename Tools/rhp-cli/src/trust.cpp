// rhp-cli root / revoke-identity / trust: roots of trust (.rhproot), identity revocation lists
// (.rhpidrev) and sending them to a host that serves a release manager (kTrust).
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <memory>
#include <optional>
#include <print>
#include <string>
#include <vector>

#include "commands.hpp"
#include "connection.hpp"
#include "release_files.hpp"

#include <rhp/release/identity_revocations.hpp>
#include <rhp/release/root_of_trust.hpp>

namespace rhp_cli {

namespace {

// Signs `r` with every identity (their signer names must be the root's key ids).
template <class Doc>
bool sign_with(Doc& r, const std::vector<std::string>& identities) {
    for (const std::string& identity : identities) {
        const auto s = load_signer(identity);
        if (!s) {
            return false;
        }
        if (auto ok = Rhp::release::sign(r, s->key); !ok) {
            std::println(stderr, "{}", ok.error());
            return false;
        }
    }
    return true;
}

std::optional<Rhp::release::signed_root> read_root(const std::string& path) {
    auto bytes = read_binary_file(path);
    if (!bytes) {
        std::println(stderr, "can't read {}", path);
        return std::nullopt;
    }
    auto r = Rhp::release::decode_root(*bytes);
    if (!r) {
        std::println(stderr, "{}: {}", path, r.error());
        return std::nullopt;
    }
    return std::move(*r);
}

bool write_root(const Rhp::release::signed_root& r, const std::string& out_path, const Rhp::release::signed_root* previous) {
    auto bytes = Rhp::release::encode_root(r);
    const std::string path = out_path.empty() ? std::format("root.{}.rhproot", r.body.version) : out_path;
    if (!bytes || !write_binary_file(path, *bytes)) {
        std::println(stderr, "can't write {}", path);
        return false;
    }
    std::print("{}", describe(r, previous));
    std::println("wrote {}", path);
    return true;
}

void add_role_options(CLI::App& cmd, root_spec& spec) {
    cmd.add_option("--root-key", spec.root.keys, "a root key: id=base64, id=alg:base64 or an identity file (repeat)");
    cmd.add_option("--root-threshold", spec.root.threshold, "root keys that must sign the next version");
    cmd.add_option("--release-key", spec.release.keys, "a release key, optionally @channel,patterns (repeat)");
    cmd.add_option("--release-threshold", spec.release.threshold, "release keys that must sign a release");
    cmd.add_option("--revocation-key", spec.revocation.keys, "a key that signs revocation lists and identity revocations (repeat)");
    cmd.add_option("--revocation-threshold", spec.revocation.threshold, "revocation keys that must sign");
    cmd.add_option("--operator-ca-key", spec.operator_ca.keys, "an operator certificate authority key (repeat)");
    cmd.add_option("--operator-ca-threshold", spec.operator_ca.threshold, "operator CA keys that must sign");
    cmd.add_option("--expires", spec.expires, "expiry, Unix seconds");
    cmd.add_option("--expires-in", spec.expires_in, "expiry in days from now");
}

struct root_build_options {
    root_spec spec;
    std::string base; // root next: the version it follows
    std::vector<std::string> sign;
    std::string out_path;
};

int run_root_build(const root_build_options& o) {
    std::optional<Rhp::release::signed_root> base;
    if (!o.base.empty()) {
        base = read_root(o.base);
        if (!base) {
            return 1;
        }
    }
    auto doc = build_root(o.spec, base ? &base->body : nullptr, std::chrono::system_clock::now());
    if (!doc) {
        std::println(stderr, "{}", doc.error());
        return 1;
    }
    auto r = Rhp::release::make_root(std::move(*doc));
    if (!r) {
        std::println(stderr, "{}", r.error());
        return 1;
    }
    if (!sign_with(*r, o.sign)) {
        return 1;
    }
    return write_root(*r, o.out_path, base ? &*base : nullptr) ? 0 : 1;
}

struct root_sign_options {
    std::string file;
    std::vector<std::string> sign;
};

int run_root_sign(const root_sign_options& o) {
    auto r = read_root(o.file);
    if (!r || !sign_with(*r, o.sign)) {
        return 1;
    }
    return write_root(*r, o.file, nullptr) ? 0 : 1;
}

struct root_show_options {
    std::string file;
    std::string previous;
};

int run_root_show(const root_show_options& o) {
    const auto r = read_root(o.file);
    if (!r) {
        return 1;
    }
    std::optional<Rhp::release::signed_root> previous;
    if (!o.previous.empty()) {
        previous = read_root(o.previous);
        if (!previous) {
            return 1;
        }
    }
    std::print("{}", describe(*r, previous ? &*previous : nullptr));
    return 0;
}

struct revoke_identity_options {
    identity_revocation_spec spec;
    std::vector<std::string> sign;
    std::string out_path;
};

int run_revoke_identity(const revoke_identity_options& o) {
    auto r = build_identity_revocations(o.spec, std::chrono::system_clock::now());
    if (!r) {
        std::println(stderr, "{}", r.error());
        return 1;
    }
    if (!sign_with(*r, o.sign)) {
        return 1;
    }
    auto bytes = Rhp::release::encode_identity_revocations(*r);
    const std::string path = o.out_path.empty() ? std::format("identities.{}.rhpidrev", r->body.seq) : o.out_path;
    if (!bytes || !write_binary_file(path, *bytes)) {
        std::println(stderr, "can't write {}", path);
        return 1;
    }
    std::print("{}", describe(*r));
    std::println("wrote {}", path);
    return 0;
}

struct trust_push_options {
    std::vector<std::string> files;
    connection_options conn;
};

int run_trust_push(const trust_push_options& o) {
    std::vector<std::vector<std::byte>> documents;
    for (const std::string& file : o.files) {
        auto bytes = read_binary_file(file);
        if (!bytes) {
            std::println(stderr, "can't read {}", file);
            return 1;
        }
        documents.push_back(std::move(*bytes));
    }
    auto c = open_connection(o.conn, nullptr);
    if (!c) {
        return 1;
    }
    auto r = c->client->trust(documents);
    if (!r) {
        std::println(stderr, "{}", r.error());
        return 1;
    }
    std::println("the host holds root of trust version {} and identity revocations {}", r->root_version, r->identity_seq);
    return 0;
}

} // namespace

void add_root(CLI::App& app, command_list& out) {
    auto* root = app.add_subcommand("root", "make, sign and show roots of trust (.rhproot)");
    root->require_subcommand(1);

    auto init = std::make_shared<root_build_options>();
    auto* cmd = root->add_subcommand("init", "make version 1 (the genesis root an app embeds)");
    add_role_options(*cmd, init->spec);
    cmd->add_option("--sign", init->sign, "sign with this identity: its signer name is the key id (repeat)");
    cmd->add_option("-o,--out", init->out_path, "file to write (default root.1.rhproot)");
    out.emplace_back(cmd, [init] { return run_root_build(*init); });

    auto next = std::make_shared<root_build_options>();
    cmd = root->add_subcommand("next", "make version N+1 from version N (sign it with the old and the new root keys)");
    cmd->add_option("file", next->base, "the .rhproot it follows")->required();
    add_role_options(*cmd, next->spec);
    cmd->add_option("--compromise", next->spec.compromise, "mark a key id compromised: what it signed is dropped (repeat)");
    cmd->add_option("--retire", next->spec.retire, "drop a key id from the root; what it signed stays (repeat)");
    cmd->add_option("--sign", next->sign, "sign with this identity (repeat)");
    cmd->add_option("-o,--out", next->out_path, "file to write (default root.<version>.rhproot)");
    out.emplace_back(cmd, [next] { return run_root_build(*next); });

    auto sign = std::make_shared<root_sign_options>();
    cmd = root->add_subcommand("sign", "add signatures to a .rhproot");
    cmd->add_option("file", sign->file, "the .rhproot file")->required();
    cmd->add_option("-i,--identity,--sign", sign->sign, "identity file (repeat)")->required();
    out.emplace_back(cmd, [sign] { return run_root_sign(*sign); });

    auto show = std::make_shared<root_show_options>();
    cmd = root->add_subcommand("show", "describe a .rhproot and check its signatures");
    cmd->add_option("file", show->file, "the .rhproot file")->required();
    cmd->add_option("--previous", show->previous, "also check that it follows this version");
    out.emplace_back(cmd, [show] { return run_root_show(*show); });
}

void add_revoke_identity(CLI::App& app, command_list& out) {
    auto o = std::make_shared<revoke_identity_options>();
    auto* cmd = app.add_subcommand("revoke-identity", "make an identity revocation list (.rhpidrev): certificates, script signers, device keys");
    cmd->add_option("--seq", o->spec.seq, "sequence number, or auto (default: Unix seconds)");
    cmd->add_option("--serial", o->spec.serials, "an operator certificate serial (repeat)");
    cmd->add_option("--signer", o->spec.signers, "a script signer key: base64, alg:base64 or an identity file (repeat)");
    cmd->add_option("--device", o->spec.devices, "a device key: base64, alg:base64 or an identity file (repeat)");
    cmd->add_option("--sign", o->sign, "sign with this identity (a key of the root's revocation role; repeat)");
    cmd->add_option("-o,--out", o->out_path, "file to write (default identities.<seq>.rhpidrev)");
    out.emplace_back(cmd, [o] { return run_revoke_identity(*o); });
}

void add_trust(CLI::App& app, command_list& out) {
    auto* trust = app.add_subcommand("trust", "send roots of trust and identity revocations to a host");
    trust->require_subcommand(1);
    auto o = std::make_shared<trust_push_options>();
    auto* cmd = trust->add_subcommand("push", "send .rhproot / .rhpidrev files (in order) to a host's release manager");
    add_connection_options(*cmd, o->conn, true);
    cmd->add_option("files", o->files, "the files")->required();
    out.emplace_back(cmd, [o] { return run_trust_push(*o); });
}

} // namespace rhp_cli

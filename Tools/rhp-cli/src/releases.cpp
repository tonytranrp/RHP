// rhp-cli release / revoke: building, signing and inspecting .rhprel / .rhprev files, and sending
// them to a host that serves a release manager.
#include <chrono>
#include <cstddef>
#include <format>
#include <memory>
#include <optional>
#include <print>
#include <string>
#include <vector>

#include "commands.hpp"
#include "connection.hpp"
#include "release_files.hpp"
#include "text.hpp"

#include <rhp/core/value.hpp>
#include <rhp/release/release.hpp>
#include <rhp/security/identity_file.hpp>

namespace rhp_cli {

namespace {

// Adds the identity's signature to a release or revocation file (in place).
template <class Doc, class Decode, class Encode>
int sign_file(const std::string& path, const std::string& identity, Decode decode, Encode encode) {
    auto id = Rhp::security::identity_file::load(identity);
    auto bytes = read_binary_file(path);
    if (!id || !bytes) {
        std::println(stderr, "{}", !id ? std::format("{}", id.error()) : std::format("can't read {}", path));
        return 1;
    }
    auto key = id->signer_key();
    if (!key) {
        std::println(stderr, "{} has no signing_key", identity);
        return 1;
    }
    auto doc = decode(*bytes);
    if (!doc) {
        std::println(stderr, "{}", doc.error());
        return 1;
    }
    if (auto signed_ok = Rhp::release::sign(*doc, *key); !signed_ok) {
        std::println(stderr, "{}", signed_ok.error());
        return 1;
    }
    auto out = encode(*doc);
    if (!out || !write_binary_file(path, *out)) {
        std::println(stderr, "can't write {}", path);
        return 1;
    }
    std::println("{}: signed by {} ({} signatures)", path, key->name, doc->signatures.size());
    return 0;
}

// What `release sign` and `revoke sign` take.
struct sign_file_options {
    std::string file;
    std::string identity;
};

void add_sign_file_options(CLI::App& cmd, sign_file_options& o, const char* file_help) {
    cmd.add_option("file", o.file, file_help)->required();
    cmd.add_option("-i,--identity", o.identity, "identity file")->required()->envname("RHP_IDENTITY");
}

// What a subcommand that sends a file to a host takes (`release apply`, `revoke apply`).
struct apply_options {
    std::string file;
    std::string confirm = "now";
    connection_options conn;
};

// ---- release ------------------------------------------------------------------------------------

struct release_build_options {
    release_spec spec;
    std::vector<std::string> sign_with;
    std::string out_path;
};

int run_release_build(const release_build_options& o) {
    auto r = build_release(o.spec, std::chrono::system_clock::now());
    if (!r) {
        std::println(stderr, "{}", r.error());
        return 1;
    }
    for (const std::string& identity : o.sign_with) {
        auto id = Rhp::security::identity_file::load(identity);
        auto key = id ? id->signer_key() : std::nullopt;
        if (!key) {
            std::println(stderr, "{}: no signing key", identity);
            return 1;
        }
        if (auto ok = Rhp::release::sign(*r, *key); !ok) {
            std::println(stderr, "{}", ok.error());
            return 1;
        }
    }
    auto bytes = Rhp::release::encode_release(*r);
    const std::string path = o.out_path.empty() ? std::format("{}.{}.rhprel", r->body.channel, r->body.seq) : o.out_path;
    if (!bytes || !write_binary_file(path, *bytes)) {
        std::println(stderr, "can't write {}", path);
        return 1;
    }
    std::print("{}", describe(*r));
    std::println("wrote {}", path);
    return 0;
}

int run_release_sign(const sign_file_options& o) {
    return sign_file<Rhp::release::release>(
        o.file, o.identity, [](const std::vector<std::byte>& b) { return Rhp::release::decode_release(b); },
        [](const Rhp::release::release& r) { return Rhp::release::encode_release(r); });
}

int run_release_inspect(const std::string& path) {
    auto bytes = read_binary_file(path);
    if (!bytes) {
        std::println(stderr, "can't read {}", path);
        return 1;
    }
    auto release = Rhp::release::decode_release(*bytes);
    if (release) {
        std::print("{}", describe(*release));
        return 0;
    }
    auto revocations = Rhp::release::decode_revocations(*bytes);
    if (revocations) {
        std::print("{}", describe(*revocations));
        return 0;
    }
    // The error of the kind of document the file says it is.
    const bool says_revocations = document_tag(*bytes) == "revocations-envelope";
    std::println(stderr, "{}: {}", path, says_revocations ? revocations.error() : release.error());
    return 1;
}

int run_release_apply(const apply_options& o) {
    auto c = open_connection(o.conn, nullptr);
    if (!c) {
        return 1;
    }
    auto bytes = read_binary_file(o.file);
    if (!bytes) {
        std::println(stderr, "can't read {}", o.file);
        return 1;
    }
    auto r = c->client->release_apply(*bytes, o.confirm);
    if (!r) {
        std::println(stderr, "{}", r.error());
        return 1;
    }
    std::println("{}: {} seq {} ({}{})", r->channel, format_value(Rhp::value{r->id}), r->seq, r->running, r->already ? ", already running" : "");
    return 0;
}

int run_release_status(const connection_options& conn) {
    auto c = open_connection(conn, nullptr);
    if (!c) {
        return 1;
    }
    auto r = c->client->release_status();
    if (!r) {
        std::println(stderr, "{}", r.error());
        return 1;
    }
    std::print("{}", describe(*r));
    return 0;
}

struct channel_options {
    std::string channel;
    bool hold = false;
    connection_options conn;
};

// `release confirm` (confirm) or `release deactivate`.
int run_release_channel(const channel_options& o, bool confirm) {
    auto c = open_connection(o.conn, nullptr);
    if (!c) {
        return 1;
    }
    auto r = confirm ? c->client->release_confirm(o.channel) : c->client->release_deactivate(o.channel, o.hold);
    if (!r) {
        std::println(stderr, "{}", r.error());
        return 1;
    }
    std::println("{}: {}", o.channel, confirm ? "confirmed" : (o.hold ? "deactivated, held" : "deactivated"));
    return 0;
}

// ---- revoke -------------------------------------------------------------------------------------

struct revoke_build_options {
    revocation_spec spec;
    std::vector<std::string> sign_with;
    std::string out_path;
};

int run_revoke_build(const revoke_build_options& o) {
    auto r = build_revocations(o.spec, std::chrono::system_clock::now());
    if (!r) {
        std::println(stderr, "{}", r.error());
        return 1;
    }
    for (const std::string& identity : o.sign_with) {
        auto id = Rhp::security::identity_file::load(identity);
        auto key = id ? id->signer_key() : std::nullopt;
        if (!key) {
            std::println(stderr, "{}: no signing key", identity);
            return 1;
        }
        if (auto ok = Rhp::release::sign(*r, *key); !ok) {
            std::println(stderr, "{}", ok.error());
            return 1;
        }
    }
    auto bytes = Rhp::release::encode_revocations(*r);
    const std::string path = o.out_path.empty() ? std::format("revocations.{}.rhprev", r->body.seq) : o.out_path;
    if (!bytes || !write_binary_file(path, *bytes)) {
        std::println(stderr, "can't write {}", path);
        return 1;
    }
    std::print("{}", describe(*r));
    std::println("wrote {}", path);
    return 0;
}

int run_revoke_sign(const sign_file_options& o) {
    return sign_file<Rhp::release::signed_revocations>(
        o.file, o.identity, [](const std::vector<std::byte>& b) { return Rhp::release::decode_revocations(b); },
        [](const Rhp::release::signed_revocations& r) { return Rhp::release::encode_revocations(r); });
}

int run_revoke_apply(const apply_options& o) {
    auto c = open_connection(o.conn, nullptr);
    if (!c) {
        return 1;
    }
    auto bytes = read_binary_file(o.file);
    if (!bytes) {
        std::println(stderr, "can't read {}", o.file);
        return 1;
    }
    auto r = c->client->revoke(*bytes);
    if (!r) {
        std::println(stderr, "{}", r.error());
        return 1;
    }
    std::println("revocation list applied: {} channel(s) changed", *r);
    return 0;
}

} // namespace

void add_release(CLI::App& app, command_list& out) {
    auto* release = app.add_subcommand("release", "build, sign, inspect and send signed releases (host.serve)");
    release->require_subcommand(1);

    auto build = std::make_shared<release_build_options>();
    auto* cmd = release->add_subcommand("build", "make a .rhprel from Lua modules");
    cmd->add_option("--channel", build->spec.channel, "the channel it fills (game.balance)")->required();
    cmd->add_option("--module", build->spec.modules, "a module: path, or name=path (repeat, in load order)")->required();
    cmd->add_option("--seq", build->spec.seq, "sequence number, or auto (the current Unix time; default)");
    cmd->add_option("--label", build->spec.label, "free text shown in status");
    cmd->add_option("--app", build->spec.app, "only hosts of this app");
    cmd->add_option("--build", build->spec.builds, "only hosts of this build (repeat)");
    cmd->add_option("--platform", build->spec.platforms, "only this platform (repeat): windows, linux, macos, ios, android");
    cmd->add_option("--not-before", build->spec.not_before, "valid from this Unix time");
    cmd->add_option("--not-after", build->spec.not_after, "valid until this Unix time");
    cmd->add_option("--role", build->spec.role, "run as patch (default) or admin");
    cmd->add_option("--lib", build->spec.libs, "a lib the host must have (repeat)");
    cmd->add_option("--fail-event", build->spec.fail_events, "a script event that marks a watched candidate unhealthy (repeat)");
    cmd->add_option("--max-handler-failures", build->spec.max_handler_failures, "handler failures a watched candidate may have");
    cmd->add_option("-i,--identity", build->sign_with, "sign with this identity (repeat for several signers)");
    cmd->add_option("-o,--out", build->out_path, "file to write (default <channel>.<seq>.rhprel)");
    out.emplace_back(cmd, [build] { return run_release_build(*build); });

    auto sign = std::make_shared<sign_file_options>();
    cmd = release->add_subcommand("sign", "add a signature to a .rhprel");
    add_sign_file_options(*cmd, *sign, "the .rhprel file");
    out.emplace_back(cmd, [sign] { return run_release_sign(*sign); });

    auto inspect = std::make_shared<std::string>();
    cmd = release->add_subcommand("inspect", "describe a .rhprel or .rhprev file");
    cmd->add_option("file", *inspect, "the file")->required();
    out.emplace_back(cmd, [inspect] { return run_release_inspect(*inspect); });

    auto apply = std::make_shared<apply_options>();
    cmd = release->add_subcommand("apply", "run a .rhprel on a host (admin)");
    cmd->add_option("file", apply->file, "the .rhprel file")->required();
    cmd->add_option("--confirm", apply->confirm, "now (default), health or manual");
    add_connection_options(*cmd, apply->conn, false);
    out.emplace_back(cmd, [apply] { return run_release_apply(*apply); });

    auto status = std::make_shared<connection_options>();
    cmd = release->add_subcommand("status", "what the host's channels run");
    add_connection_options(*cmd, *status, false);
    out.emplace_back(cmd, [status] { return run_release_status(*status); });

    auto confirm = std::make_shared<channel_options>();
    cmd = release->add_subcommand("confirm", "make a channel's candidate active (admin)");
    cmd->add_option("channel", confirm->channel, "the channel")->required();
    add_connection_options(*cmd, confirm->conn, false);
    out.emplace_back(cmd, [confirm] { return run_release_channel(*confirm, true); });

    auto deactivate = std::make_shared<channel_options>();
    cmd = release->add_subcommand("deactivate", "stop what a channel runs (admin)");
    cmd->add_option("channel", deactivate->channel, "the channel")->required();
    cmd->add_flag("--hold", deactivate->hold, "run nothing until a new release (default: fall back)");
    add_connection_options(*cmd, deactivate->conn, false);
    out.emplace_back(cmd, [deactivate] { return run_release_channel(*deactivate, false); });
}

void add_revoke(CLI::App& app, command_list& out) {
    auto* revoke = app.add_subcommand("revoke", "build, sign and send revocation lists");
    revoke->require_subcommand(1);

    auto build = std::make_shared<revoke_build_options>();
    auto* cmd = revoke->add_subcommand("build", "make a .rhprev (hosts add it to what they revoked already)");
    cmd->add_option("--seq", build->spec.seq, "sequence number, or auto (default: Unix seconds; pass a number to make two in one second)");
    cmd->add_option("--release", build->spec.releases, "a release id to revoke, hex (repeat)");
    cmd->add_option("--key", build->spec.keys, "a signing key to stop trusting, base64 (repeat)");
    cmd->add_option("--floor", build->spec.floors, "channel=seq: revoke that channel's releases up to seq (repeat)");
    cmd->add_option("-i,--identity", build->sign_with, "sign with this identity (repeat)");
    cmd->add_option("-o,--out", build->out_path, "file to write (default revocations.<seq>.rhprev)");
    out.emplace_back(cmd, [build] { return run_revoke_build(*build); });

    auto sign = std::make_shared<sign_file_options>();
    cmd = revoke->add_subcommand("sign", "add a signature to a .rhprev");
    add_sign_file_options(*cmd, *sign, "the .rhprev file");
    out.emplace_back(cmd, [sign] { return run_revoke_sign(*sign); });

    auto apply = std::make_shared<apply_options>();
    cmd = revoke->add_subcommand("apply", "send a .rhprev to a host");
    cmd->add_option("file", apply->file, "the .rhprev file")->required();
    add_connection_options(*cmd, apply->conn, false);
    out.emplace_back(cmd, [apply] { return run_revoke_apply(*apply); });
}

} // namespace rhp_cli

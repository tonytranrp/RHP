// rhp-cli: a REPL and scripting client for RHP hosts.
//
//   rhp-cli keygen dev                                  # dev.rhpid + the lines for the host
//   rhp-cli connect 127.0.0.1:7777 -i dev.rhpid         # REPL
//   rhp-cli run patch.lua -c 127.0.0.1:7777 -i dev.rhpid --pin
//   rhp-cli stubs -c 127.0.0.1:7777 -i dev.rhpid -o rhp_api.lua
//   rhp-cli release build --channel game.balance --module tuning.lua -i dev.rhpid -o balance.rhprel
//   rhp-cli release apply balance.rhprel -c 127.0.0.1:7777 -i admin.rhpid --confirm health
//
// Every script it sends is signed with the identity's Ed25519 key.
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "commands.hpp"
#include "connection.hpp"
#include "dap.hpp"
#include "release_files.hpp"
#include "shell.hpp"
#include "text.hpp"
#include <CLI/CLI.hpp>
#include <replxx.hxx>

#include <rhp/core/json.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/platform/process.hpp>
#include <rhp/rhp.hpp>
#include <rhp/test/cli.hpp>

namespace {

using rhp_cli::cli_cfg;
using cli_shell = rhp_cli::shell<cli_cfg>;
using rhp_cli::add_connection_options;
using rhp_cli::connection_options;
using rhp_cli::open_connection;

std::atomic<bool> g_interrupted{false};

extern "C" void on_interrupt(int) {
    g_interrupted.store(true);
    // The MSVC runtime resets a handler to SIG_DFL before calling it: without this the second
    // Ctrl+C would kill rhp-cli (and the host would revert this session's work).
    std::signal(SIGINT, on_interrupt);
}

[[nodiscard]] std::string home_dir() {
    for (const char* var : {"HOME", "USERPROFILE"}) {
        if (std::string value = Rhp::platform::environment_variable(var); !value.empty()) {
            return value;
        }
    }
    return ".";
}

[[nodiscard]] bool interrupted() {
    return g_interrupted.exchange(false);
}

int repl(const connection_options& o) {
    const bool interactive = Rhp::platform::stdin_is_terminal();
    replxx::Replxx rx;
    auto conn = open_connection(o, interactive ? &rx : nullptr);
    if (!conn) {
        return 1;
    }
    cli_shell sh{*conn->client, [out = conn->out.get()](rhp_cli::style s, std::string_view t) { (*out)(s, t); }, &interrupted};
    if (!interactive) {
        // Scripted input (a pipe or file): one command per line, no line editing.
        std::string line;
        while (std::getline(std::cin, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            if (!sh.feed(line)) {
                break;
            }
        }
        (void)sh.finish();
        return sh.failures() == 0 ? 0 : 1;
    }

    const std::filesystem::path history = std::filesystem::path{home_dir()} / ".rhp" / "history";
    std::error_code ec;
    std::filesystem::create_directories(history.parent_path(), ec);
    rx.install_window_change_handler();
    rx.set_max_history_size(1000);
    rx.set_unique_history(true);
    rx.history_load(history.string());
    rx.set_word_break_characters(" \t\n\"\\'`@$><=;|&{(,");
    rx.set_completion_callback([&sh](const std::string& input, int& context) {
        std::size_t start = input.find_last_of(" \t\n\"\\'`@$><=;|&{(,");
        start = start == std::string::npos ? 0 : start + 1;
        const std::string prefix = input.substr(start);
        context = static_cast<int>(prefix.size());
        replxx::Replxx::completions_t out;
        for (const std::string& name : sh.complete(prefix)) {
            out.emplace_back(name);
        }
        return out;
    });
    (*conn->out)(rhp_cli::style::kInfo, "type `help` for commands, `quit` to leave (Ctrl+C cancels a running script)");
    while (true) {
        g_interrupted.store(false);
        const char* input = rx.input(sh.continuing() ? "...> " : "rhp> ");
        if (input == nullptr) {
            if (errno == EAGAIN) { // Ctrl+C at the prompt: drop the line (and unfinished multi-line Lua)
                if (sh.continuing()) {
                    sh.reset();
                    (*conn->out)(rhp_cli::style::kInfo, "(multi-line input dropped)");
                }
                continue;
            }
            break; // Ctrl+D / end of input
        }
        const std::string line{input};
        if (!line.empty()) {
            rx.history_add(line);
        }
        if (!sh.feed(line)) {
            break;
        }
    }
    rx.history_save(history.string());
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    CLI::App app{"rhp-cli: talk to RHP hosts (REPL, scripts, keys)"};
    app.require_subcommand(1);

    std::string name;
    std::string out_path;
    std::string role_text = "admin";
    bool force = false;
    auto* keygen_cmd = app.add_subcommand("keygen", "create an identity file (PSK + Ed25519 signing key)");
    keygen_cmd->add_option("name", name, "the key name the host will know")->required();
    keygen_cmd->add_option("-o,--out", out_path, "identity file to write (default <name>.rhpid)");
    keygen_cmd->add_option("--role", role_text, "role printed in the keyring line (observe, patch, admin)");
    keygen_cmd->add_flag("--force", force, "replace an existing file");

    std::string identity;
    auto* pubkey_cmd = app.add_subcommand("pubkey", "print the host's keyring and signers lines for an identity");
    pubkey_cmd->add_option("-i,--identity", identity, "identity file")->required()->envname("RHP_IDENTITY");
    pubkey_cmd->add_option("--role", role_text, "role for the keyring line");

    std::string file;
    auto* sign_cmd = app.add_subcommand("sign", "print the signature of a script (`signer base64`)");
    sign_cmd->add_option("file", file, "the .lua file")->required();
    sign_cmd->add_option("-i,--identity", identity, "identity file")->required()->envname("RHP_IDENTITY");

    connection_options conn;
    Rhp::net::browse_options discovery;
    int discover_ms = 1500;
    const auto add_discovery_options = [&](CLI::App& cmd) {
        cmd.add_option("--app", discovery.app, "discover this application only");
        cmd.add_option("--build", discovery.build, "discover this build only");
        cmd.add_option("--platform", discovery.platform, "discover this platform only");
        cmd.add_option("--wait", discover_ms, "milliseconds to browse DNS-SD")->check(CLI::Range(1, 60000));
    };
    auto* discover_cmd = app.add_subcommand("discover", "find explicitly advertised RHP hosts via DNS-SD");
    add_discovery_options(*discover_cmd);
    auto* fleet_cmd = app.add_subcommand("fleet", "discover hosts and broadcast a signed Lua file, collecting every result");
    int broadcast_timeout_ms = 10000;
    fleet_cmd->add_option("file", file, "Lua source file")->required();
    fleet_cmd->add_option("-i,--identity", identity, "identity file")->required()->envname("RHP_IDENTITY");
    add_discovery_options(*fleet_cmd);
    fleet_cmd->add_option("--timeout", broadcast_timeout_ms, "broadcast deadline in milliseconds (default 10000)")->check(CLI::Range(1, 3600000));
    fleet_cmd->add_flag("--tls", conn.tls, "TLS even on loopback");
    fleet_cmd->add_flag("--insecure-lan", conn.insecure_lan, "allow plaintext to non-loopback endpoints");
    fleet_cmd->add_option("--ca", conn.ca, "validate host certificates against this CA (PEM)");
    fleet_cmd->add_option("--server-name", conn.server_name, "expected certificate name (with --ca)");
    auto* connect_cmd = app.add_subcommand("connect", "interactive REPL (reads commands from stdin when it isn't a terminal)");
    add_connection_options(*connect_cmd, conn, true);

    bool pin = false;
    std::string module;
    auto* run_cmd = app.add_subcommand("run", "run a .lua file (exec), or load it as a module with --pin / --name");
    run_cmd->add_option("file", file, "the .lua file")->required();
    run_cmd->add_flag("--pin", pin, "load as a module and pin it: it stays after rhp-cli exits (admin)");
    run_cmd->add_option("--name", module, "load as this module (default with --pin: the file name)");
    add_connection_options(*run_cmd, conn, false);

    std::string code;
    auto* exec_cmd = app.add_subcommand("exec", "run one Lua chunk and print what it returns");
    exec_cmd->add_option("code", code, "Lua source")->required();
    add_connection_options(*exec_cmd, conn, false);

    auto* stubs_cmd = app.add_subcommand("stubs", "fetch LuaLS annotations for everything your role can use");
    stubs_cmd->add_option("-o,--out", out_path, "file to write (default: print)");
    add_connection_options(*stubs_cmd, conn, false);

    std::string sink;
    auto* blob_cmd = app.add_subcommand("blob", "push a file to a host blob sink");
    blob_cmd->add_option("sink", sink, "the sink's name")->required();
    blob_cmd->add_option("file", file, "the file")->required();
    blob_cmd->add_option("--name", module, "name passed to the sink (default: the file name)");
    add_connection_options(*blob_cmd, conn, false);

    std::vector<std::string> event_names;
    auto* events_cmd = app.add_subcommand("events", "print host events (C++ events, or rhp.publish of your identity; * = all) until Ctrl+C");
    events_cmd->add_option("event", event_names, "event names")->required();
    add_connection_options(*events_cmd, conn, false);

    std::string folder;
    auto* watch_cmd = app.add_subcommand("watch", "reload <folder>/*.lua whenever one is saved (Ctrl+C stops)");
    watch_cmd->add_option("folder", folder, "folder to watch")->required();
    add_connection_options(*watch_cmd, conn, false);

    // ---- releases ---------------------------------------------------------------------------------
    auto* release_cmd = app.add_subcommand("release", "build, sign, inspect and send signed releases (host.serve)");
    release_cmd->require_subcommand(1);
    rhp_cli::release_spec spec;
    std::vector<std::string> sign_with;
    auto* rbuild_cmd = release_cmd->add_subcommand("build", "make a .rhprel from Lua modules");
    rbuild_cmd->add_option("--channel", spec.channel, "the channel it fills (game.balance)")->required();
    rbuild_cmd->add_option("--module", spec.modules, "a module: path, or name=path (repeat, in load order)")->required();
    rbuild_cmd->add_option("--seq", spec.seq, "sequence number, or auto (the current Unix time; default)");
    rbuild_cmd->add_option("--label", spec.label, "free text shown in status");
    rbuild_cmd->add_option("--app", spec.app, "only hosts of this app");
    rbuild_cmd->add_option("--build", spec.builds, "only hosts of this build (repeat)");
    rbuild_cmd->add_option("--platform", spec.platforms, "only this platform (repeat): windows, linux, macos, ios, android");
    rbuild_cmd->add_option("--not-before", spec.not_before, "valid from this Unix time");
    rbuild_cmd->add_option("--not-after", spec.not_after, "valid until this Unix time");
    rbuild_cmd->add_option("--role", spec.role, "run as patch (default) or admin");
    rbuild_cmd->add_option("--lib", spec.libs, "a lib the host must have (repeat)");
    rbuild_cmd->add_option("--fail-event", spec.fail_events, "a script event that marks a watched candidate unhealthy (repeat)");
    rbuild_cmd->add_option("--max-handler-failures", spec.max_handler_failures, "handler failures a watched candidate may have");
    rbuild_cmd->add_option("-i,--identity", sign_with, "sign with this identity (repeat for several signers)");
    rbuild_cmd->add_option("-o,--out", out_path, "file to write (default <channel>.<seq>.rhprel)");
    auto* rsign_cmd = release_cmd->add_subcommand("sign", "add a signature to a .rhprel");
    rsign_cmd->add_option("file", file, "the .rhprel file")->required();
    rsign_cmd->add_option("-i,--identity", identity, "identity file")->required()->envname("RHP_IDENTITY");
    auto* rinspect_cmd = release_cmd->add_subcommand("inspect", "describe a .rhprel or .rhprev file");
    rinspect_cmd->add_option("file", file, "the file")->required();
    std::string confirm = "now";
    auto* rapply_cmd = release_cmd->add_subcommand("apply", "run a .rhprel on a host (admin)");
    rapply_cmd->add_option("file", file, "the .rhprel file")->required();
    rapply_cmd->add_option("--confirm", confirm, "now (default), health or manual");
    add_connection_options(*rapply_cmd, conn, false);
    auto* rstatus_cmd = release_cmd->add_subcommand("status", "what the host's channels run");
    add_connection_options(*rstatus_cmd, conn, false);
    std::string channel;
    bool hold = false;
    auto* rconfirm_cmd = release_cmd->add_subcommand("confirm", "make a channel's candidate active (admin)");
    rconfirm_cmd->add_option("channel", channel, "the channel")->required();
    add_connection_options(*rconfirm_cmd, conn, false);
    auto* rdeactivate_cmd = release_cmd->add_subcommand("deactivate", "stop what a channel runs (admin)");
    rdeactivate_cmd->add_option("channel", channel, "the channel")->required();
    rdeactivate_cmd->add_flag("--hold", hold, "run nothing until a new release (default: fall back)");
    add_connection_options(*rdeactivate_cmd, conn, false);

    std::vector<std::string> rollout_hosts;
    std::vector<std::string> canaries;
    std::vector<std::string> stage_specs;
    std::size_t max_failures = 0;
    bool keep_on_failure = false;
    auto* rollout_cmd = app.add_subcommand("rollout", "spread a .rhprel over hosts stage by stage (canaries, then fractions)");
    rollout_cmd->add_option("file", file, "the .rhprel file")->required();
    rollout_cmd->add_option("-i,--identity", identity, "admin identity file")->required()->envname("RHP_IDENTITY");
    rollout_cmd->add_option("--host", rollout_hosts, "host:port (repeat); without any, hosts are discovered");
    rollout_cmd->add_option("--canary", canaries, "a host (its name, or host:port with --host) that goes first (repeat)");
    rollout_cmd->add_option("--stage", stage_specs, "fraction:observe_ms, cumulative (default 0.1:30000 0.5:30000 1:0)");
    rollout_cmd->add_option("--max-failures", max_failures, "hosts that may fail before the rollout stops");
    rollout_cmd->add_flag("--keep-on-failure", keep_on_failure, "don't deactivate the release where it went when the rollout stops");
    add_discovery_options(*rollout_cmd);
    rollout_cmd->add_flag("--tls", conn.tls, "TLS even on loopback");
    rollout_cmd->add_option("--ca", conn.ca, "validate host certificates against this CA (PEM)");
    rollout_cmd->add_option("--server-name", conn.server_name, "expected certificate name (with --ca)");
    rollout_cmd->add_flag("--insecure-lan", conn.insecure_lan, "allow plaintext to non-loopback endpoints");

    std::string tune_path;
    std::string tune_value;
    auto* tune_cmd = app.add_subcommand("tune", "list the host's variables and their tags (tunables), or set one");
    tune_cmd->add_option("path", tune_path, "a lib or a variable (lists what starts with it)");
    tune_cmd->add_option("value", tune_value, "set the variable to this (a Lua literal: 2.5, true, \"text\")");
    add_connection_options(*tune_cmd, conn, false);

    double profile_seconds = 5;
    std::uint32_t profile_interval = 1000;
    std::string profile_out;
    auto* profile_cmd = app.add_subcommand("profile", "sample your identity's scripts for a while, print where they spend instructions");
    profile_cmd->add_option("--seconds", profile_seconds, "how long to sample (default 5)");
    profile_cmd->add_option("--interval", profile_interval, "instructions per sample (default 1000, at least 100)");
    profile_cmd->add_option("-o,--out", profile_out, "also write the folded stacks (flamegraph.pl, speedscope)");
    add_connection_options(*profile_cmd, conn, false);

    std::string dap_root;
    auto* dap_cmd = app.add_subcommand("dap", "a Debug Adapter Protocol server on stdin / stdout, for editors");
    dap_cmd->add_option("--root", dap_root, "the folder module sources are in (<root>/game/combat.lua is module game.combat)");
    add_connection_options(*dap_cmd, conn, false);

    auto* revoke_cmd = app.add_subcommand("revoke", "build, sign and send revocation lists");
    revoke_cmd->require_subcommand(1);
    rhp_cli::revocation_spec revocations;
    auto* vbuild_cmd = revoke_cmd->add_subcommand("build", "make a .rhprev (hosts add it to what they revoked already)");
    vbuild_cmd->add_option("--seq", revocations.seq, "sequence number, or auto (default: Unix seconds; pass a number to make two in one second)");
    vbuild_cmd->add_option("--release", revocations.releases, "a release id to revoke, hex (repeat)");
    vbuild_cmd->add_option("--key", revocations.keys, "a signing key to stop trusting, base64 (repeat)");
    vbuild_cmd->add_option("--floor", revocations.floors, "channel=seq: revoke that channel's releases up to seq (repeat)");
    vbuild_cmd->add_option("-i,--identity", sign_with, "sign with this identity (repeat)");
    vbuild_cmd->add_option("-o,--out", out_path, "file to write (default revocations.<seq>.rhprev)");
    auto* vsign_cmd = revoke_cmd->add_subcommand("sign", "add a signature to a .rhprev");
    vsign_cmd->add_option("file", file, "the .rhprev file")->required();
    vsign_cmd->add_option("-i,--identity", identity, "identity file")->required()->envname("RHP_IDENTITY");
    auto* vapply_cmd = revoke_cmd->add_subcommand("apply", "send a .rhprev to a host");
    vapply_cmd->add_option("file", file, "the .rhprev file")->required();
    add_connection_options(*vapply_cmd, conn, false);

    auto* test_cmd = app.add_subcommand("test", "run Lua test files offline (`rhp-cli test --help`; --exe runs a program's own test executable)");
    test_cmd->prefix_command(); // everything after `test` belongs to the test runner
    test_cmd->set_help_flag();

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        // Prints the help text or the usage error; usage errors exit 2 like the rest of rhp-cli.
        return app.exit(e) == 0 ? 0 : 2;
    }
    if (test_cmd->parsed()) {
        return rhp_cli::test_command(test_cmd->remaining());
    }
    std::signal(SIGINT, on_interrupt);

    if (keygen_cmd->parsed()) {
        return rhp_cli::keygen(name, out_path, role_text, force);
    }
    if (pubkey_cmd->parsed()) {
        return rhp_cli::pubkey(identity, role_text);
    }
    if (sign_cmd->parsed()) {
        return rhp_cli::sign(file, identity);
    }
    if (rbuild_cmd->parsed()) {
        return rhp_cli::release_build(spec, sign_with, out_path);
    }
    if (rsign_cmd->parsed()) {
        return rhp_cli::release_sign(file, identity);
    }
    if (rinspect_cmd->parsed()) {
        return rhp_cli::inspect(file);
    }
    if (vbuild_cmd->parsed()) {
        return rhp_cli::revoke_build(revocations, sign_with, out_path);
    }
    if (vsign_cmd->parsed()) {
        return rhp_cli::revoke_sign(file, identity);
    }
    discovery.duration = std::chrono::milliseconds{discover_ms};
    discovery.protocol_revision = Rhp::wire::kProtocolRevision;
    if (discover_cmd->parsed()) {
        auto records = Rhp::discover<cli_cfg>(discovery);
        if (!records) {
            std::println(stderr, "{}", records.error());
            return 1;
        }
        for (const auto& host : *records) {
            std::println("{} {}:{} {} {} {} {}", host.name, host.address, host.port, host.platform, host.app, host.build, host.transport);
        }
        return 0;
    }
    if (fleet_cmd->parsed()) {
        auto id = Rhp::security::identity_file::load(identity);
        auto source = rhp_cli::read_text_file(file);
        if (!id) {
            std::println(stderr, "{}", id.error());
            return 1;
        }
        if (!source) {
            std::println(stderr, "can't read fleet source {}", file);
            return 1;
        }
        auto signer = id->signer_key();
        if (!signer) {
            std::println(stderr, "fleet requires an identity with a signing key");
            return 1;
        }
        Rhp::fleet_options options;
        options.timeout = std::chrono::milliseconds{broadcast_timeout_ms};
        options.insecure_lan = conn.insecure_lan;
        options.tls = conn.tls ? Rhp::net::tls_mode::kRequire : Rhp::net::tls_mode::kAuto;
        options.client.tls.server_name = conn.server_name;
        if (!conn.ca.empty()) {
            auto ca = rhp_cli::read_text_file(conn.ca);
            if (!ca) {
                std::println(stderr, "can't read fleet CA {}", conn.ca);
                return 1;
            }
            options.client.tls.ca_pem = std::move(*ca);
        }
        Rhp::fleet<cli_cfg> group{id->credential(), std::move(*signer), std::move(options)};
        auto discovered = group.discover(discovery);
        if (!discovered) {
            std::println(stderr, "{}", discovered.error());
            return 1;
        }
        if (group.size() == 0) {
            std::println(stderr, "no compatible fleet hosts discovered");
            return 1;
        }
        bool ok = true;
        for (const auto& entry : group.exec(*source)) {
            if (entry.outcome) {
                std::println("{}: {}", entry.host.name, rhp_cli::format_value(Rhp::value{*entry.outcome}));
            } else {
                std::println(stderr, "{}: {}", entry.host.name, entry.outcome.error());
                ok = false;
            }
        }
        return ok ? 0 : 1;
    }
    if (rollout_cmd->parsed()) {
        auto id = Rhp::security::identity_file::load(identity);
        auto bytes = rhp_cli::read_binary_file(file);
        if (!id || !bytes) {
            std::println(stderr, "{}", !id ? std::format("{}", id.error()) : std::format("can't read {}", file));
            return 1;
        }
        auto signer = id->signer_key();
        Rhp::fleet_options options;
        options.insecure_lan = conn.insecure_lan;
        options.tls = conn.tls ? Rhp::net::tls_mode::kRequire : Rhp::net::tls_mode::kAuto;
        options.client.tls.server_name = conn.server_name;
        if (!conn.ca.empty()) {
            auto ca = rhp_cli::read_text_file(conn.ca);
            if (!ca) {
                std::println(stderr, "can't read rollout CA {}", conn.ca);
                return 1;
            }
            options.client.tls.ca_pem = std::move(*ca);
        }
        auto group = signer ? std::make_unique<Rhp::fleet<cli_cfg>>(id->credential(), std::move(*signer), std::move(options))
                            : std::make_unique<Rhp::fleet<cli_cfg>>(id->credential(), std::move(options));
        if (rollout_hosts.empty()) {
            if (auto found = group->discover(discovery); !found) {
                std::println(stderr, "{}", found.error());
                return 1;
            }
        }
        for (const std::string& h : rollout_hosts) {
            auto ep = rhp_cli::parse_endpoint(h, false, conn.insecure_lan);
            if (!ep) {
                std::println(stderr, "{}: {}", h, ep.error().message);
                return 2;
            }
            Rhp::net::service_record r;
            r.name = h;
            r.address = ep->host;
            r.port = ep->port;
            r.protocol_revision = Rhp::wire::kProtocolRevision;
            if (auto added = group->add(std::move(r)); !added) {
                std::println(stderr, "{}: {}", h, added.error());
                return 1;
            }
        }
        if (group->size() == 0) {
            std::println(stderr, "no hosts to roll out to");
            return 1;
        }
        Rhp::rollout_plan plan;
        plan.canaries = canaries;
        plan.max_failures = max_failures;
        plan.rollback_on_failure = !keep_on_failure;
        if (!stage_specs.empty()) {
            plan.stages.clear();
            for (const std::string& stage_spec : stage_specs) {
                const auto stage = rhp_cli::parse_stage(stage_spec);
                if (!stage) {
                    std::println(stderr, "--stage is fraction:observe_ms with a fraction in [0, 1] (got '{}')", stage_spec);
                    return 2;
                }
                plan.stages.push_back(*stage);
            }
        }
        plan.on_progress = [](std::string_view line) { std::println("{}", line); };
        const auto report = group->rollout(*bytes, plan);
        for (const auto& h : report.hosts) {
            std::println("  {:<24} {}{}", h.host.name, Rhp::to_string(h.status), h.err ? std::format(" ({})", h.err->message) : std::string{});
        }
        if (!report.completed) {
            std::println(stderr, "rollout of {} to {} did not complete: {}", report.release.substr(0, 8), report.channel, report.err ? report.err->message : "?");
            return 1;
        }
        std::println("rolled out {} to {} on {} host(s)", report.release.substr(0, 8), report.channel, report.hosts.size());
        return 0;
    }
    if (connect_cmd->parsed()) {
        return repl(conn);
    }

    if (dap_cmd->parsed()) {
        Rhp::platform::binary_stdio(); // byte-counted messages: no newline translation
        auto dc = open_connection(conn, nullptr, true);
        if (!dc) {
            return 1;
        }
        std::mutex write_mutex;
        rhp_cli::dap_server<cli_cfg> server{*dc->client, dap_root, [&](std::string_view bytes) {
                                                const std::scoped_lock lock{write_mutex};
                                                std::fwrite(bytes.data(), 1, bytes.size(), stdout);
                                                std::fflush(stdout);
                                            }};
        return server.run([] { return rhp_cli::read_dap_message(stdin); });
    }

    auto c = open_connection(conn, nullptr);
    if (!c) {
        return 1;
    }
    cli_shell sh{*c->client, [out = c->out.get()](rhp_cli::style s, std::string_view t) { (*out)(s, t); }, &interrupted};
    bool ok = true;
    if (run_cmd->parsed()) {
        if (pin || !module.empty()) {
            ok = sh.load_file(module.empty() ? rhp_cli::module_name_for(file) : module, file, false, pin);
            if (ok && !pin) {
                (*c->out)(rhp_cli::style::kInfo, "not pinned: the module is reverted when rhp-cli exits (add --pin to keep it)");
            }
        } else if (const auto source = rhp_cli::read_text_file(file)) {
            ok = sh.exec(*source);
        } else {
            std::println(stderr, "can't read {}", file);
            ok = false;
        }
    } else if (exec_cmd->parsed()) {
        ok = sh.exec(code);
    } else if (stubs_cmd->parsed()) {
        ok = sh.stubs(out_path);
    } else if (blob_cmd->parsed()) {
        ok = sh.send_blob(sink, file, module);
    } else if (watch_cmd->parsed()) {
        if (!sh.watch(folder)) {
            return 1;
        }
        while (!g_interrupted.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
        }
        sh.unwatch();
    } else if (rapply_cmd->parsed() || vapply_cmd->parsed()) {
        auto bytes = rhp_cli::read_binary_file(file);
        if (!bytes) {
            std::println(stderr, "can't read {}", file);
            return 1;
        }
        if (rapply_cmd->parsed()) {
            auto r = c->client->release_apply(*bytes, confirm);
            if (!r) {
                std::println(stderr, "{}", r.error());
                return 1;
            }
            std::println("{}: {} seq {} ({}{})", r->channel, rhp_cli::format_value(Rhp::value{r->id}), r->seq, r->running, r->already ? ", already running" : "");
        } else {
            auto r = c->client->revoke(*bytes);
            if (!r) {
                std::println(stderr, "{}", r.error());
                return 1;
            }
            std::println("revocation list applied: {} channel(s) changed", *r);
        }
    } else if (rstatus_cmd->parsed()) {
        auto r = c->client->release_status();
        if (!r) {
            std::println(stderr, "{}", r.error());
            return 1;
        }
        std::print("{}", rhp_cli::describe(*r));
    } else if (rconfirm_cmd->parsed() || rdeactivate_cmd->parsed()) {
        auto r = rconfirm_cmd->parsed() ? c->client->release_confirm(channel) : c->client->release_deactivate(channel, hold);
        if (!r) {
            std::println(stderr, "{}", r.error());
            return 1;
        }
        std::println("{}: {}", channel, rconfirm_cmd->parsed() ? "confirmed" : (hold ? "deactivated, held" : "deactivated"));
    } else if (tune_cmd->parsed()) {
        ok = tune_value.empty() ? sh.tunables(tune_path) : sh.tune(tune_path, rhp_cli::parse_literal(tune_value));
    } else if (profile_cmd->parsed()) {
        if (!sh.profile("start", std::to_string(profile_interval))) {
            return 1;
        }
        const auto until = std::chrono::steady_clock::now() + std::chrono::duration<double>{profile_seconds};
        while (std::chrono::steady_clock::now() < until && !g_interrupted.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds{50});
        }
        ok = sh.profile("stop", profile_out);
    } else if (events_cmd->parsed()) {
        for (const std::string& event : event_names) {
            if (!sh.subscribe(event)) {
                return 1;
            }
        }
        while (!g_interrupted.load() && !c->client->info().closed) {
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
        }
        sh.unsubscribe_all();
    }
    return ok ? 0 : 1;
}

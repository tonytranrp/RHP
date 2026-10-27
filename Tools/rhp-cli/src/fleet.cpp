// rhp-cli discover / fleet / rollout: hosts found through DNS-SD (or listed), one signed script on
// all of them, a release spread over them stage by stage.
#include <chrono>
#include <cstddef>
#include <format>
#include <memory>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "commands.hpp"
#include "release_files.hpp"
#include "shell.hpp"
#include "text.hpp"

#include <rhp/rhp.hpp>

namespace rhp_cli {

namespace {

// The DNS-SD filters and browse time discover, fleet and rollout share.
struct discovery_options {
    Rhp::net::browse_options browse;
    int wait_ms = 1500;

    [[nodiscard]] Rhp::net::browse_options to_browse() const {
        Rhp::net::browse_options out = browse;
        out.duration = std::chrono::milliseconds{wait_ms};
        out.protocol_revision = Rhp::wire::kProtocolRevision;
        return out;
    }
};

void add_discovery_options(CLI::App& cmd, discovery_options& o) {
    cmd.add_option("--app", o.browse.app, "discover this application only");
    cmd.add_option("--build", o.browse.build, "discover this build only");
    cmd.add_option("--platform", o.browse.platform, "discover this platform only");
    cmd.add_option("--wait", o.wait_ms, "milliseconds to browse DNS-SD")->check(CLI::Range(1, 60000));
}

int run_discover(const discovery_options& o) {
    auto records = Rhp::discover<cli_cfg>(o.to_browse());
    if (!records) {
        std::println(stderr, "{}", records.error());
        return 1;
    }
    for (const auto& host : *records) {
        std::println("{} {}:{} {} {} {} {}", host.name, host.address, host.port, host.platform, host.app, host.build, host.transport);
    }
    return 0;
}

// The TLS choices fleet and rollout take (the hosts' addresses come from discovery or --host).
struct fleet_tls_options {
    bool tls = false;
    bool insecure_lan = false;
    std::string ca;
    std::string server_name;
};

void add_fleet_tls_options(CLI::App& cmd, fleet_tls_options& o) {
    cmd.add_flag("--tls", o.tls, "TLS even on loopback");
    cmd.add_flag("--insecure-lan", o.insecure_lan, "allow plaintext to non-loopback endpoints");
    cmd.add_option("--ca", o.ca, "validate host certificates against this CA (PEM)");
    cmd.add_option("--server-name", o.server_name, "expected certificate name (with --ca)");
}

// The fleet's options for o; nullopt (after saying so) when the CA file can't be read.
[[nodiscard]] std::optional<Rhp::fleet_options> fleet_options_from(const fleet_tls_options& o, std::string_view command) {
    Rhp::fleet_options options;
    options.insecure_lan = o.insecure_lan;
    options.tls = o.tls ? Rhp::net::tls_mode::kRequire : Rhp::net::tls_mode::kAuto;
    options.client.tls.server_name = o.server_name;
    if (!o.ca.empty()) {
        auto ca = read_text_file(o.ca);
        if (!ca) {
            std::println(stderr, "can't read {} CA {}", command, o.ca);
            return std::nullopt;
        }
        options.client.tls.ca_pem = std::move(*ca);
    }
    return options;
}

struct broadcast_options {
    std::string file;
    std::string identity;
    discovery_options discovery;
    int timeout_ms = 10000;
    fleet_tls_options tls;
};

int run_fleet(const broadcast_options& o) {
    auto id = Rhp::security::identity_file::load(o.identity);
    auto source = read_text_file(o.file);
    if (!id) {
        std::println(stderr, "{}", id.error());
        return 1;
    }
    if (!source) {
        std::println(stderr, "can't read fleet source {}", o.file);
        return 1;
    }
    auto signer = id->signer_key();
    if (!signer) {
        std::println(stderr, "fleet requires an identity with a signing key");
        return 1;
    }
    auto options = fleet_options_from(o.tls, "fleet");
    if (!options) {
        return 1;
    }
    options->timeout = std::chrono::milliseconds{o.timeout_ms};
    Rhp::fleet<cli_cfg> group{id->credential(), std::move(*signer), std::move(*options)};
    auto discovered = group.discover(o.discovery.to_browse());
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
            std::println("{}: {}", entry.host.name, format_value(Rhp::value{*entry.outcome}));
        } else {
            std::println(stderr, "{}: {}", entry.host.name, entry.outcome.error());
            ok = false;
        }
    }
    return ok ? 0 : 1;
}

struct rollout_options {
    std::string file;
    std::string identity;
    std::vector<std::string> hosts;
    std::vector<std::string> canaries;
    std::vector<std::string> stages;
    std::size_t max_failures = 0;
    bool keep_on_failure = false;
    discovery_options discovery;
    fleet_tls_options tls;
};

int run_rollout(const rollout_options& o) {
    auto id = Rhp::security::identity_file::load(o.identity);
    auto bytes = read_binary_file(o.file);
    if (!id || !bytes) {
        std::println(stderr, "{}", !id ? std::format("{}", id.error()) : std::format("can't read {}", o.file));
        return 1;
    }
    auto signer = id->signer_key();
    auto options = fleet_options_from(o.tls, "rollout");
    if (!options) {
        return 1;
    }
    auto group = signer ? std::make_unique<Rhp::fleet<cli_cfg>>(id->credential(), std::move(*signer), std::move(*options))
                        : std::make_unique<Rhp::fleet<cli_cfg>>(id->credential(), std::move(*options));
    if (o.hosts.empty()) {
        if (auto found = group->discover(o.discovery.to_browse()); !found) {
            std::println(stderr, "{}", found.error());
            return 1;
        }
    }
    for (const std::string& h : o.hosts) {
        auto ep = parse_endpoint(h, false, o.tls.insecure_lan);
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
    plan.canaries = o.canaries;
    plan.max_failures = o.max_failures;
    plan.rollback_on_failure = !o.keep_on_failure;
    if (!o.stages.empty()) {
        plan.stages.clear();
        for (const std::string& stage_spec : o.stages) {
            const auto stage = parse_stage(stage_spec);
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

} // namespace

void add_discover(CLI::App& app, command_list& out) {
    auto o = std::make_shared<discovery_options>();
    auto* cmd = app.add_subcommand("discover", "find explicitly advertised RHP hosts via DNS-SD");
    add_discovery_options(*cmd, *o);
    out.emplace_back(cmd, [o] { return run_discover(*o); });
}

void add_fleet(CLI::App& app, command_list& out) {
    auto o = std::make_shared<broadcast_options>();
    auto* cmd = app.add_subcommand("fleet", "discover hosts and broadcast a signed Lua file, collecting every result");
    cmd->add_option("file", o->file, "Lua source file")->required();
    cmd->add_option("-i,--identity", o->identity, "identity file")->required()->envname("RHP_IDENTITY");
    add_discovery_options(*cmd, o->discovery);
    cmd->add_option("--timeout", o->timeout_ms, "broadcast deadline in milliseconds (default 10000)")->check(CLI::Range(1, 3600000));
    add_fleet_tls_options(*cmd, o->tls);
    out.emplace_back(cmd, [o] { return run_fleet(*o); });
}

void add_rollout(CLI::App& app, command_list& out) {
    auto o = std::make_shared<rollout_options>();
    auto* cmd = app.add_subcommand("rollout", "spread a .rhprel over hosts stage by stage (canaries, then fractions)");
    cmd->add_option("file", o->file, "the .rhprel file")->required();
    cmd->add_option("-i,--identity", o->identity, "admin identity file")->required()->envname("RHP_IDENTITY");
    cmd->add_option("--host", o->hosts, "host:port (repeat); without any, hosts are discovered");
    cmd->add_option("--canary", o->canaries, "a host (its name, or host:port with --host) that goes first (repeat)");
    cmd->add_option("--stage", o->stages, "fraction:observe_ms, cumulative (default 0.1:30000 0.5:30000 1:0)");
    cmd->add_option("--max-failures", o->max_failures, "hosts that may fail before the rollout stops");
    cmd->add_flag("--keep-on-failure", o->keep_on_failure, "don't deactivate the release where it went when the rollout stops");
    add_discovery_options(*cmd, o->discovery);
    add_fleet_tls_options(*cmd, o->tls);
    out.emplace_back(cmd, [o] { return run_rollout(*o); });
}

} // namespace rhp_cli

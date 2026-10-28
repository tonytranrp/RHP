#include "connection.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <format>
#include <memory>
#include <mutex>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

#include "dev.hpp"
#include "text.hpp"
#include <CLI/CLI.hpp>
#include <replxx.hxx>

#include <rhp/platform/files.hpp>
#include <rhp/platform/process.hpp>
#include <rhp/rhp.hpp>
#include <rhp/security/certified.hpp>
#include <rhp/security/dev_session.hpp>
#include <rhp/security/operator_cert.hpp>

namespace rhp_cli {

void terminal::operator()(style s, std::string_view text) {
    const char* open = "";
    const char* close = "";
    if (color_) {
        switch (s) {
        case style::kPlain: break;
        case style::kOutput: open = "\x1b[36m"; break;
        case style::kInfo: open = "\x1b[2m"; break;
        case style::kError: open = "\x1b[31m"; break;
        }
        close = *open != '\0' ? "\x1b[0m" : "";
    }
    const std::string line = std::format("{}{}{}\n", open, text, close);
    const std::scoped_lock lock{mutex_};
    if (rx_ != nullptr) {
        rx_->write(line.data(), static_cast<int>(line.size()));
    } else if (s == style::kError || to_stderr_) {
        std::fputs(line.c_str(), stderr);
    } else {
        std::fputs(line.c_str(), stdout);
        std::fflush(stdout);
    }
}

void add_connection_options(CLI::App& cmd, connection_options& o, bool positional_address, bool required) {
    CLI::Option* address = positional_address ? cmd.add_option("address", o.address, "host:port of the host (or where to listen with --listen)")
                                              : cmd.add_option("-c,--connect", o.address, "host:port of the host (or where to listen with --listen)");
    CLI::Option* identity = cmd.add_option("-i,--identity", o.identity, "identity file (rhp-cli keygen)")->envname("RHP_IDENTITY");
    address->required(required);
    identity->required(required);
    cmd.add_flag("--insecure-lan", o.insecure_lan, "plaintext to a non-loopback address (no TLS)");
    cmd.add_flag("--tls", o.tls, "TLS even on loopback (non-loopback addresses always use it)");
    cmd.add_option("--ca", o.ca, "check the host's certificate against this CA (PEM); default: not checked, the handshake is bound to the TLS channel");
    cmd.add_option("--server-name", o.server_name, "the name the host's certificate must carry (with --ca)");
    cmd.add_option("--cert", o.cert, "with --listen: this side's certificate chain (PEM); default: ephemeral self-signed");
    cmd.add_option("--key", o.key, "with --listen: the certificate's private key (PEM)");
    cmd.add_option("--cert-file", o.cert_file, "sign scripts with this operator certificate (.rhpcert, rhp-cli cert issue) and the identity's signing key");
    cmd.add_option("--claim-app", o.claim_app, "with --cert-file: the app the scripts are for (default: any)");
    cmd.add_option("--claim-env", o.claim_env, "with --cert-file: the host environment they are for, dev or prod (default: any)");
    cmd.add_option("--claim-audience", o.claim_audience, "with --cert-file: the host id they are for (host_options::host_id; default: any)");
    cmd.add_flag("--listen", o.listen, "reverse mode: listen at the address and wait for the host to dial in");
    cmd.add_option("--timeout", o.timeout_ms, "ms to wait for the session (default 10000, 600000 with --listen)");
}

namespace {

std::unique_ptr<terminal> make_terminal(replxx::Replxx* rx, bool to_stderr) {
    // Colors only where the terminal shows them (a classic Windows console needs them turned on).
    const bool color = !to_stderr && Rhp::platform::stdout_is_terminal() && Rhp::platform::environment_variable("NO_COLOR").empty() && Rhp::platform::enable_ansi_colors();
    return std::make_unique<terminal>(rx, color, to_stderr);
}

void print_warnings(const Rhp::security::identity_file& id, terminal* out) {
    for (const std::string& warning : id.warnings) {
        if (out != nullptr) {
            (*out)(style::kError, "warning: " + warning);
        } else {
            std::println(stderr, "warning: {}", warning);
        }
    }
}

// Makes the client, connects and says to whom.
template <class Cfg>
std::optional<connection<Cfg>> start(const Rhp::endpoint& ep, const Rhp::security::identity_file& id, Rhp::client_options options, std::unique_ptr<terminal> out,
                                     std::optional<typename Cfg::signing_key_t> signer) {
    terminal* sink = out.get();
    options.on_output = [sink](std::uint64_t, std::string_view line) { (*sink)(style::kOutput, line); };
    options.on_emit = [sink](std::uint64_t, Rhp::module_id, const Rhp::value& v) { (*sink)(style::kOutput, "emit " + format_value(v)); };
    auto c = signer ? std::make_unique<Rhp::client<Cfg>>(ep, id.credential(), std::move(*signer), options) : std::make_unique<Rhp::client<Cfg>>(ep, id.credential(), options);
    if (!signer) {
        (*out)(style::kInfo, "this identity has no signing_key: only observe hosts will run its scripts");
    }
    if (ep.direction == Rhp::endpoint::mode::kListen) {
        auto port = c->port();
        if (!port) {
            (*out)(style::kError, std::format("{}", port.error()));
            return std::nullopt;
        }
        (*out)(style::kInfo, std::format("listening on {}:{}; waiting for the host to dial in...", ep.host, *port));
    }
    if (auto ok = c->connect(); !ok) {
        (*out)(style::kError, std::format("{}", ok.error()));
        return std::nullopt;
    }
    const auto who = c->info();
    (*out)(style::kInfo, std::format("connected as {} ({}) to a {} host{}", who.identity, who.granted, who.host_platform, who.tls ? " over TLS" : ""));
    return connection<Cfg>{std::move(c), std::move(out)};
}

} // namespace

std::optional<connected> open_connection(const connection_options& o, replxx::Replxx* rx, bool to_stderr) {
    auto out = make_terminal(rx, to_stderr);
    auto id = load_identity(o.identity, out.get());
    if (!id) {
        return std::nullopt;
    }
    auto ep = parse_endpoint(o.address, o.listen, o.insecure_lan);
    if (!ep) {
        (*out)(style::kError, ep.error().message);
        return std::nullopt;
    }
    if (o.tls) {
        ep->tls = Rhp::net::tls_mode::kRequire;
    }
    Rhp::client_options options;
    options.connect_timeout = std::chrono::milliseconds{o.timeout_ms > 0 ? o.timeout_ms : (o.listen ? 600'000 : 10'000)};
    for (const auto& [path, field] : {std::pair{&o.ca, &options.tls.ca_pem}, std::pair{&o.cert, &options.tls.cert_pem}, std::pair{&o.key, &options.tls.key_pem}}) {
        if (path->empty()) {
            continue;
        }
        auto pem = read_text_file(*path);
        if (!pem) {
            (*out)(style::kError, std::format("can't read {}", *path));
            return std::nullopt;
        }
        *field = std::move(*pem);
    }
    options.tls.server_name = o.server_name;
    std::optional<cli_cfg::signing_key_t> signer;
    if (!o.cert_file.empty()) {
        auto cert = Rhp::security::load_operator_cert(o.cert_file);
        if (!cert) {
            (*out)(style::kError, std::format("{}", cert.error()));
            return std::nullopt;
        }
        if (!id->signing || !std::ranges::equal(id->signing->public_key().bytes(), cert->fields.pub)) {
            (*out)(style::kError, std::format("certificate {} names another key than {}'s signing_key", cert->id(), o.identity));
            return std::nullopt;
        }
        options.app = o.claim_app;
        options.env = o.claim_env;
        options.audience = o.claim_audience;
        (*out)(style::kInfo, std::format("signing as {} (max role {})", cert->id(), cert->fields.max_role));
        signer.emplace(Rhp::security::certified::key{*id->signing, std::move(*cert)});
    } else if (auto key = id->signer_key()) {
        signer.emplace(std::move(*key));
    }
    return start<cli_cfg>(*ep, *id, std::move(options), std::move(out), std::move(signer));
}

std::optional<dev_connected> open_dev_connection(std::string_view app, int timeout_ms, replxx::Replxx* rx) {
    auto out = make_terminal(rx, false);
    auto dir = Rhp::security::dev_session_directory();
    auto path = dir ? pick_dev_session(*dir, app) : Rhp::result<std::filesystem::path>{std::unexpected{dir.error()}};
    auto session = path ? Rhp::security::read_dev_session(*path) : Rhp::result<Rhp::security::dev_session>{std::unexpected{path.error()}};
    if (!session) {
        (*out)(style::kError, std::format("{}", session.error()));
        return std::nullopt;
    }
    print_warnings(session->identity, out.get());
    auto target = dev_endpoint(*session);
    if (!target) {
        (*out)(style::kError, std::format("{}", target.error()));
        return std::nullopt;
    }
    (*out)(style::kInfo, std::format("dev session of {} at {}", session->app, session->endpoint()));
    Rhp::client_options options;
    options.connect_timeout = std::chrono::milliseconds{timeout_ms > 0 ? timeout_ms : 10'000};
    if (target->ipc) {
        auto c = start<cli_ipc_cfg>(target->ep, session->identity, std::move(options), std::move(out), session->identity.signer_key());
        return c ? std::optional<dev_connected>{std::move(*c)} : std::nullopt;
    }
    auto key = session->identity.signer_key();
    auto c = start<cli_cfg>(target->ep, session->identity, std::move(options), std::move(out),
                            key ? std::optional<cli_cfg::signing_key_t>{std::move(*key)} : std::nullopt);
    return c ? std::optional<dev_connected>{std::move(*c)} : std::nullopt;
}

std::optional<Rhp::security::identity_file> load_identity(const std::string& path, terminal* out) {
    auto id = Rhp::security::identity_file::load(path);
    if (!id) {
        if (out != nullptr) {
            (*out)(style::kError, std::format("{}", id.error()));
        } else {
            std::println(stderr, "{}", id.error());
        }
        return std::nullopt;
    }
    print_warnings(*id, out);
    return std::move(*id);
}

std::optional<signer> load_signer(const std::string& path) {
    auto id = load_identity(path);
    if (!id) {
        return std::nullopt;
    }
    auto key = id->signer_key();
    if (!key) {
        std::println(stderr, "{} has no signing_key", path);
        return std::nullopt;
    }
    return signer{std::move(*id), std::move(*key)};
}

} // namespace rhp_cli

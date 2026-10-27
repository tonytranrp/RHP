#include "connection.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <format>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "text.hpp"
#include <CLI/CLI.hpp>
#include <replxx.hxx>

#include <rhp/platform/files.hpp>
#include <rhp/platform/process.hpp>
#include <rhp/rhp.hpp>

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

void add_connection_options(CLI::App& cmd, connection_options& o, bool positional_address) {
    if (positional_address) {
        cmd.add_option("address", o.address, "host:port of the host (or where to listen with --listen)")->required();
    } else {
        cmd.add_option("-c,--connect", o.address, "host:port of the host (or where to listen with --listen)")->required();
    }
    cmd.add_option("-i,--identity", o.identity, "identity file (rhp-cli keygen)")->required()->envname("RHP_IDENTITY");
    cmd.add_flag("--insecure-lan", o.insecure_lan, "plaintext to a non-loopback address (no TLS)");
    cmd.add_flag("--tls", o.tls, "TLS even on loopback (non-loopback addresses always use it)");
    cmd.add_option("--ca", o.ca, "check the host's certificate against this CA (PEM); default: not checked, the handshake is bound to the TLS channel");
    cmd.add_option("--server-name", o.server_name, "the name the host's certificate must carry (with --ca)");
    cmd.add_option("--cert", o.cert, "with --listen: this side's certificate chain (PEM); default: ephemeral self-signed");
    cmd.add_option("--key", o.key, "with --listen: the certificate's private key (PEM)");
    cmd.add_flag("--listen", o.listen, "reverse mode: listen at the address and wait for the host to dial in");
    cmd.add_option("--timeout", o.timeout_ms, "ms to wait for the session (default 10000, 600000 with --listen)");
}

std::optional<connected> open_connection(const connection_options& o, replxx::Replxx* rx, bool to_stderr) {
    auto out = std::make_unique<terminal>(rx, !to_stderr && Rhp::platform::stdout_is_terminal() && Rhp::platform::environment_variable("NO_COLOR").empty(), to_stderr);
    auto id = Rhp::security::identity_file::load(o.identity);
    if (!id) {
        (*out)(style::kError, std::format("{}", id.error()));
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
    terminal* sink = out.get();
    options.on_output = [sink](std::uint64_t, std::string_view line) { (*sink)(style::kOutput, line); };
    options.on_emit = [sink](std::uint64_t, Rhp::module_id, const Rhp::value& v) { (*sink)(style::kOutput, "emit " + format_value(v)); };
    auto signer = id->signer_key();
    auto c = signer ? std::make_unique<Rhp::client<cli_cfg>>(*ep, id->credential(), std::move(*signer), options)
                    : std::make_unique<Rhp::client<cli_cfg>>(*ep, id->credential(), options);
    if (!signer) {
        (*out)(style::kInfo, "this identity has no signing_key: only observe hosts will run its scripts");
    }
    if (o.listen) {
        auto port = c->port();
        if (!port) {
            (*out)(style::kError, std::format("{}", port.error()));
            return std::nullopt;
        }
        (*out)(style::kInfo, std::format("listening on {}:{}; waiting for the host to dial in...", ep->host, *port));
    }
    if (auto ok = c->connect(); !ok) {
        (*out)(style::kError, std::format("{}", ok.error()));
        return std::nullopt;
    }
    const auto who = c->info();
    (*out)(style::kInfo, std::format("connected as {} ({}) to a {} host{}", who.identity, who.granted, who.host_platform, who.tls ? " over TLS" : ""));
    return connected{std::move(c), std::move(out)};
}

} // namespace rhp_cli

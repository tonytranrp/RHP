// rhp-cli: a REPL and scripting client for RHP hosts.
//
//   rhp-cli keygen dev                                  # dev.rhpid + the lines for the host
//   rhp-cli connect 127.0.0.1:7777 -i dev.rhpid         # REPL
//   rhp-cli run patch.lua -c 127.0.0.1:7777 -i dev.rhpid --pin
//   rhp-cli stubs -c 127.0.0.1:7777 -i dev.rhpid -o rhp_api.lua
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
#include <iterator>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

#include "shell.hpp"
#include "text.hpp"
#include <CLI/CLI.hpp>
#include <replxx.hxx>

#include <rhp/rhp.hpp>

namespace {

using cli_cfg = Rhp::config<>::logger<Rhp::core::null_logger>;
using cli_shell = rhp_cli::shell<cli_cfg>;

std::atomic<bool> g_interrupted{false};

extern "C" void on_interrupt(int) {
    g_interrupted.store(true);
    // The MSVC runtime resets a handler to SIG_DFL before calling it: without this the second
    // Ctrl+C would kill rhp-cli (and the host would revert this session's work).
    std::signal(SIGINT, on_interrupt);
}

[[nodiscard]] bool stdout_is_terminal() {
#if defined(_WIN32)
    return _isatty(_fileno(stdout)) != 0;
#else
    return isatty(fileno(stdout)) != 0;
#endif
}

[[nodiscard]] bool stdin_is_terminal() {
#if defined(_WIN32)
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(fileno(stdin)) != 0;
#endif
}

// An environment variable's value ("" when unset).
[[nodiscard]] std::string env(const char* name) {
#if defined(_MSC_VER)
    char* value = nullptr;
    std::size_t length = 0;
    if (_dupenv_s(&value, &length, name) != 0 || value == nullptr) {
        return {};
    }
    std::string out{value};
    std::free(value);
    return out;
#else
    const char* value = std::getenv(name);
    return value != nullptr ? std::string{value} : std::string{};
#endif
}

[[nodiscard]] std::string home_dir() {
    for (const char* var : {"HOME", "USERPROFILE"}) {
        if (std::string value = env(var); !value.empty()) {
            return value;
        }
    }
    return ".";
}

// Writes shell output: colored through replxx in the REPL, plain lines otherwise. Thread-safe.
class terminal {
public:
    explicit terminal(replxx::Replxx* rx, bool color) : rx_(rx), color_(color) {}

    void operator()(rhp_cli::style s, std::string_view text) {
        const char* open = "";
        const char* close = "";
        if (color_) {
            switch (s) {
            case rhp_cli::style::kPlain: break;
            case rhp_cli::style::kOutput: open = "\x1b[36m"; break;
            case rhp_cli::style::kInfo: open = "\x1b[2m"; break;
            case rhp_cli::style::kError: open = "\x1b[31m"; break;
            }
            close = *open != '\0' ? "\x1b[0m" : "";
        }
        const std::string line = std::format("{}{}{}\n", open, text, close);
        const std::scoped_lock lock{mutex_};
        if (rx_ != nullptr) {
            rx_->write(line.data(), static_cast<int>(line.size()));
        } else if (s == rhp_cli::style::kError) {
            std::fputs(line.c_str(), stderr);
        } else {
            std::fputs(line.c_str(), stdout);
            std::fflush(stdout);
        }
    }

private:
    replxx::Replxx* rx_;
    bool color_;
    std::mutex mutex_;
};

struct connection_options {
    std::string address;
    std::string identity;
    bool insecure_lan = false;
    bool listen = false;
    bool tls = false;
    std::string ca;
    std::string server_name;
    std::string cert;
    std::string key;
    int timeout_ms = 0; // 0: 10 s when dialing, 10 min when listening
};

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

// The connection a network command works over.
struct connected {
    std::unique_ptr<Rhp::client<cli_cfg>> client;
    std::unique_ptr<terminal> out;
};

[[nodiscard]] std::optional<connected> open(const connection_options& o, replxx::Replxx* rx) {
    auto out = std::make_unique<terminal>(rx, stdout_is_terminal() && env("NO_COLOR").empty());
    auto id = Rhp::security::identity_file::load(o.identity);
    if (!id) {
        (*out)(rhp_cli::style::kError, std::format("{}", id.error()));
        return std::nullopt;
    }
    auto ep = rhp_cli::parse_endpoint(o.address, o.listen, o.insecure_lan);
    if (!ep) {
        (*out)(rhp_cli::style::kError, ep.error().message);
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
        std::ifstream in{*path, std::ios::binary};
        if (!in) {
            (*out)(rhp_cli::style::kError, std::format("can't read {}", *path));
            return std::nullopt;
        }
        *field = std::string{std::istreambuf_iterator<char>{in}, {}};
    }
    options.tls.server_name = o.server_name;
    terminal* sink = out.get();
    options.on_output = [sink](std::uint64_t, std::string_view line) { (*sink)(rhp_cli::style::kOutput, line); };
    options.on_emit = [sink](std::uint64_t, Rhp::module_id, const Rhp::value& v) { (*sink)(rhp_cli::style::kOutput, "emit " + rhp_cli::format_value(v)); };
    auto signer = id->signer_key();
    auto c = signer ? std::make_unique<Rhp::client<cli_cfg>>(*ep, id->credential(), std::move(*signer), options)
                    : std::make_unique<Rhp::client<cli_cfg>>(*ep, id->credential(), options);
    if (!signer) {
        (*out)(rhp_cli::style::kInfo, "this identity has no signing_key: only observe hosts will run its scripts");
    }
    if (o.listen) {
        auto port = c->port();
        if (!port) {
            (*out)(rhp_cli::style::kError, std::format("{}", port.error()));
            return std::nullopt;
        }
        (*out)(rhp_cli::style::kInfo, std::format("listening on {}:{}; waiting for the host to dial in...", ep->host, *port));
    }
    if (auto ok = c->connect(); !ok) {
        (*out)(rhp_cli::style::kError, std::format("{}", ok.error()));
        return std::nullopt;
    }
    const auto who = c->info();
    (*out)(rhp_cli::style::kInfo, std::format("connected as {} ({}) to a {} host{}", who.identity, who.granted, who.host_platform, who.tls ? " over TLS" : ""));
    return connected{std::move(c), std::move(out)};
}

[[nodiscard]] bool interrupted() {
    return g_interrupted.exchange(false);
}

int repl(const connection_options& o) {
    const bool interactive = stdin_is_terminal();
    replxx::Replxx rx;
    auto conn = open(o, interactive ? &rx : nullptr);
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

int keygen(const std::string& name, const std::string& out_path, const std::string& role_text, bool force) {
    const auto granted = Rhp::parse_role(role_text);
    if (!granted) {
        std::println(stderr, "unknown role '{}' (observe, patch or admin)", role_text);
        return 2;
    }
    const std::string path = out_path.empty() ? name + ".rhpid" : out_path;
    std::error_code ec;
    if (!force && std::filesystem::exists(path, ec)) {
        std::println(stderr, "{} exists (use --force to replace it)", path);
        return 1;
    }
    auto id = Rhp::security::identity_file::generate(name);
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

int pubkey(const std::string& identity, const std::string& role_text) {
    const auto granted = Rhp::parse_role(role_text);
    auto id = Rhp::security::identity_file::load(identity);
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

int sign(const std::string& file, const std::string& identity) {
    auto id = Rhp::security::identity_file::load(identity);
    if (!id) {
        std::println(stderr, "{}", id.error());
        return 1;
    }
    auto key = id->signer_key();
    if (!key) {
        std::println(stderr, "{} has no signing_key", identity);
        return 1;
    }
    const auto source = rhp_cli::read_text_file(file);
    if (!source) {
        std::println(stderr, "can't read {}", file);
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

    CLI11_PARSE(app, argc, argv);
    std::signal(SIGINT, on_interrupt);

    if (keygen_cmd->parsed()) {
        return keygen(name, out_path, role_text, force);
    }
    if (pubkey_cmd->parsed()) {
        return pubkey(identity, role_text);
    }
    if (sign_cmd->parsed()) {
        return sign(file, identity);
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
    if (connect_cmd->parsed()) {
        return repl(conn);
    }

    auto c = open(conn, nullptr);
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

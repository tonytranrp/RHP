// rhp-cli: a REPL and scripting client for RHP hosts.
//
//   rhp-cli keygen dev                                  # dev.rhpid + the lines for the host
//   rhp-cli connect 127.0.0.1:7777 -i dev.rhpid         # REPL
//   rhp-cli connect --dev                               # REPL on a program's dev session
//   rhp-cli run patch.lua -c 127.0.0.1:7777 -i dev.rhpid --pin
//   rhp-cli stubs -c 127.0.0.1:7777 -i dev.rhpid -o rhp_api.lua
//   rhp-cli release build --channel game.balance --module tuning.lua -i dev.rhpid -o balance.rhprel
//   rhp-cli release apply balance.rhprel -c 127.0.0.1:7777 -i admin.rhpid --confirm health
//
// Every script it sends is signed with the identity's Ed25519 key. This file holds the REPL and the
// subcommands that work through the command shell (one instantiation of rhp_cli::shell), and runs
// the subcommand given; the others are in keys.cpp, fleet.cpp, releases.cpp and test_command.cpp.
#include <atomic>
#include <cerrno>
#include <chrono>
#include <concepts>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <print>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <variant>
#include <vector>

#include "commands.hpp"
#include "connection.hpp"
#include "dap.hpp"
#include "shell.hpp"
#include "text.hpp"
#include <CLI/CLI.hpp>
#include <replxx.hxx>

#include <rhp/platform/files.hpp>
#include <rhp/platform/process.hpp>

namespace {

using rhp_cli::cli_cfg;
using cli_shell = rhp_cli::shell<cli_cfg>;
using rhp_cli::command_list;
using rhp_cli::connection_options;

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

// ---- connect: the REPL ---------------------------------------------------------------------------

// The REPL over one connection (TCP, or a dev session's local IPC).
template <class Cfg>
int run_repl(rhp_cli::connection<Cfg>& conn, replxx::Replxx& rx, bool interactive) {
    rhp_cli::shell<Cfg> sh{*conn.client, [out = conn.out.get()](rhp_cli::style s, std::string_view t) { (*out)(s, t); }, &interrupted};
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
    (*conn.out)(rhp_cli::style::kInfo, "type `help` for commands, `quit` to leave (Ctrl+C cancels a running script)");
    while (true) {
        g_interrupted.store(false);
        const char* input = rx.input(sh.continuing() ? "...> " : "rhp> ");
        if (input == nullptr) {
            if (errno == EAGAIN) { // Ctrl+C at the prompt: drop the line (and unfinished multi-line Lua)
                if (sh.continuing()) {
                    sh.reset();
                    (*conn.out)(rhp_cli::style::kInfo, "(multi-line input dropped)");
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

struct connect_options {
    connection_options conn;
    std::string dev_app;
};

int run_connect(const connect_options& o, bool dev) {
    const bool interactive = Rhp::platform::stdin_is_terminal();
    replxx::Replxx rx;
    if (dev) {
        if (!o.conn.address.empty()) {
            std::println(stderr, "--dev reads the address and the identity from the dev session file");
            return 2;
        }
        auto conn = rhp_cli::open_dev_connection(o.dev_app, o.conn.timeout_ms, interactive ? &rx : nullptr);
        return conn ? std::visit([&](auto& c) { return run_repl(c, rx, interactive); }, *conn) : 1;
    }
    if (o.conn.address.empty() || o.conn.identity.empty()) {
        std::println(stderr, "connect needs the host's address and -i/--identity (or --dev)");
        return 2;
    }
    auto conn = rhp_cli::open_connection(o.conn, interactive ? &rx : nullptr);
    return conn ? run_repl(*conn, rx, interactive) : 1;
}

void add_connect(CLI::App& app, command_list& out) {
    auto o = std::make_shared<connect_options>();
    auto* cmd = app.add_subcommand("connect", "interactive REPL (reads commands from stdin when it isn't a terminal)");
    rhp_cli::add_connection_options(*cmd, o->conn, true, false);
    auto* dev = cmd->add_option("--dev", o->dev_app, "connect to a dev session of a program on this machine (its file in the user config folder; the app, when there are several)")
                    ->expected(0, 1);
    out.emplace_back(cmd, [o, dev] { return run_connect(*o, dev->count() > 0); });
}

// ---- subcommands that run one shell command -----------------------------------------------------

// Connects and runs `body` with a shell over the connection: its exit status, 1 when the connection fails.
template <std::invocable<cli_shell&, rhp_cli::connected&> Body>
int with_shell(const connection_options& conn, Body body) {
    auto c = rhp_cli::open_connection(conn, nullptr);
    if (!c) {
        return 1;
    }
    cli_shell sh{*c->client, [out = c->out.get()](rhp_cli::style s, std::string_view t) { (*out)(s, t); }, &interrupted};
    return body(sh, *c);
}

// Adds a subcommand with connection options (-c/--connect, -i/--identity, ...) after its own.
template <class Options, std::invocable<CLI::App&, Options&> Add, std::invocable<const Options&> Run>
void add_session_command(CLI::App& app, command_list& out, const char* name, const char* help, Add add, Run run) {
    auto o = std::make_shared<Options>();
    auto* cmd = app.add_subcommand(name, help);
    add(*cmd, *o);
    rhp_cli::add_connection_options(*cmd, o->conn, false);
    out.emplace_back(cmd, [o, run] { return run(*o); });
}

struct run_options {
    std::string file;
    bool pin = false;
    std::string module;
    connection_options conn;
};

int run_run(const run_options& o) {
    return with_shell(o.conn, [&](cli_shell& sh, rhp_cli::connected& c) {
        bool ok = true;
        if (o.pin || !o.module.empty()) {
            ok = sh.load_file(o.module.empty() ? rhp_cli::module_name_for(o.file) : o.module, o.file, false, o.pin);
            if (ok && !o.pin) {
                (*c.out)(rhp_cli::style::kInfo, "not pinned: the module is reverted when rhp-cli exits (add --pin to keep it)");
            }
        } else if (const auto source = rhp_cli::read_text_file(o.file)) {
            ok = sh.exec(*source);
        } else {
            std::println(stderr, "can't read {}", o.file);
            ok = false;
        }
        return ok ? 0 : 1;
    });
}

struct exec_options {
    std::string code;
    connection_options conn;
};

struct stubs_options {
    std::string out_path;
    connection_options conn;
};

struct blob_options {
    std::string sink;
    std::string file;
    std::string name;
    connection_options conn;
};

struct events_options {
    std::vector<std::string> names;
    connection_options conn;
};

int run_events(const events_options& o) {
    return with_shell(o.conn, [&](cli_shell& sh, rhp_cli::connected& c) {
        for (const std::string& event : o.names) {
            if (!sh.subscribe(event)) {
                return 1;
            }
        }
        while (!g_interrupted.load() && !c.client->info().closed) {
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
        }
        sh.unsubscribe_all();
        return 0;
    });
}

struct watch_options {
    std::string folder;
    connection_options conn;
};

int run_watch(const watch_options& o) {
    return with_shell(o.conn, [&](cli_shell& sh, rhp_cli::connected& c) {
        if (!sh.watch(o.folder)) {
            return 1;
        }
        // Until Ctrl+C, or the session ends (like events: a closed session reloads nothing more).
        while (!g_interrupted.load() && !c.client->info().closed) {
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
        }
        sh.unwatch();
        return 0;
    });
}

struct tune_options {
    std::string path;
    std::string value;
    connection_options conn;
};

struct profile_options {
    double seconds = 5;
    std::uint32_t interval = 1000;
    std::string out_path;
    connection_options conn;
};

int run_profile(const profile_options& o) {
    return with_shell(o.conn, [&](cli_shell& sh, rhp_cli::connected&) {
        if (!sh.profile("start", std::to_string(o.interval))) {
            return 1;
        }
        const auto until = std::chrono::steady_clock::now() + std::chrono::duration<double>{o.seconds};
        while (std::chrono::steady_clock::now() < until && !g_interrupted.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds{50});
        }
        return sh.profile("stop", o.out_path) ? 0 : 1;
    });
}

struct dap_options {
    std::string root;
    connection_options conn;
};

int run_dap(const dap_options& o) {
    Rhp::platform::binary_stdio(); // byte-counted messages: no newline translation
    auto dc = rhp_cli::open_connection(o.conn, nullptr, true);
    if (!dc) {
        return 1;
    }
    std::mutex write_mutex;
    rhp_cli::dap_server<cli_cfg> server{*dc->client, o.root, [&](std::string_view bytes) {
                                            const std::scoped_lock lock{write_mutex};
                                            std::fwrite(bytes.data(), 1, bytes.size(), stdout);
                                            std::fflush(stdout);
                                        }};
    return server.run([] { return rhp_cli::read_dap_message(stdin); });
}

void add_run(CLI::App& app, command_list& out) {
    add_session_command<run_options>(
        app, out, "run", "run a .lua file (exec), or load it as a module with --pin / --name",
        [](CLI::App& cmd, run_options& o) {
            cmd.add_option("file", o.file, "the .lua file")->required();
            cmd.add_flag("--pin", o.pin, "load as a module and pin it: it stays after rhp-cli exits (admin)");
            cmd.add_option("--name", o.module, "load as this module (default with --pin: the file name)");
        },
        run_run);
}

void add_exec(CLI::App& app, command_list& out) {
    add_session_command<exec_options>(
        app, out, "exec", "run one Lua chunk and print what it returns", [](CLI::App& cmd, exec_options& o) { cmd.add_option("code", o.code, "Lua source")->required(); },
        [](const exec_options& o) { return with_shell(o.conn, [&](cli_shell& sh, rhp_cli::connected&) { return sh.exec(o.code) ? 0 : 1; }); });
}

void add_stubs(CLI::App& app, command_list& out) {
    add_session_command<stubs_options>(
        app, out, "stubs", "fetch LuaLS annotations for everything your role can use",
        [](CLI::App& cmd, stubs_options& o) { cmd.add_option("-o,--out", o.out_path, "file to write (default: print)"); },
        [](const stubs_options& o) { return with_shell(o.conn, [&](cli_shell& sh, rhp_cli::connected&) { return sh.stubs(o.out_path) ? 0 : 1; }); });
}

void add_blob(CLI::App& app, command_list& out) {
    add_session_command<blob_options>(
        app, out, "blob", "push a file to a host blob sink",
        [](CLI::App& cmd, blob_options& o) {
            cmd.add_option("sink", o.sink, "the sink's name")->required();
            cmd.add_option("file", o.file, "the file")->required();
            cmd.add_option("--name", o.name, "name passed to the sink (default: the file name)");
        },
        [](const blob_options& o) { return with_shell(o.conn, [&](cli_shell& sh, rhp_cli::connected&) { return sh.send_blob(o.sink, o.file, o.name) ? 0 : 1; }); });
}

void add_events(CLI::App& app, command_list& out) {
    add_session_command<events_options>(
        app, out, "events", "print host events (C++ events, or rhp.publish of your identity; * = all) until Ctrl+C",
        [](CLI::App& cmd, events_options& o) { cmd.add_option("event", o.names, "event names")->required(); }, run_events);
}

void add_watch(CLI::App& app, command_list& out) {
    add_session_command<watch_options>(
        app, out, "watch", "reload <folder>/*.lua whenever one is saved (Ctrl+C stops)",
        [](CLI::App& cmd, watch_options& o) { cmd.add_option("folder", o.folder, "folder to watch")->required(); }, run_watch);
}

void add_tune(CLI::App& app, command_list& out) {
    add_session_command<tune_options>(
        app, out, "tune", "list the host's variables and their tags (tunables), or set one",
        [](CLI::App& cmd, tune_options& o) {
            cmd.add_option("path", o.path, "a lib or a variable (lists what starts with it)");
            cmd.add_option("value", o.value, "set the variable to this (a Lua literal: 2.5, true, \"text\")");
        },
        [](const tune_options& o) {
            return with_shell(o.conn, [&](cli_shell& sh, rhp_cli::connected&) {
                return (o.value.empty() ? sh.tunables(o.path) : sh.tune(o.path, rhp_cli::parse_literal(o.value))) ? 0 : 1;
            });
        });
}

void add_profile(CLI::App& app, command_list& out) {
    add_session_command<profile_options>(
        app, out, "profile", "sample your identity's scripts for a while, print where they spend instructions",
        [](CLI::App& cmd, profile_options& o) {
            cmd.add_option("--seconds", o.seconds, "how long to sample (default 5)");
            cmd.add_option("--interval", o.interval, "instructions per sample (default 1000, at least 100)");
            cmd.add_option("-o,--out", o.out_path, "also write the folded stacks (flamegraph.pl, speedscope)");
        },
        run_profile);
}

void add_dap(CLI::App& app, command_list& out) {
    add_session_command<dap_options>(
        app, out, "dap", "a Debug Adapter Protocol server on stdin / stdout, for editors",
        [](CLI::App& cmd, dap_options& o) { cmd.add_option("--root", o.root, "the folder module sources are in (<root>/game/combat.lua is module game.combat)"); },
        run_dap);
}

} // namespace

int main(int argc, char** argv) {
    CLI::App app{"rhp-cli: talk to RHP hosts (REPL, scripts, keys)"};
    app.require_subcommand(1);

    // In the order `rhp-cli --help` lists them.
    command_list commands;
    rhp_cli::add_keygen(app, commands);
    rhp_cli::add_pubkey(app, commands);
    rhp_cli::add_sign(app, commands);
    rhp_cli::add_ca(app, commands);
    rhp_cli::add_cert(app, commands);
    rhp_cli::add_discover(app, commands);
    rhp_cli::add_fleet(app, commands);
    add_connect(app, commands);
    add_run(app, commands);
    add_exec(app, commands);
    add_stubs(app, commands);
    add_blob(app, commands);
    add_events(app, commands);
    add_watch(app, commands);
    rhp_cli::add_release(app, commands);
    rhp_cli::add_rollout(app, commands);
    add_tune(app, commands);
    add_profile(app, commands);
    add_dap(app, commands);
    rhp_cli::add_revoke(app, commands);
    rhp_cli::add_test(app, commands);

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        // Prints the help text or the usage error; usage errors exit 2 like the rest of rhp-cli.
        return app.exit(e) == 0 ? 0 : 2;
    }
    for (const rhp_cli::command& c : commands) {
        if (c.cli->parsed()) {
            if (c.catches_interrupt) {
                std::signal(SIGINT, on_interrupt);
            }
            return c.run();
        }
    }
    return 2; // unreachable: CLI11 requires one subcommand (and one under release / revoke)
}

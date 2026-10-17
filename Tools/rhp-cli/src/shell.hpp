#pragma once

#include <atomic>
#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "text.hpp"

#include <rhp/client/client.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/errors_mode.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>

namespace rhp_cli {

// How a line of output should look (the terminal front-end colors them).
enum class style : std::uint8_t {
    kPlain,  // command results
    kOutput, // print() lines from scripts
    kInfo,   // what the shell did
    kError
};

// Where the shell writes. Must be thread-safe: `watch` reports from its own thread.
using printer = std::function<void(style, std::string_view)>;

[[nodiscard]] inline std::optional<std::string> read_text_file(const std::string& path) {
    std::ifstream in{path, std::ios::binary};
    if (!in) {
        return std::nullopt;
    }
    return std::string{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
}

// A module named by id ("#3" or "3") or name.
[[nodiscard]] inline Rhp::module_ref parse_module(std::string_view text) {
    std::string_view digits = text.starts_with('#') ? text.substr(1) : text;
    std::uint64_t id = 0;
    bool numeric = !digits.empty() && digits.size() <= 18; // ids fit; longer digit runs are names
    for (const char c : digits) {
        if (c < '0' || c > '9') {
            numeric = false;
            break;
        }
        id = id * 10 + static_cast<std::uint64_t>(c - '0');
    }
    if (numeric) {
        return Rhp::module_ref{Rhp::module_id{id}};
    }
    return Rhp::module_ref{std::string{text}};
}

// The rhp-cli command language over one client: REPL lines, multi-line Lua, `watch`. Every
// command prints its outcome; failures() counts the ones that failed (the exit status of
// non-interactive runs).
template <Rhp::configuration Cfg>
    requires std::same_as<typename Cfg::errors_t, Rhp::errors::expected>
class shell {
public:
    // `interrupted` is polled while a script runs (Ctrl+C): true cancels it on the host.
    shell(Rhp::client<Cfg>& c, printer out, std::function<bool()> interrupted = {}) : client_(c), out_(std::move(out)), interrupted_(std::move(interrupted)) {}

    ~shell() {
        unwatch();
        unsubscribe_all();
    }

    shell(const shell&) = delete;
    shell& operator=(const shell&) = delete;

    // One line of input. Unfinished Lua is buffered until it is complete (continuing() says so).
    // False once the user asked to quit.
    bool feed(std::string_view line) {
        if (!buffer_.empty()) {
            buffer_ += '\n';
            buffer_ += line;
            if (lua_incomplete(buffer_)) {
                return true;
            }
            std::string chunk = std::exchange(buffer_, {});
            (void)exec(chunk);
            return true;
        }
        const auto words = split_words(line);
        if (words.empty()) {
            return true;
        }
        const std::string& cmd = words.front();
        const auto arg = [&](std::size_t i) -> std::string { return i < words.size() ? words[i] : std::string{}; };
        const auto need = [&](std::size_t n, std::string_view usage) {
            if (words.size() < n + 1) {
                error(std::format("usage: {}", usage));
                return false;
            }
            return true;
        };
        if (cmd == "quit" || cmd == "exit") {
            return false;
        }
        if (cmd == "help" || cmd == "?") {
            help();
        } else if (cmd == "exec") {
            const auto at = line.find_first_not_of(" \t");
            run_lua(std::string{line.substr(at).starts_with("exec") ? line.substr(at + 4) : line});
        } else if (cmd == "load" || cmd == "reload") {
            if (need(2, std::format("{} <module> <file.lua>", cmd))) {
                (void)load_file(arg(1), arg(2), cmd == "reload");
            }
        } else if (cmd == "call") {
            if (need(2, "call <module> <function> [args...]")) {
                // Quoted arguments stay strings: "42" is text, 42 a number.
                const auto quoted = split_words(line, true);
                std::vector<Rhp::value> args;
                for (std::size_t i = 3; i < quoted.size(); ++i) {
                    args.push_back(parse_literal(quoted[i]));
                }
                report_values(client_.call(parse_module(arg(1)), arg(2), args));
            }
        } else if (cmd == "rollback") {
            if (need(1, "rollback <module> [steps]")) {
                const Rhp::value n = words.size() > 2 ? parse_literal(arg(2)) : Rhp::value{std::int64_t{1}};
                const auto* count = n.get_if<std::int64_t>();
                if (count == nullptr || *count < 1) {
                    error("usage: rollback <module> [steps >= 1]");
                    return true;
                }
                const auto steps = static_cast<std::size_t>(*count);
                auto r = client_.rollback(parse_module(arg(1)), steps);
                r ? info(std::format("rolled back {} to revision {}", arg(1), *r)) : error(r.error());
            }
        } else if (cmd == "revert") {
            if (need(1, "revert <module>")) {
                report_summary("reverted", client_.revert(parse_module(arg(1))));
            }
        } else if (cmd == "unload") {
            if (need(1, "unload <module> [force]")) {
                report_summary("unloaded", client_.unload(parse_module(arg(1)), arg(2) == "force"));
            }
        } else if (cmd == "pin" || cmd == "unpin") {
            if (need(1, std::format("{} <module>", cmd))) {
                auto r = cmd == "pin" ? client_.pin(parse_module(arg(1))) : client_.unpin(parse_module(arg(1)));
                r ? info(std::format("{}ned {}", cmd, arg(1))) : error(r.error());
            }
        } else if (cmd == "checkpoint") {
            if (need(1, "checkpoint <tag>")) {
                auto r = client_.checkpoint(arg(1));
                r ? info(std::format("checkpoint {}", arg(1))) : error(r.error());
            }
        } else if (cmd == "revert_to") {
            if (need(1, "revert_to <tag>")) {
                report_summary("reverted to " + arg(1), client_.revert_to(arg(1)));
            }
        } else if (cmd == "revert_all") {
            report_summary("revert_all", client_.revert_all());
        } else if (cmd == "list") {
            list();
        } else if (cmd == "status") {
            if (need(1, "status <module>")) {
                auto s = client_.status(parse_module(arg(1)));
                s ? plain(describe(*s)) : error(s.error());
            }
        } else if (cmd == "stubs") {
            // stubs | stubs file | stubs > file
            std::string target = arg(1) == ">" ? arg(2) : arg(1);
            (void)stubs(target);
        } else if (cmd == "blob") {
            if (need(2, "blob <sink> <file> [name]")) {
                (void)send_blob(arg(1), arg(2), words.size() > 3 ? arg(3) : std::string{});
            }
        } else if (cmd == "watch") {
            if (need(1, "watch <folder>")) {
                (void)watch(arg(1));
            }
        } else if (cmd == "unwatch") {
            unwatch();
            info("stopped watching");
        } else if (cmd == "subscribe") {
            if (need(1, "subscribe <event>")) {
                (void)subscribe(arg(1));
            }
        } else if (cmd == "unsubscribe") {
            if (need(1, "unsubscribe <event>")) {
                (void)unsubscribe(arg(1));
            }
        } else if (cmd == "whoami") {
            const auto who = client_.info();
            info(std::format("{} ({}) on a {} host, session {}", who.identity, who.granted, who.host_platform, who.session));
        } else {
            run_lua(std::string{line}); // bare Lua
        }
        return true;
    }

    [[nodiscard]] bool continuing() const noexcept { return !buffer_.empty(); }

    // Drops unfinished multi-line Lua (Ctrl+C at a continuation prompt).
    void reset() noexcept { buffer_.clear(); }

    // End of input: unfinished Lua is an error (never run, never silently dropped). False if there was some.
    bool finish() {
        if (buffer_.empty()) {
            return true;
        }
        buffer_.clear();
        error("unfinished Lua at the end of input (an open block, bracket or string)");
        return false;
    }

    // Runs Lua in the scratch module and prints what it returned. True on success.
    bool exec(std::string_view source) {
        auto p = client_.async().exec(source);
        bool cancelled = false;
        while (!p.wait_for(std::chrono::milliseconds{50})) {
            if (!cancelled && interrupted_ && interrupted_()) {
                client_.cancel(p.request());
                cancelled = true;
                info("cancelling...");
            }
        }
        auto r = std::move(p).get();
        if (!r) {
            error(r.error());
            return false;
        }
        if (!r->empty()) {
            plain(format_values(*r));
        }
        return true;
    }

    // load (or reload, by name) a file as a module; `pin` keeps it after this client leaves.
    bool load_file(const std::string& name, const std::string& path, bool reload_only = false, bool pin = false) {
        const auto source = read_text_file(path);
        if (!source) {
            error(std::format("can't read {}", path));
            return false;
        }
        if (reload_only) {
            auto r = client_.reload(parse_module(name), *source);
            if (!r) {
                error(r.error());
                return false;
            }
            info(std::format("reloaded {} (revision {})", name, *r));
            return true;
        }
        auto mod = client_.load(name, *source);
        if (!mod) {
            error(mod.error());
            return false;
        }
        info(std::format("loaded {} #{}", name, *mod));
        if (pin) {
            if (auto pinned = client_.pin(*mod); !pinned) {
                error(pinned.error());
                return false;
            }
            info(std::format("pinned {}: it stays after this client disconnects", name));
        }
        return true;
    }

    // Writes the host's LuaLS stubs to `path` (empty: prints them).
    bool stubs(const std::string& path) {
        auto text = client_.describe();
        if (!text) {
            error(text.error());
            return false;
        }
        if (path.empty()) {
            plain(*text);
            return true;
        }
        std::ofstream file{path, std::ios::binary | std::ios::trunc};
        if (!(file << *text)) {
            error(std::format("can't write {}", path));
            return false;
        }
        info(std::format("wrote {} ({} bytes)", path, text->size()));
        return true;
    }

    bool send_blob(const std::string& sink, const std::string& path, std::string name) {
        const auto data = read_text_file(path);
        if (!data) {
            error(std::format("can't read {}", path));
            return false;
        }
        if (name.empty()) {
            name = std::filesystem::path{path}.filename().string();
        }
        auto r = client_.blob(sink, std::as_bytes(std::span{data->data(), data->size()}), name);
        if (!r) {
            error(r.error());
            return false;
        }
        info(std::format("sent {} ({} bytes) to sink {}", name, data->size(), sink));
        return true;
    }

    // Prints every delivery of `event` (a C++ event of the host, or an rhp.publish of this identity's
    // scripts; "*": every publish) until unsubscribe.
    bool subscribe(const std::string& event) {
        if (subs_.contains(event)) {
            info(std::format("already subscribed to {}", event));
            return true;
        }
        auto id = client_.on(event, [print = out_](const Rhp::remote_event& e) {
            std::string line = std::format("event {}", e.name);
            if (e.module) {
                line += std::format(" [#{}]", e.module);
            }
            if (!e.args.empty()) {
                line += ' ';
                line += format_values(std::vector<Rhp::value>{e.args.begin(), e.args.end()});
            }
            if (e.dropped != 0) {
                line += std::format(" (dropped {})", e.dropped);
            }
            print(style::kOutput, line);
        });
        if (!id) {
            error(id.error());
            return false;
        }
        subs_.emplace(event, *id);
        info(std::format("subscribed to {}", event));
        return true;
    }

    bool unsubscribe(const std::string& event) {
        const auto it = subs_.find(event);
        if (it == subs_.end()) {
            error(std::format("not subscribed to {}", event));
            return false;
        }
        auto r = client_.off(it->second);
        subs_.erase(it);
        if (!r) {
            error(r.error());
            return false;
        }
        info(std::format("unsubscribed from {}", event));
        return true;
    }

    void unsubscribe_all() {
        for (const auto& [event, id] : std::exchange(subs_, {})) {
            (void)client_.off(id);
        }
    }

    // Reloads <folder>/*.lua whenever one is saved (module name = file stem). Replaces an earlier watch.
    bool watch(const std::string& folder) {
        unwatch();
        std::error_code ec;
        if (!std::filesystem::is_directory(folder, ec)) {
            error(std::format("{} is not a folder", folder));
            return false;
        }
        info(std::format("watching {} (save a .lua file to reload it; `unwatch` stops)", folder));
        watcher_ = std::jthread{[this, folder](std::stop_token stop) {
            std::map<std::filesystem::path, std::filesystem::file_time_type> seen = snapshot(folder);
            while (!stop.stop_requested()) {
                std::this_thread::sleep_for(std::chrono::milliseconds{200});
                for (const auto& [file, time] : snapshot(folder)) {
                    const auto it = seen.find(file);
                    if (it != seen.end() && it->second == time) {
                        continue;
                    }
                    seen[file] = time;
                    (void)load_file(module_name_for(file.string()), file.string());
                }
            }
        }};
        return true;
    }

    void unwatch() {
        if (watcher_.joinable()) {
            watcher_.request_stop();
            watcher_.join();
        }
    }

    // Commands, then (once fetched) the host's lib names and loaded modules, starting with `prefix`.
    [[nodiscard]] std::vector<std::string> complete(std::string_view prefix) {
        if (!names_) {
            names_.emplace(commands());
            if (auto text = client_.describe()) {
                for (std::string& n : names_from_stubs(*text)) {
                    names_->push_back(std::move(n));
                }
            }
            if (auto modules = client_.list()) {
                for (const Rhp::module_status& m : *modules) {
                    if (!m.scratch) {
                        names_->push_back(m.name);
                    }
                }
            }
        }
        std::vector<std::string> out;
        for (const std::string& n : *names_) {
            if (n.starts_with(prefix)) {
                out.push_back(n);
            }
        }
        return out;
    }

    [[nodiscard]] static std::vector<std::string> commands() {
        return {"help", "exec", "load", "reload", "call", "rollback", "revert", "unload", "pin", "unpin", "checkpoint", "revert_to", "revert_all",
                "list", "status", "stubs", "blob", "watch", "unwatch", "subscribe", "unsubscribe", "whoami", "quit"};
    }

    [[nodiscard]] int failures() const noexcept { return failures_; }

private:
    void run_lua(std::string chunk) {
        if (lua_incomplete(chunk)) {
            buffer_ = std::move(chunk);
            return;
        }
        (void)exec(chunk);
    }

    void help() {
        info(R"(Lua lines run in your scratch module (unfinished blocks continue on the next line).
  exec <lua>                  run Lua                     load <module> <file>     load or reload a module
  reload <module> <file>      transactional reload        call <module> <fn> [args] call an exported function
  rollback <module> [n]       back n revisions            revert <module>          undo its effects
  unload <module> [force]     unload                      pin / unpin <module>     keep after disconnect (admin)
  checkpoint <tag>            mark the ledger             revert_to <tag>          undo back to the mark
  revert_all                  panic button (admin)        list / status <module>   introspection
  stubs [> file]              LuaLS annotations           blob <sink> <file>       push a file to a host sink
  watch <folder> / unwatch    reload *.lua on save        subscribe / unsubscribe <event>  print host events
  whoami / quit
Ctrl+C cancels a running script.)");
    }

    void list() {
        auto modules = client_.list();
        if (!modules) {
            error(modules.error());
            return;
        }
        for (const Rhp::module_status& m : *modules) {
            plain(describe(m));
        }
    }

    [[nodiscard]] static std::string describe(const Rhp::module_status& m) {
        std::string line = std::format("#{} {} [{}] revision {} effects {}", m.id, m.scratch ? std::string{"(scratch)"} : m.name, m.state, m.revision, m.effects);
        if (m.irreversible_effects != 0) {
            line += std::format(" irreversible {}", m.irreversible_effects);
        }
        if (m.pinned) {
            line += " pinned";
        }
        if (m.fault) {
            line += std::format(" fault: {}", m.fault->message);
        }
        return line;
    }

    void report_values(const Rhp::result<Rhp::value_list>& r) {
        if (!r) {
            error(r.error());
            return;
        }
        if (!r->empty()) {
            plain(format_values(*r));
        }
    }

    void report_summary(std::string_view what, const Rhp::result<Rhp::revert_summary>& r) {
        if (!r) {
            error(r.error());
            return;
        }
        std::string line = std::format("{}: {} effects undone", what, r->undone);
        if (r->irreversible != 0) {
            line += std::format(", {} irreversible", r->irreversible);
        }
        if (!r->failures.empty()) {
            line += std::format(", {} failed", r->failures.size());
        }
        if (r->deferred) {
            line += " (deferred)";
        }
        info(line);
    }

    [[nodiscard]] static std::map<std::filesystem::path, std::filesystem::file_time_type> snapshot(const std::string& folder) {
        std::map<std::filesystem::path, std::filesystem::file_time_type> out;
        std::error_code ec;
        for (const auto& entry : std::filesystem::directory_iterator{folder, ec}) {
            if (entry.is_regular_file(ec) && entry.path().extension() == ".lua") {
                out[entry.path()] = entry.last_write_time(ec);
            }
        }
        return out;
    }

    void plain(std::string_view text) { out_(style::kPlain, text); }
    void info(std::string_view text) { out_(style::kInfo, text); }
    void error(std::string_view text) {
        ++failures_;
        out_(style::kError, text);
    }
    void error(const Rhp::error& e) { error(std::format("{}", e)); }

    Rhp::client<Cfg>& client_;
    printer out_;
    std::function<bool()> interrupted_;
    std::string buffer_;
    std::optional<std::vector<std::string>> names_;
    std::atomic<int> failures_{0};
    std::map<std::string, std::uint64_t> subs_; // subscribed event → client.on id
    std::jthread watcher_;
};

} // namespace rhp_cli

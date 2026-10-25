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
#include <algorithm>
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
        if (debug_events_) {
            (void)client_.off(*debug_events_);
        }
    }

    shell(const shell&) = delete;
    shell& operator=(const shell&) = delete;

    // One line of input. Unfinished Lua is buffered until it is complete (continuing() says so).
    // False once the user asked to quit.
    bool feed(std::string_view line) {
        report_background();
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
                const std::string function = arg(2);
                (void)wait_or_detach(client_.async().call(parse_module(arg(1)), function, args), function, [this](const Rhp::result<Rhp::value_list>& r) {
                    report_values(r);
                    return r.has_value();
                });
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
        } else if (cmd == "tunables") {
            (void)tunables(arg(1));
        } else if (cmd == "tune") {
            if (need(2, "tune <path> <value>")) {
                const auto quoted = split_words(line, true);
                (void)tune(arg(1), parse_literal(quoted[2]));
            }
        } else if (cmd == "profile") {
            (void)profile(arg(1).empty() ? "show" : arg(1), arg(2));
        } else if (cmd == "break") {
            if (need(1, "break <module> [line...] (no lines: clear)")) {
                std::vector<std::uint32_t> lines;
                for (std::size_t i = 2; i < words.size(); ++i) {
                    const auto n = parse_literal(words[i]);
                    const auto* v = n.get_if<std::int64_t>();
                    if (v == nullptr || *v < 1) {
                        error(std::format("'{}' is not a line number", words[i]));
                        return true;
                    }
                    lines.push_back(static_cast<std::uint32_t>(*v));
                }
                (void)set_breakpoints(arg(1), std::move(lines));
            }
        } else if (cmd == "pause") {
            (void)debug_action("pause", 0);
        } else if (cmd == "paused") {
            (void)show_paused();
        } else if (cmd == "continue" || cmd == "step") {
            const std::string mode = cmd == "continue" ? std::string{"continue"} : (arg(1) == "into" || arg(1) == "out" || arg(1) == "over" ? arg(1) : std::string{"over"});
            const std::string which = cmd == "continue" ? arg(1) : (arg(1) == mode ? arg(2) : arg(1));
            (void)resume(mode, which);
        } else if (cmd == "stack") {
            (void)show_stack(arg(1));
        } else if (cmd == "locals" || cmd == "upvalues" || cmd == "globals") {
            (void)show_variables(cmd, arg(1), words.size() > 2 ? std::vector<std::string>(words.begin() + 2, words.end()) : std::vector<std::string>{});
        } else if (cmd == "print") {
            if (need(1, "print <name.path> [frame]")) {
                (void)evaluate(arg(1), arg(2));
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

    // Runs Lua in the scratch module and prints what it returned. True on success. A script that
    // pauses at a breakpoint goes to the background: its result prints when it finishes.
    bool exec(std::string_view source) {
        return wait_or_detach(client_.async().exec(source), "exec", [this](const Rhp::result<Rhp::value_list>& r) {
            if (!r) {
                error(r.error());
                return false;
            }
            if (!r->empty()) {
                plain(format_values(*r));
            }
            return true;
        });
    }

    // Waits for a request (Ctrl+C cancels it). When a script of it pauses at a breakpoint (a pause
    // whose request label is `label`, or ends in "." + label), it moves to the background and `done`
    // runs when it ends; returns what `done` returned, or true for a backgrounded request.
    template <class Pending, class Done>
    bool wait_or_detach(Pending p, std::string label, Done done) {
        pause_seen_.store(false); // pauses before this request aren't its own
        bool cancelled = false;
        while (!p.wait_for(std::chrono::milliseconds{50})) {
            if (!cancelled && interrupted_ && interrupted_()) {
                client_.cancel(p.request());
                cancelled = true;
                info("cancelling...");
            }
            if (took_pause(label)) {
                auto held = std::make_shared<Pending>(std::move(p));
                background_.push_back([held, done]() mutable {
                    if (!held->wait_for(std::chrono::milliseconds{0})) {
                        return false;
                    }
                    (void)done(std::move(*held).get());
                    return true;
                });
                return true;
            }
        }
        return done(std::move(p).get());
    }

    // load (or reload, by name) a file as a module; `pin` keeps it after this client leaves.
    bool load_file(const std::string& name, const std::string& path, bool reload_only = false, bool pin = false) {
        const auto source = read_text_file(path);
        if (!source) {
            error(std::format("can't read {}", path));
            return false;
        }
        if (reload_only) {
            return wait_or_detach(client_.async().reload(parse_module(name), *source), name, [this, name](const Rhp::result<Rhp::revision_id>& r) {
                if (!r) {
                    error(r.error());
                    return false;
                }
                info(std::format("reloaded {} (revision {})", name, *r));
                return true;
            });
        }
        return wait_or_detach(client_.async().load(name, *source), name, [this, name, pin](const Rhp::result<Rhp::module_id>& mod) {
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
        });
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
        return {"help",     "exec",   "load",  "reload",    "call",   "rollback", "revert", "unload",   "pin",      "unpin",  "checkpoint",
                "revert_to", "revert_all", "list", "status", "stubs", "blob",     "watch",  "unwatch",  "subscribe", "unsubscribe", "tunables",
                "tune",     "profile", "break", "pause",     "paused", "continue", "step",   "stack",    "locals",   "upvalues", "globals",
                "print",    "whoami", "quit"};
    }

    // ---- tunables, profiler, debugger --------------------------------------------------------------

    bool tunables(const std::string& prefix) {
        auto list = client_.tunables(prefix);
        if (!list) {
            error(list.error());
            return false;
        }
        for (const Rhp::tunable_message& t : *list) {
            std::string line = std::format("{} = {} ({}{})", t.path, format_value(t.current), t.type, t.writable ? "" : ", read-only");
            if (t.min && t.max) {
                line += std::format(" [{}, {}]", *t.min, *t.max);
            }
            if (t.step) {
                line += std::format(" step {}", *t.step);
            }
            if (!t.unit.empty()) {
                line += std::format(" {}", t.unit);
            }
            if (!t.doc.empty()) {
                line += std::format(": {}", t.doc);
            }
            plain(line);
        }
        return true;
    }

    bool tune(const std::string& path, const Rhp::value& v) {
        auto r = client_.tune(path, v);
        if (!r) {
            error(r.error());
            return false;
        }
        info(std::format("{} = {}", path, format_value(v)));
        return true;
    }

    // profile start [interval] | show | stop [file.folded]
    bool profile(const std::string& action, const std::string& extra) {
        if (action == "start") {
            std::uint32_t interval = 1000;
            if (!extra.empty()) {
                const auto n = parse_literal(extra);
                const auto* v = n.get_if<std::int64_t>();
                if (v == nullptr || *v < 1) {
                    error("usage: profile start [interval]");
                    return false;
                }
                interval = static_cast<std::uint32_t>(*v);
            }
            auto r = client_.profile("start", interval);
            if (!r) {
                error(r.error());
                return false;
            }
            info(std::format("profiling every {} instructions (`profile show`, `profile stop [file]`)", r->interval));
            return true;
        }
        if (action != "show" && action != "stop") {
            error("usage: profile start [interval] | show | stop [file.folded]");
            return false;
        }
        auto r = client_.profile(action == "stop" ? "stop" : "read");
        if (!r) {
            error(r.error());
            return false;
        }
        for (const std::string& line : profile_summary(*r, 15)) {
            plain(line);
        }
        if (action == "stop" && !extra.empty()) {
            std::ofstream file{extra, std::ios::binary | std::ios::trunc};
            if (!(file << folded(*r))) {
                error(std::format("can't write {}", extra));
                return false;
            }
            info(std::format("wrote {} ({} stacks, folded: flamegraph.pl or speedscope)", extra, r->stacks.size()));
        }
        return true;
    }

    bool set_breakpoints(const std::string& source, std::vector<std::uint32_t> lines) {
        listen_for_pauses();
        Rhp::debug_request req;
        req.action = "break";
        req.source = source;
        req.lines = std::move(lines);
        auto r = client_.debug(req);
        if (!r) {
            error(r.error());
            return false;
        }
        if (r->lines.empty()) {
            info(std::format("no breakpoints in {}", source));
        } else {
            std::string at;
            for (const std::uint32_t l : r->lines) {
                at += std::format("{}{}", at.empty() ? "" : ", ", l);
            }
            info(std::format("breakpoints in {}: {}", source, at));
        }
        return true;
    }

    bool show_paused() {
        auto r = debug_action("paused", 0);
        if (!r) {
            return false;
        }
        if (r->paused.empty()) {
            info("nothing is paused");
        }
        for (const auto& p : r->paused) {
            plain(std::format("request {} {} at {}:{} ({})", p.request, p.label, p.source, p.line, p.reason));
        }
        return true;
    }

    bool resume(const std::string& mode, const std::string& which) {
        const auto req = pick_request(which);
        if (!req) {
            return false;
        }
        if (!debug_action(mode, *req)) {
            return false;
        }
        // Wait a little for what happens next: the script finishes, or pauses again.
        pause_seen_.store(false);
        for (int i = 0; i < 40 && !took_pause({}); ++i) {
            if (report_background()) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{50});
        }
        return true;
    }

    bool show_stack(const std::string& which) {
        const auto req = pick_request(which);
        if (!req) {
            return false;
        }
        auto r = debug_action("stack", *req);
        if (!r) {
            return false;
        }
        for (const auto& f : r->frames) {
            plain(std::format("#{} {} ({}:{}){}", f.level, f.name, f.source, f.line, f.what == "C" ? " [C]" : ""));
        }
        return true;
    }

    // locals|upvalues|globals [frame] [name field...]
    bool show_variables(const std::string& scope, const std::string& frame_text, std::vector<std::string> path) {
        const auto req = pick_request({});
        if (!req) {
            return false;
        }
        Rhp::debug_request d;
        d.action = "variables";
        d.request = *req;
        d.scope = scope;
        if (!frame_text.empty()) {
            const auto n = parse_literal(frame_text);
            if (const auto* v = n.get_if<std::int64_t>(); v != nullptr && *v >= 0) {
                d.frame = static_cast<std::uint32_t>(*v);
            } else {
                path.insert(path.begin(), frame_text); // `locals t` is a path, not a frame
            }
        }
        d.path = std::move(path);
        auto r = client_.debug(d);
        if (!r) {
            error(r.error());
            return false;
        }
        for (const auto& v : r->variables) {
            plain(std::format("{} = {}{}", v.name, v.text, v.type == "string" || v.type == "number" || v.type == "boolean" || v.type == "nil" ? "" : std::format(" ({})", v.type)));
        }
        return true;
    }

    bool evaluate(const std::string& expression, const std::string& frame_text) {
        const auto req = pick_request({});
        if (!req) {
            return false;
        }
        Rhp::debug_request d;
        d.action = "evaluate";
        d.request = *req;
        d.expression = expression;
        if (!frame_text.empty()) {
            const auto n = parse_literal(frame_text);
            if (const auto* v = n.get_if<std::int64_t>(); v != nullptr && *v >= 0) {
                d.frame = static_cast<std::uint32_t>(*v);
            }
        }
        auto r = client_.debug(d);
        if (!r) {
            error(r.error());
            return false;
        }
        for (const auto& v : r->variables) {
            plain(std::format("{} = {} ({})", v.name, v.text, v.type));
        }
        return true;
    }

    // "stack count" lines, the folded format flame graph tools read.
    [[nodiscard]] static std::string folded(const Rhp::profile_reply& r) {
        std::string out;
        for (const auto& s : r.stacks) {
            out += std::format("{} {}\n", s.stack, s.samples);
        }
        return out;
    }

    // A header line, then the functions with the most samples of their own ("self") and in total.
    [[nodiscard]] static std::vector<std::string> profile_summary(const Rhp::profile_reply& r, std::size_t top) {
        std::vector<std::string> out;
        out.push_back(std::format("{} samples every {} instructions over {:.1f} ms ({} dropped){}", r.samples, r.interval, static_cast<double>(r.elapsed_us) / 1000.0,
                                  r.dropped, r.running ? ", still running" : ""));
        std::map<std::string, std::pair<std::uint64_t, std::uint64_t>> by_frame; // self, total
        for (const auto& s : r.stacks) {
            std::vector<std::string_view> frames;
            for (std::size_t start = 0; start <= s.stack.size();) {
                const std::size_t end = std::min(s.stack.find(';', start), s.stack.size());
                frames.emplace_back(std::string_view{s.stack}.substr(start, end - start));
                start = end + 1;
            }
            std::vector<std::string_view> seen;
            for (const std::string_view f : frames) {
                if (std::ranges::find(seen, f) == seen.end()) { // recursion counts once in the total
                    by_frame[std::string{f}].second += s.samples;
                    seen.push_back(f);
                }
            }
            if (!frames.empty()) {
                by_frame[std::string{frames.back()}].first += s.samples;
            }
        }
        std::vector<std::pair<std::string, std::pair<std::uint64_t, std::uint64_t>>> rows(by_frame.begin(), by_frame.end());
        std::ranges::sort(rows, [](const auto& a, const auto& b) { return a.second.first != b.second.first ? a.second.first > b.second.first : a.first < b.first; });
        const double total = r.samples == 0 ? 1.0 : static_cast<double>(r.samples);
        out.emplace_back("   self   total  function");
        for (std::size_t i = 0; i < rows.size() && i < top; ++i) {
            out.push_back(std::format("{:6.1f}% {:6.1f}%  {}", 100.0 * static_cast<double>(rows[i].second.first) / total, 100.0 * static_cast<double>(rows[i].second.second) / total,
                                      rows[i].first));
        }
        return out;
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

    // The paused request a command means: `which` ("#3" or "3"), else the one that paused last, else
    // the only one paused.
    std::optional<std::uint64_t> pick_request(const std::string& which) {
        if (!which.empty()) {
            const auto n = parse_literal(which.starts_with('#') ? which.substr(1) : which);
            if (const auto* v = n.get_if<std::int64_t>(); v != nullptr && *v > 0) {
                return static_cast<std::uint64_t>(*v);
            }
            error(std::format("'{}' is not a request number", which));
            return std::nullopt;
        }
        auto r = debug_action("paused", 0);
        if (!r) {
            return std::nullopt;
        }
        if (r->paused.empty()) {
            error("nothing is paused");
            return std::nullopt;
        }
        const std::uint64_t last = last_paused_.load();
        for (const auto& p : r->paused) {
            if (p.request == last) {
                return last;
            }
        }
        return r->paused.front().request;
    }

    Rhp::result<Rhp::debug_reply> debug_action(const std::string& action, std::uint64_t request) {
        if (action == "pause") {
            listen_for_pauses();
        }
        Rhp::debug_request d;
        d.action = action;
        d.request = request;
        auto r = client_.debug(d);
        if (!r) {
            error(r.error());
        } else if (action == "pause") {
            info("the next line a script runs pauses");
        }
        return r;
    }

    // Prints "paused at ..." for every pause the host reports (subscribed when debugging starts).
    void listen_for_pauses() {
        if (debug_events_) {
            return;
        }
        auto id = client_.on("rhp.debug", [this](const Rhp::remote_event& e) {
            if (e.args.empty()) {
                return;
            }
            const Rhp::value& info_map = e.args.front();
            const auto text = [&](std::string_view key) {
                const Rhp::value* v = info_map.find(key);
                if (v != nullptr && v->get_if<std::string>() != nullptr) {
                    return *v->get_if<std::string>();
                }
                return v != nullptr ? format_value(*v) : std::string{"?"};
            };
            const Rhp::value* kind = info_map.find("kind");
            const bool paused = kind != nullptr && kind->get_if<std::string>() != nullptr && *kind->get_if<std::string>() == "paused";
            if (const Rhp::value* req = info_map.find("request"); req != nullptr && req->get_if<std::int64_t>() != nullptr && paused) {
                last_paused_.store(static_cast<std::uint64_t>(*req->get_if<std::int64_t>()));
                {
                    const std::scoped_lock lock{pause_mutex_};
                    pause_label_ = text("label");
                }
                pause_seen_.store(true);
            }
            out_(style::kInfo, std::format("{} at {}:{} (request {}, {}){}", paused ? "paused" : "hit (can't pause here)", text("source"), text("line"), text("request"),
                                           text("reason"), paused ? ": continue / step [into|over|out] / stack / locals / print <name>" : ""));
        });
        if (id) {
            debug_events_ = *id;
        } else {
            error(id.error());
        }
    }

    // A pause arrived since the flag was cleared (of a request labelled `label`, when one is given).
    bool took_pause(const std::string& label) {
        if (!pause_seen_.load()) {
            return false;
        }
        if (!label.empty()) {
            const std::scoped_lock lock{pause_mutex_};
            if (pause_label_ != label && !pause_label_.ends_with("." + label)) {
                return false;
            }
        }
        return pause_seen_.exchange(false);
    }

    // Prints the results of requests that paused and have finished since. True if one did.
    bool report_background() {
        bool any = false;
        for (auto it = background_.begin(); it != background_.end();) {
            if ((*it)()) {
                it = background_.erase(it);
                any = true;
            } else {
                ++it;
            }
        }
        return any;
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
  tunables [prefix]           variables and their tags    tune <path> <value>      set one (journaled)
  profile start [n] / show / stop [file.folded]           sample where scripts spend instructions
  break <module> [lines]      set (or clear) breakpoints  pause                    pause the next line run
  paused / continue [req]     list / resume               step [into|over|out]     step a paused script
  stack / locals|upvalues|globals [frame] [path]          print <name.path> [frame]  inspect (no Lua runs)
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
    std::optional<std::uint64_t> debug_events_; // the "rhp.debug" subscription, once debugging started
    std::atomic<bool> pause_seen_{false};
    std::atomic<std::uint64_t> last_paused_{0};
    std::mutex pause_mutex_;
    std::string pause_label_;                        // of the last pause (guarded by pause_mutex_)
    std::vector<std::function<bool()>> background_; // requests that paused while the shell waited: true once done and printed
    std::jthread watcher_;
};

} // namespace rhp_cli

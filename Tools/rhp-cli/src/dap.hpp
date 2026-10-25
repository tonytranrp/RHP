#pragma once

// rhp-cli dap: a Debug Adapter Protocol server on stdin / stdout that drives a host's debugger
// (wire kDebug) for one identity. An editor (VS Code, any DAP client) launches `rhp-cli dap -c
// host -i id [--root folder]`; breakpoints set in <root>/game/combat.lua apply to the module
// "game.combat". Paused requests are DAP threads.

#include <algorithm>
#include <charconv>
#include <chrono>
#include <concepts>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <filesystem>
#include <format>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "json.hpp"

#include <rhp/client/client.hpp>
#include <rhp/core/value.hpp>

namespace rhp_cli {

// Module name <-> file path under a source root ("game/combat.lua" <-> "game.combat").
class source_map {
public:
    explicit source_map(std::string root) : root_(std::move(root)) {}

    [[nodiscard]] std::string module_for(std::string_view path) const {
        std::filesystem::path p{std::string{path}};
        if (!root_.empty()) {
            std::error_code ec;
            const auto rel = std::filesystem::relative(p, root_, ec);
            if (!ec && !rel.empty() && !rel.string().starts_with("..")) {
                p = rel;
            } else {
                p = p.filename();
            }
        } else {
            p = p.filename();
        }
        p.replace_extension();
        std::string name = p.generic_string();
        for (char& c : name) {
            if (c == '/') {
                c = '.';
            }
        }
        return name;
    }

    // The file a module came from, when there is a root and the file is in it.
    [[nodiscard]] std::optional<std::string> path_for(std::string_view module) const {
        if (root_.empty() || module.empty()) {
            return std::nullopt;
        }
        std::string rel{module};
        for (char& c : rel) {
            if (c == '.') {
                c = '/';
            }
        }
        std::filesystem::path p = std::filesystem::path{root_} / (rel + ".lua");
        p.make_preferred();
        std::error_code ec;
        if (!std::filesystem::is_regular_file(p, ec)) {
            return std::nullopt;
        }
        return p.string();
    }

private:
    std::string root_;
};

// Reads DAP messages ("Content-Length: n\r\n\r\n<json>") from a stream. nullopt at the end, and
// for what isn't DAP (no length, a length that isn't a number, a header line that never ends, a
// body over 64 MiB): the stream can't be resynchronized after that.
// `next_byte()` returns the next byte as an unsigned char value, or EOF.
template <std::invocable Next>
[[nodiscard]] std::optional<std::string> read_dap_message(Next&& next_byte) {
    constexpr std::size_t kMaxHeader = 1024;   // bytes in one header line
    constexpr std::size_t kMaxHeaders = 32;    // header lines in one message
    constexpr std::size_t kMaxBody = 64u << 20;
    std::optional<std::size_t> length;
    std::size_t headers = 0;
    std::string line;
    while (true) {
        const int c = static_cast<int>(next_byte());
        if (c == EOF) {
            return std::nullopt;
        }
        if (c != '\n') {
            if (c != '\r') {
                if (line.size() == kMaxHeader) {
                    return std::nullopt;
                }
                line += static_cast<char>(c);
            }
            continue;
        }
        if (line.empty()) {
            if (headers == 0) {
                continue; // blank lines between messages
            }
            break; // the blank line after the headers
        }
        if (++headers > kMaxHeaders) {
            return std::nullopt;
        }
        constexpr std::string_view kLength = "Content-Length:";
        if (line.starts_with(kLength)) {
            std::string_view digits = std::string_view{line}.substr(kLength.size());
            while (!digits.empty() && (digits.front() == ' ' || digits.front() == '\t')) {
                digits.remove_prefix(1);
            }
            while (!digits.empty() && (digits.back() == ' ' || digits.back() == '\t')) {
                digits.remove_suffix(1);
            }
            std::size_t n = 0;
            const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), n);
            if (digits.empty() || ec != std::errc{} || end != digits.data() + digits.size() || length) {
                return std::nullopt; // not a number, or two lengths
            }
            length = n;
        }
        line.clear();
    }
    if (!length || *length > kMaxBody) {
        return std::nullopt;
    }
    const std::size_t length_value = *length;
    std::string body;
    body.reserve(length_value);
    for (std::size_t i = 0; i < length_value; ++i) {
        const int c = static_cast<int>(next_byte());
        if (c == EOF) {
            return std::nullopt; // cut short
        }
        body += static_cast<char>(c);
    }
    return body;
}

[[nodiscard]] inline std::optional<std::string> read_dap_message(std::FILE* in) {
    return read_dap_message([in] { return std::fgetc(in); });
}

template <Rhp::configuration Cfg>
class dap_server {
public:
    dap_server(Rhp::client<Cfg>& c, std::string root, std::function<void(std::string_view)> write)
        : client_(c), sources_(std::move(root)), write_(std::move(write)) {}

    // Handles messages until the client disconnects or `next` returns nothing; returns the exit status.
    // `next` runs on a reader thread that may outlive this call (blocked in a read): it owns its
    // copy of `next` and shares only the inbox with the server.
    int run(std::function<std::optional<std::string>()> next) {
        const std::shared_ptr<inbox> box = inbox_;
        auto events = client_.on("rhp.debug", [box](const Rhp::remote_event& e) {
            if (!e.args.empty()) {
                const std::scoped_lock lock{box->mutex};
                box->events.push_back(e.args.front());
                box->wake.notify_all();
            }
        });
        if (!events) {
            log(std::format("can't subscribe to rhp.debug: {}", events.error()));
            return 1;
        }
        std::jthread reader{[box, next = std::move(next)](std::stop_token stop) {
            while (!stop.stop_requested()) {
                auto message = next();
                const std::scoped_lock lock{box->mutex};
                if (!message) {
                    box->eof = true;
                    box->wake.notify_all();
                    return;
                }
                box->messages.push_back(std::move(*message));
                box->wake.notify_all();
            }
        }};
        while (!done_) {
            std::optional<std::string> message;
            std::vector<Rhp::value> events_now;
            {
                std::unique_lock lock{box->mutex};
                box->wake.wait_for(lock, std::chrono::milliseconds{50}, [&] { return !box->messages.empty() || !box->events.empty() || box->eof; });
                if (!box->messages.empty()) {
                    message = std::move(box->messages.front());
                    box->messages.pop_front();
                }
                events_now.swap(box->events);
                if (box->eof && box->messages.empty() && !message) {
                    done_ = true;
                }
            }
            for (const Rhp::value& e : events_now) {
                host_event(e);
            }
            if (message) {
                handle(*message);
            }
        }
        (void)client_.off(*events);
        reader.request_stop();
        reader.detach(); // blocked in a read of stdin: the process ends with it
        return 0;
    }

    // One message (exposed for tests).
    void handle(std::string_view text) {
        const auto msg = parse_json(text);
        if (!msg || msg->find("command") == nullptr) {
            log("a message that isn't a DAP request");
            return;
        }
        const std::string command = str(*msg, "command");
        const Rhp::value args = msg->find("arguments") != nullptr ? *msg->find("arguments") : Rhp::value{Rhp::value::map{}};
        const std::int64_t seq = num(*msg, "seq");
        auto body = dispatch(command, args);
        if (body) {
            respond(seq, command, true, {}, std::move(*body));
        } else {
            respond(seq, command, false, body.error().message, Rhp::value{});
        }
        if (command == "initialize") {
            event("initialized", Rhp::value{Rhp::value::map{}});
        }
    }

    [[nodiscard]] bool done() const noexcept { return done_; }

private:
    struct frame_ref {
        std::uint64_t request = 0;
        std::uint32_t level = 0;
    };

    struct var_ref {
        std::uint64_t request = 0;
        std::uint32_t level = 0;
        std::string scope;
        std::vector<std::string> path;
    };

    // What the reader thread and the event callback hand to the server loop.
    struct inbox {
        std::mutex mutex;
        std::condition_variable wake;
        std::deque<std::string> messages;
        std::vector<Rhp::value> events;
        bool eof = false;
    };

    static constexpr std::int64_t kNoThread = 0;     // the thread shown when nothing is paused
    static constexpr std::size_t kMaxRefs = 100'000; // frame / variable references kept (oldest go first)

    static std::string str(const Rhp::value& m, std::string_view key) {
        const Rhp::value* v = m.find(key);
        return v != nullptr && v->get_if<std::string>() != nullptr ? *v->get_if<std::string>() : std::string{};
    }

    static std::int64_t num(const Rhp::value& m, std::string_view key) {
        const Rhp::value* v = m.find(key);
        return v != nullptr && v->get_if<std::int64_t>() != nullptr ? *v->get_if<std::int64_t>() : 0;
    }

    static Rhp::value obj(std::initializer_list<std::pair<std::string_view, Rhp::value>> fields) {
        Rhp::value::map m;
        for (const auto& [k, v] : fields) {
            m.emplace_back(Rhp::value{std::string{k}}, v);
        }
        return Rhp::value{std::move(m)};
    }

    void send(const Rhp::value& message) {
        const std::string json = to_json(message);
        write_(std::format("Content-Length: {}\r\n\r\n{}", json.size(), json));
    }

    void respond(std::int64_t request_seq, const std::string& command, bool success, const std::string& message, Rhp::value body) {
        Rhp::value::map m;
        m.emplace_back(Rhp::value{"seq"}, Rhp::value{++seq_});
        m.emplace_back(Rhp::value{"type"}, Rhp::value{"response"});
        m.emplace_back(Rhp::value{"request_seq"}, Rhp::value{request_seq});
        m.emplace_back(Rhp::value{"success"}, Rhp::value{success});
        m.emplace_back(Rhp::value{"command"}, Rhp::value{command});
        if (!success) {
            m.emplace_back(Rhp::value{"message"}, Rhp::value{message});
        }
        if (!body.is_nil()) {
            m.emplace_back(Rhp::value{"body"}, std::move(body));
        }
        send(Rhp::value{std::move(m)});
    }

    void event(std::string_view name, Rhp::value body) {
        send(obj({{"seq", Rhp::value{++seq_}}, {"type", Rhp::value{"event"}}, {"event", Rhp::value{std::string{name}}}, {"body", std::move(body)}}));
    }

    void log(std::string_view text) { event("output", obj({{"category", Rhp::value{"console"}}, {"output", Rhp::value{std::format("{}\n", text)}}})); }

    Rhp::result<Rhp::debug_reply> debug(Rhp::debug_request r) { return client_.debug(r); }

    Rhp::result<Rhp::debug_reply> action(std::string name, std::uint64_t request = 0) {
        Rhp::debug_request r;
        r.action = std::move(name);
        r.request = request;
        return debug(std::move(r));
    }

    std::int64_t frame_id(std::uint64_t request, std::uint32_t level) {
        if (frames_.size() >= kMaxRefs) {
            frames_.erase(frames_.begin());
        }
        const std::int64_t id = ++next_ref_;
        frames_.emplace(id, frame_ref{request, level});
        return id;
    }

    std::int64_t var_id(var_ref ref) {
        if (vars_.size() >= kMaxRefs) {
            vars_.erase(vars_.begin());
        }
        const std::int64_t id = ++next_ref_;
        vars_.emplace(id, std::move(ref));
        return id;
    }

    // A script ran on: the frames and variables handed out for it describe a stack that is gone.
    // Other paused scripts keep theirs.
    void forget_refs(std::uint64_t request) {
        std::erase_if(frames_, [&](const auto& f) { return f.second.request == request; });
        std::erase_if(vars_, [&](const auto& v) { return v.second.request == request; });
    }

    void host_event(const Rhp::value& e) {
        const std::string kind = str(e, "kind");
        if (kind == "paused") {
            const std::string reason = str(e, "reason");
            event("stopped", obj({{"reason", Rhp::value{reason == "pause" ? std::string{"pause"} : reason}},
                                  {"threadId", Rhp::value{num(e, "request")}},
                                  {"allThreadsStopped", Rhp::value{false}}}));
        } else if (kind == "hit") {
            log(std::format("breakpoint at {}:{} hit where the script can't pause (a handler called from C++, or a coroutine)", str(e, "source"), num(e, "line")));
        }
    }

    Rhp::result<Rhp::value> dispatch(const std::string& command, const Rhp::value& args) {
        using V = Rhp::value;
        if (command == "initialize") {
            return obj({{"supportsConfigurationDoneRequest", V{true}}, {"supportsEvaluateForHovers", V{true}}, {"supportsSetVariable", V{false}}});
        }
        if (command == "launch" || command == "attach" || command == "configurationDone" || command == "setExceptionBreakpoints") {
            return V{};
        }
        if (command == "disconnect" || command == "terminate") {
            (void)action("reset");
            done_ = true;
            return V{};
        }
        if (command == "setBreakpoints") {
            const V* source = args.find("source");
            const std::string path = source != nullptr ? str(*source, "path") : std::string{};
            Rhp::debug_request r;
            r.action = "break";
            r.source = sources_.module_for(path);
            if (const V* list = args.find("breakpoints"); list != nullptr && list->get_if<V::array>() != nullptr) {
                for (const V& b : *list->get_if<V::array>()) {
                    if (const auto line = num(b, "line"); line > 0) {
                        r.lines.push_back(static_cast<std::uint32_t>(line));
                    }
                }
            }
            auto set = debug(r);
            if (!set) {
                return std::unexpected{std::move(set).error()};
            }
            V::array out;
            for (const std::uint32_t line : r.lines) {
                const bool kept = std::ranges::find(set->lines, line) != set->lines.end();
                if (kept) {
                    out.push_back(obj({{"verified", V{true}}, {"line", V{static_cast<std::int64_t>(line)}}}));
                } else {
                    out.push_back(obj({{"verified", V{false}}, {"line", V{static_cast<std::int64_t>(line)}}, {"message", V{"the host didn't keep this breakpoint"}}}));
                }
            }
            return obj({{"breakpoints", V{std::move(out)}}});
        }
        if (command == "threads") {
            auto paused = action("paused");
            if (!paused) {
                return std::unexpected{std::move(paused).error()};
            }
            V::array threads;
            for (const auto& p : paused->paused) {
                threads.push_back(obj({{"id", V{static_cast<std::int64_t>(p.request)}}, {"name", V{std::format("{} (request {})", p.label, p.request)}}}));
            }
            if (threads.empty()) { // editors expect a thread to show (and to send "pause" to)
                threads.push_back(obj({{"id", V{kNoThread}}, {"name", V{"(no script paused)"}}}));
            }
            return obj({{"threads", V{std::move(threads)}}});
        }
        if (command == "stackTrace") {
            if (num(args, "threadId") == kNoThread) {
                return obj({{"stackFrames", V{V::array{}}}, {"totalFrames", V{std::int64_t{0}}}});
            }
            const auto request = static_cast<std::uint64_t>(num(args, "threadId"));
            auto stack = action("stack", request);
            if (!stack) {
                return std::unexpected{std::move(stack).error()};
            }
            V::array frames;
            for (const auto& f : stack->frames) {
                V::map m;
                m.emplace_back(V{"id"}, V{frame_id(request, f.level)});
                m.emplace_back(V{"name"}, V{f.name});
                if (f.what != "C") {
                    V::map source;
                    source.emplace_back(V{"name"}, V{f.source});
                    if (auto path = sources_.path_for(f.source)) {
                        source.emplace_back(V{"path"}, V{std::move(*path)});
                    }
                    m.emplace_back(V{"source"}, V{std::move(source)});
                }
                m.emplace_back(V{"line"}, V{static_cast<std::int64_t>(f.line)});
                m.emplace_back(V{"column"}, V{std::int64_t{1}});
                frames.emplace_back(std::move(m));
            }
            const auto count = static_cast<std::int64_t>(frames.size());
            return obj({{"stackFrames", V{std::move(frames)}}, {"totalFrames", V{count}}});
        }
        if (command == "scopes") {
            const auto it = frames_.find(num(args, "frameId"));
            if (it == frames_.end()) {
                return Rhp::fail(Rhp::errc::kNotFound, "no such frame (the script ran on)", "dap");
            }
            const frame_ref f = it->second;
            V::array scopes;
            for (const auto& [name, scope] : {std::pair{"Locals", "locals"}, std::pair{"Upvalues", "upvalues"}, std::pair{"Globals", "globals"}}) {
                scopes.push_back(obj({{"name", V{name}}, {"variablesReference", V{var_id(var_ref{f.request, f.level, scope, {}})}}, {"expensive", V{false}}}));
            }
            return obj({{"scopes", V{std::move(scopes)}}});
        }
        if (command == "variables") {
            const auto it = vars_.find(num(args, "variablesReference"));
            if (it == vars_.end()) {
                return Rhp::fail(Rhp::errc::kNotFound, "no such variables (the script ran on)", "dap");
            }
            const var_ref ref = it->second;
            Rhp::debug_request r;
            r.action = "variables";
            r.request = ref.request;
            r.frame = ref.level;
            r.scope = ref.scope;
            r.path = ref.path;
            auto vars = debug(r);
            if (!vars) {
                return std::unexpected{std::move(vars).error()};
            }
            V::array out;
            for (const auto& v : vars->variables) {
                std::int64_t child = 0;
                if (v.expandable) {
                    var_ref c = ref;
                    c.path.push_back(v.name);
                    child = var_id(std::move(c));
                }
                out.push_back(obj({{"name", V{v.name}}, {"value", V{v.text}}, {"type", V{v.type}}, {"variablesReference", V{child}}}));
            }
            return obj({{"variables", V{std::move(out)}}});
        }
        if (command == "continue" || command == "next" || command == "stepIn" || command == "stepOut") {
            if (num(args, "threadId") == kNoThread) {
                return command == "continue" ? obj({{"allThreadsContinued", V{false}}}) : V{};
            }
            const auto request = static_cast<std::uint64_t>(num(args, "threadId"));
            const std::string mode = command == "continue" ? "continue" : command == "next" ? "over"
                                                                      : command == "stepIn" ? "into"
                                                                                            : "out";
            forget_refs(request);
            auto r = action(mode, request);
            if (!r) {
                return std::unexpected{std::move(r).error()};
            }
            return command == "continue" ? obj({{"allThreadsContinued", V{false}}}) : V{};
        }
        if (command == "pause") {
            auto r = action("pause");
            if (!r) {
                return std::unexpected{std::move(r).error()};
            }
            return V{};
        }
        if (command == "evaluate") {
            const auto it = frames_.find(num(args, "frameId"));
            if (it == frames_.end()) {
                return Rhp::fail(Rhp::errc::kNotFound, "evaluate needs a paused frame", "dap");
            }
            const frame_ref f = it->second;
            Rhp::debug_request r;
            r.action = "evaluate";
            r.request = f.request;
            r.frame = f.level;
            r.expression = str(args, "expression");
            auto v = debug(r);
            if (!v) {
                return std::unexpected{std::move(v).error()};
            }
            if (v->variables.empty()) {
                return Rhp::fail(Rhp::errc::kProtocol, "the host sent no value", "dap");
            }
            const auto& var = v->variables.front();
            return obj({{"result", V{var.text}}, {"type", V{var.type}}, {"variablesReference", V{std::int64_t{0}}}});
        }
        return Rhp::fail(Rhp::errc::kInvalidArgument, std::format("'{}' isn't supported", command), "dap");
    }

    Rhp::client<Cfg>& client_;
    source_map sources_;
    std::function<void(std::string_view)> write_;
    std::int64_t seq_ = 0;
    bool done_ = false;
    std::int64_t next_ref_ = 0;
    std::map<std::int64_t, frame_ref> frames_; // DAP frame ids (stackTrace)
    std::map<std::int64_t, var_ref> vars_;     // DAP variable references (scopes, variables)
    std::shared_ptr<inbox> inbox_ = std::make_shared<inbox>();
};

} // namespace rhp_cli

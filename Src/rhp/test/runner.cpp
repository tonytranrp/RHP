#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <format>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <rhp/build_config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/test/detail/framework.hpp>
#include <rhp/test/detail/support.hpp>
#include <rhp/test/fake_registry.hpp>
#include <rhp/test/runner.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/utils/crc32c.hpp>
#include <rhp/utils/scope_guard.hpp>

namespace Rhp::test {

using script::sandbox;
using script::value_list;
using steady = std::chrono::steady_clock;

namespace {

namespace fs = std::filesystem;
using detail::object;
using detail::write_text;

constexpr bool kLuaEnabled = RHP_ENABLE != 0;

// ---- small value helpers ----------------------------------------------------------------------------

// A traceback without the framework's own frames (chunks "rhp.test/..."), and the first frame left
// as file and line ("specs/x_spec.lua:12: in ..."), when there is one.
struct user_trace {
    std::string text;
    std::string file;
    std::uint32_t line = 0;
};

user_trace user_traceback(std::string_view traceback) {
    user_trace out;
    std::size_t start = 0;
    while (start < traceback.size()) {
        std::size_t end = traceback.find('\n', start);
        if (end == std::string_view::npos) {
            end = traceback.size();
        }
        const std::string_view line = traceback.substr(start, end - start);
        start = end + 1;
        const std::string_view frame = line.substr(std::min(line.find_first_not_of(" \t"), line.size()));
        if (frame.starts_with("rhp.test/") || frame.starts_with("[C]: in ?") || frame == "(...tail calls...)") {
            continue;
        }
        if (out.file.empty() && !frame.starts_with("stack traceback") && !frame.starts_with("[C]")) {
            const std::size_t colon = frame.find(':');
            const std::size_t colon2 = colon == std::string_view::npos ? colon : frame.find(':', colon + 1);
            if (colon2 != std::string_view::npos) {
                std::uint32_t n = 0;
                const std::string_view digits = frame.substr(colon + 1, colon2 - colon - 1);
                const auto [p, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), n);
                if (ec == std::errc{} && p == digits.data() + digits.size()) {
                    out.file = std::string{frame.substr(0, colon)};
                    out.line = n;
                }
            }
        }
        out.text.append(line).push_back('\n');
    }
    if (!out.text.empty()) {
        out.text.pop_back();
    }
    if (out.text == "stack traceback:") {
        out.text.clear();
    }
    return out;
}

const value* field(const value& v, std::string_view key) {
    return v.find(key);
}

std::string text_of(const value& v, std::string_view key) {
    const value* f = field(v, key);
    const auto* s = f != nullptr ? f->get_if<std::string>() : nullptr;
    return s != nullptr ? *s : std::string{};
}

std::int64_t int_of(const value& v, std::string_view key, std::int64_t fallback = 0) {
    const value* f = field(v, key);
    if (f == nullptr) {
        return fallback;
    }
    if (const auto* i = f->get_if<std::int64_t>()) {
        return *i;
    }
    if (const auto* d = f->get_if<double>()) {
        return static_cast<std::int64_t>(*d);
    }
    return fallback;
}

// An integer or a number as a double; 0 for anything else.
double as_number(const value& v) {
    if (const auto* i = v.get_if<std::int64_t>()) {
        return static_cast<double>(*i);
    }
    if (const auto* d = v.get_if<double>()) {
        return *d;
    }
    return 0;
}

double number_of(const value& v, std::string_view key) {
    const value* f = field(v, key);
    return f != nullptr ? as_number(*f) : 0;
}

bool bool_of(const value& v, std::string_view key) {
    const value* f = field(v, key);
    const auto* b = f != nullptr ? f->get_if<bool>() : nullptr;
    return b != nullptr && *b;
}

const value::array* array_of(const value& v, std::string_view key) {
    const value* f = field(v, key);
    return f != nullptr ? f->get_if<value::array>() : nullptr;
}

std::vector<std::string> strings_of(const value& v, std::string_view key) {
    std::vector<std::string> out;
    if (const auto* list = array_of(v, key)) {
        for (const value& item : *list) {
            if (const auto* s = item.get_if<std::string>()) {
                out.push_back(*s);
            }
        }
    }
    return out;
}

std::string join(const std::vector<std::string>& parts, std::string_view separator) {
    std::string out;
    for (const std::string& p : parts) {
        if (!out.empty()) {
            out += separator;
        }
        out += p;
    }
    return out;
}

// An error the framework reports for a file ({message, source, line, traceback}).
file_error file_error_of(const value& e) {
    return file_error{text_of(e, "message"), text_of(e, "source"), static_cast<std::uint32_t>(int_of(e, "line")), text_of(e, "traceback")};
}

// A note on the globals a test created (the framework removed them after it), when it created any.
void note_globals(const value& outcome, std::vector<std::string>& notes) {
    if (const auto* list = array_of(outcome, "globals"); list != nullptr && !list->empty()) {
        notes.push_back(std::format("the test set global(s) {} (removed after it)", join(strings_of(outcome, "globals"), ", ")));
    }
}

// "file:line" of a test's failure (or of the test).
std::string where_of(const test_result& r) {
    const detail::place at = detail::failure_place(r);
    return std::format("{}:{}", at.file, at.line);
}

// A module whose require()s aren't loaded yet (it waits for the next round).
bool waits_for_require(const error& e) {
    return e.message.find("is not loaded") != std::string::npos || e.message.find("is still loading") != std::string::npos;
}

std::string read_text(const fs::path& path, std::optional<error>& failure) {
    auto bytes = platform::read_file(path);
    if (!bytes) {
        failure = std::move(bytes).error();
        return {};
    }
    return std::string{reinterpret_cast<const char*>(bytes->data()), bytes->size()};
}

bool is_test_file(const fs::path& p) {
    const std::string name = p.filename().string();
    return p.extension() == ".lua" && (name.ends_with("_spec.lua") || name.ends_with(".spec.lua") || name.ends_with("_test.lua") || name.starts_with("test_"));
}

std::string generic(const fs::path& p) {
    return p.generic_string();
}

// "scripts/game/combat.lua" under "scripts" -> "game.combat"; init.lua names its folder.
std::optional<std::string> module_name(const fs::path& relative) {
    fs::path p = relative;
    if (p.filename() == "init.lua") {
        p = p.parent_path();
    } else {
        p.replace_extension();
    }
    std::string name = p.generic_string();
    std::ranges::replace(name, '/', '.');
    if (name.empty()) {
        return std::nullopt;
    }
    for (std::size_t i = 0; i < name.size(); ++i) {
        const char c = name[i];
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9' && i > 0 && name[i - 1] != '.') || c == '_' || (c == '.' && i > 0 && i + 1 < name.size() && name[i - 1] != '.');
        if (!ok) {
            return std::nullopt;
        }
    }
    return name;
}

// Long-bracket Lua text for a string: [==[...]==] at a level the text doesn't close.
// A Lua long string holding `text` exactly: [[...]], [=[...]=], ... (multi-line text starts on its
// own line: Lua drops a newline right after the opening bracket).
std::string long_bracket(std::string_view text) {
    std::size_t level = 0;
    while (true) {
        const std::string close = "]" + std::string(level, '=');
        if (text.find(close + "]") == std::string_view::npos && !text.ends_with(close)) {
            break;
        }
        ++level;
    }
    const std::string eq(level, '=');
    const bool own_line = text.find('\n') != std::string_view::npos || text.starts_with('\r');
    return std::format("[{}[{}{}]{}]", eq, own_line ? "\n" : "", text, eq);
}

// A Lua string literal in double quotes.
std::string lua_quoted(std::string_view text) {
    std::string out = "\"";
    for (const char c : text) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) {
                out += std::format("\\{:03}", static_cast<unsigned char>(c));
            } else {
                out += c;
            }
        }
    }
    out += '"';
    return out;
}

bool name_matches(const std::string& name, const std::string& filter) {
    if (filter.size() >= 2 && filter.front() == '/' && filter.back() == '/') {
        try {
            return std::regex_search(name, std::regex{filter.substr(1, filter.size() - 2)});
        } catch (const std::regex_error&) {
            return false;
        }
    }
    return name.find(filter) != std::string::npos;
}

// Lines between "-- rhp: coverage off" and "-- rhp: coverage on" (also luacov's disable / enable).
std::set<std::uint32_t> excluded_lines(std::string_view source) {
    std::set<std::uint32_t> out;
    bool off = false;
    std::uint32_t line = 1;
    std::size_t start = 0;
    while (start <= source.size()) {
        const std::size_t end = std::min(source.find('\n', start), source.size());
        const std::string_view text = source.substr(start, end - start);
        if (text.find("rhp: coverage off") != std::string_view::npos || text.find("luacov: disable") != std::string_view::npos) {
            off = true;
        }
        if (off) {
            out.insert(line);
        }
        if (text.find("rhp: coverage on") != std::string_view::npos || text.find("luacov: enable") != std::string_view::npos) {
            off = false;
        }
        if (end >= source.size()) {
            break;
        }
        start = end + 1;
        ++line;
    }
    return out;
}

// ---- the snapshot store of one test file ---------------------------------------------------------------

struct snapshot_store {
    fs::path path;
    bool loaded = false;
    std::map<std::string, std::string> stored;  // key -> serialized value
    std::map<std::string, std::string> written; // what this run checked or stored
    bool dirty = false;
    std::string broken; // why the file can't be read: its tests fail, and it isn't rewritten
};

} // namespace

// ---- the runner -------------------------------------------------------------------------------------------

struct runner::impl {
    run_options options;
    install_fn install;
    fs::path root;
    std::uint64_t seed = 0;

    struct script_file {
        std::string module;
        fs::path path;
        std::string source;
        mutable std::string bytecode; // compiled by the first sandbox that loads it (load_script)
    };
    std::vector<script_file> scripts;
    std::vector<std::string> lua_fake_returns;      // fake<L> results set from Lua in this test
    std::vector<std::string> script_errors;         // modules folder problems, reported per file
    std::map<std::string, std::string> chunk_files; // chunk name -> file (relative) for coverage

    // The state of the test running now.
    steady::time_point clock{}; // the fake script clock
    struct clock_command {
        enum class kind : std::uint8_t {
            kNone,
            kAdvance,
            kFrames
        } what = kind::kNone;
        double ms = 0;
        std::uint64_t frames = 0;
        double dt = 0;
    } pending_command;
    std::vector<std::string> output;
    std::vector<value> emitted;
    std::vector<value> failures;
    std::map<request_id, result<value_list>> finished;
    snapshot_store* snapshots = nullptr;
    std::string current_file;
    std::vector<std::string> run_notes;

    // Coverage and profile of the whole run.
    std::map<std::string, std::map<std::uint32_t, std::uint64_t>> coverage_hits; // file -> line -> hits
    std::map<std::string, std::set<std::uint32_t>> coverage_lines;               // file -> executable lines
    std::map<std::string, std::uint64_t> profile;                                // stack -> samples

    impl(run_options o, install_fn i) : options(std::move(o)), install(std::move(i)) {
        std::error_code ec;
        root = options.root.empty() ? fs::current_path(ec) : options.root;
        seed = options.seed ? *options.seed : static_cast<std::uint64_t>(std::chrono::system_clock::now().time_since_epoch().count()) % 1'000'000'000ull;
        load_scripts();
    }

    std::string relative(const fs::path& p) const {
        std::error_code ec;
        const fs::path rel = fs::relative(p, root, ec);
        if (ec || rel.empty() || rel.generic_string().starts_with("..")) {
            return generic(p);
        }
        return generic(rel);
    }

    void load_scripts() {
        for (const fs::path& dir : options.scripts) {
            std::error_code ec;
            if (!fs::is_directory(dir, ec)) {
                script_errors.push_back(std::format("scripts folder '{}' doesn't exist", generic(dir)));
                continue;
            }
            std::vector<fs::path> found;
            for (fs::recursive_directory_iterator it{dir, ec}, end; !ec && it != end; it.increment(ec)) {
                if (it->is_regular_file() && it->path().extension() == ".lua" && !is_test_file(it->path())) {
                    found.push_back(it->path());
                }
            }
            std::ranges::sort(found);
            for (const fs::path& p : found) {
                const auto name = module_name(fs::relative(p, dir, ec));
                if (!name) {
                    script_errors.push_back(std::format("'{}' isn't a module name (dotted lowercase): rename it or move it out of the scripts folder", generic(p)));
                    continue;
                }
                std::optional<error> failure;
                std::string source = read_text(p, failure);
                if (failure) {
                    script_errors.push_back(std::format("can't read '{}': {}", generic(p), failure->message));
                    continue;
                }
                chunk_files[*name] = relative(p);
                scripts.push_back(script_file{*name, p, std::move(source), {}});
            }
        }
    }

    std::vector<fs::path> test_files() const {
        std::vector<fs::path> out;
        for (const fs::path& p : options.tests) {
            std::error_code ec;
            if (fs::is_directory(p, ec)) {
                std::vector<fs::path> found;
                for (fs::recursive_directory_iterator it{p, ec}, end; !ec && it != end; it.increment(ec)) {
                    if (it->is_regular_file() && is_test_file(it->path())) {
                        found.push_back(it->path());
                    }
                }
                std::ranges::sort(found);
                out.insert(out.end(), found.begin(), found.end());
            } else {
                out.push_back(p);
            }
        }
        return out;
    }

    // ---- the sandbox of a test file ----

    // `warnings`: problems of the module folders (a file that isn't a module, a module that doesn't
    // load); reported, but the file's tests still run (one that needs the module fails itself).
    std::unique_ptr<sandbox> make_sandbox(std::vector<file_error>& errors, std::vector<file_error>& warnings) {
        script::sandbox_options so;
        so.caller_role = options.caller;
        so.limits = options.limits;
        if (so.limits.wall_ms == 0) {
            // A test that never yields (an endless loop) is stopped by the limit: the runner's own
            // timeout is only checked between pumps.
            so.limits.wall_ms = static_cast<std::uint32_t>(std::clamp<std::int64_t>(options.timeout.count(), 1, (std::numeric_limits<std::uint32_t>::max)()));
        }
        so.identity = "test";
        so.clock = [this] { return clock; };
        so.on_output = [this](request_id, module_id, std::string_view line) { output.emplace_back(line); };
        so.on_emit = [this](request_id, module_id, const value& v) { emitted.push_back(v); };
        so.on_result = [this](request_id id, const result<value_list>& r) { finished.insert_or_assign(id, r); };
        so.on_handler_error = [this](const script::handler_failure& f) {
            failures.push_back(object{}
                                   .set("module", value{f.module_name})
                                   .set("kind", value{std::string{script::to_string(f.kind)}})
                                   .set("source", value{f.source})
                                   .set("code", value{std::string{to_string(f.err.code)}})
                                   .set("message", value{f.err.message})
                                   .set("where", value{f.err.where})
                                   .done());
        };
        auto box = std::make_unique<sandbox>(std::move(so));
        if (install) {
            try {
                if (auto installed = install(*box); !installed) {
                    errors.push_back(file_error{std::format("installing the API failed: {}", installed.error()), current_file, 0, {}});
                }
            } catch (const std::exception& e) {
                errors.push_back(file_error{std::format("installing the API failed: {}", e.what()), current_file, 0, {}});
            }
        }
        script::testing_options to;
        to.host = [this](std::string_view command, std::span<const value> args) { return host(command, args); };
        to.fake_os_epoch = options.epoch;
        if (auto enabled = box->enable_testing(std::move(to)); !enabled) {
            errors.push_back(file_error{std::format("can't enable testing: {}", enabled.error()), current_file, 0, {}});
            return box;
        }
        if (!options.coverage.empty()) {
            (void)box->start_coverage();
        }
        for (const detail::lua_source& part : detail::framework_sources()) {
            if (auto ran = box->exec_cached(part.text, part.name); !ran) {
                errors.push_back(file_error{std::format("the test framework didn't load ({}): {}", part.name, ran.error()), current_file, 0, ran.error().traceback});
                return box;
            }
        }
        if (auto configured = box->exec("__rhp_t.configure(__rhp_test.host('config'))", "rhp.test/configure"); !configured) {
            errors.push_back(file_error{std::format("configuring the framework failed: {}", configured.error()), current_file, 0, {}});
        }
        if (options.api) {
            const std::string strict = options.strict_fakes ? "true" : "false";
            if (auto faked = box->exec(std::format("__rhp_t.install_fakes(__rhp_test.host('api'), {{strict = {}}})", strict), "rhp.test/fakes"); !faked) {
                errors.push_back(file_error{std::format("building fakes from the API description failed: {}", faked.error()), current_file, 0, {}});
            }
        }
        load_modules(*box, warnings);
        box->start_metering();
        return box;
    }

    // Loads a module of the scripts folder. Its bytecode is compiled once, in the first sandbox, and
    // every later sandbox (one per file, or per test with --isolation test) loads that instead of
    // parsing the source again: in-process and made here, so it is trusted as is.
    static auto load_script(sandbox& box, const script_file& s) {
        if (s.bytecode.empty()) {
            if (auto code = box.compile_module(s.module, s.source)) {
                s.bytecode = std::move(*code);
            }
        }
        return s.bytecode.empty() ? box.load(s.module, s.source) : box.load(s.module, s.source, script::trusted_bytecode{s.bytecode});
    }

    void load_modules(sandbox& box, std::vector<file_error>& errors) {
        for (const std::string& e : script_errors) {
            errors.push_back(file_error{e, current_file, 0, {}});
        }
        // In rounds: a module whose require()s aren't loaded yet waits for the next round.
        std::vector<const script_file*> left;
        for (const script_file& s : scripts) {
            left.push_back(&s);
        }
        while (!left.empty()) {
            std::vector<const script_file*> later;
            std::vector<std::pair<const script_file*, error>> failed;
            for (const script_file* s : left) {
                auto loaded = load_script(box, *s);
                if (loaded) {
                    continue;
                }
                const error& e = loaded.error();
                if (waits_for_require(e)) {
                    later.push_back(s);
                    if (auto id = box.find(s->module)) {
                        (void)box.unload(*id, script::force);
                    }
                } else {
                    failed.emplace_back(s, e);
                }
            }
            for (const auto& [s, e] : failed) {
                errors.push_back(file_error{std::format("module {} didn't load: {}", s->module, e), relative(s->path), 0, e.traceback});
            }
            if (later.size() == left.size()) {
                for (const script_file* s : later) {
                    if (auto again = load_script(box, *s); !again) {
                        const bool waiting = waits_for_require(again.error());
                        errors.push_back(file_error{std::format("module {} didn't load: {}", s->module, waiting ? std::string{"a require() cycle, or a module that doesn't exist"} : std::format("{}", again.error())), relative(s->path), 0, {}});
                    }
                }
                break;
            }
            left = std::move(later);
        }
    }

    // ---- requests and the clock ----

    void pump(sandbox& box, std::uint64_t& frames) {
        box.pump();
        ++frames;
    }

    // Runs `source` as a request and drives the clock until it ends; the request's values or error.
    result<value_list> run_request(sandbox& box, std::string_view source, std::string_view chunk, std::uint64_t& frames, bool& timed_out) {
        pending_command = clock_command{};
        auto first = box.exec(source, chunk);
        const request_id id = box.last_request();
        if (!box.pending(id)) {
            if (first && first->empty() && !finished.contains(id)) {
                // It suspended and was then ended before exec returned (a fault, a cancel): its
                // outcome is delivered by the next pump.
                box.pump();
                if (const auto it = finished.find(id); it != finished.end()) {
                    result<value_list> out = std::move(it->second);
                    finished.erase(it);
                    return out;
                }
            }
            return first;
        }
        const auto started = steady::now();
        std::uint64_t idle = 0;
        auto idle_since = started;
        while (box.pending(id)) {
            if (steady::now() - started > options.timeout || frames > options.max_frames) {
                timed_out = true;
                box.cancel(id);
                box.pump();
                break;
            }
            const clock_command cmd = std::exchange(pending_command, clock_command{});
            switch (cmd.what) {
            case clock_command::kind::kAdvance: {
                const steady::time_point target = clock + std::chrono::duration_cast<steady::duration>(std::chrono::duration<double, std::milli>{cmd.ms});
                bool moved_on = false; // the test resumed and asked for something else, or ended
                while (true) {
                    const auto due = box.next_due();
                    if (!due || *due > target) {
                        break;
                    }
                    clock = std::max(clock, *due);
                    pump(box, frames);
                    if (!box.pending(id) || pending_command.what != clock_command::kind::kNone) {
                        moved_on = true;
                        break;
                    }
                    if (frames > options.max_frames) {
                        break;
                    }
                }
                clock = std::max(clock, target);
                if (!moved_on) {
                    pump(box, frames);
                }
                idle = 0;
                break;
            }
            case clock_command::kind::kFrames: {
                const auto dt = std::chrono::duration_cast<steady::duration>(std::chrono::duration<double, std::milli>{cmd.dt});
                for (std::uint64_t i = 0; i < cmd.frames && box.pending(id) && pending_command.what == clock_command::kind::kNone; ++i) {
                    clock += dt;
                    pump(box, frames);
                }
                idle = 0;
                break;
            }
            case clock_command::kind::kNone: {
                // The test waits on its own (an event, an asynchronous result, rhp.sleep): pump, and
                // when nothing else can move it, jump the clock to the next due time.
                pump(box, frames);
                if (!box.pending(id) || pending_command.what != clock_command::kind::kNone) {
                    break;
                }
                if (const auto due = box.next_due(); due && *due > clock) {
                    clock = *due;
                    idle = 0;
                } else if (const script::sandbox_stats st = box.stats();
                           st.queued_events != 0 || st.schedule_entries != 0 || st.tasks != 0 || (st.waiting == 0 && st.async_waiting == 0)) {
                    idle = 0; // something may still wake it, or it waits on frames (--max-frames)
                } else if (idle++ == 0) {
                    idle_since = steady::now();
                } else if (idle > 100 && steady::now() - idle_since > std::chrono::seconds{1}) {
                    // A second of pumps with nothing that could wake it (an asynchronous binding
                    // completing on another thread gets that second).
                    timed_out = true;
                    box.cancel(id);
                    box.pump();
                    finished.insert_or_assign(id, fail(errc::kTimeout, "the test waits for something nothing will do (an event, an asynchronous result, a frame count) and the clock has nothing left to run", "test"));
                }
                break;
            }
            }
        }
        const auto too_long = [&] {
            return fail(errc::kTimeout, std::format("the test didn't finish in {} ms of real time or {} frames", options.timeout.count(), options.max_frames), "test");
        };
        const auto it = finished.find(id);
        if (it == finished.end()) {
            return too_long();
        }
        result<value_list> out = std::move(it->second);
        finished.erase(it);
        if (timed_out && (out || out.error().code == errc::kCancelled)) {
            return too_long();
        }
        return out;
    }

    // ---- the framework's services ----

    result<value> host(std::string_view command, std::span<const value> args) {
        const auto arg_number = [&](std::size_t i) { return i < args.size() ? as_number(args[i]) : 0.0; };
        const auto arg_text = [&](std::size_t i) -> std::string {
            if (i < args.size()) {
                if (const auto* s = args[i].get_if<std::string>()) {
                    return *s;
                }
            }
            return {};
        };
        if (command == "advance") {
            const double ms = arg_number(0);
            if (!std::isfinite(ms) || ms < 0 || ms > 1e12) {
                return fail(errc::kInvalidArgument, std::format("test.advance: {} ms isn't a time to advance by", ms), "test");
            }
            pending_command = clock_command{clock_command::kind::kAdvance, ms, 0, 0};
            return value{};
        }
        if (command == "frames") {
            const double n = arg_number(0);
            const double dt = arg_number(1);
            if (!std::isfinite(n) || n < 1 || !std::isfinite(dt) || dt < 0 || dt > 1e9) {
                return fail(errc::kInvalidArgument, std::format("test.frames: {} frames of {} ms isn't a frame count", n, dt), "test");
            }
            const auto count = static_cast<std::uint64_t>(std::min(n, static_cast<double>(options.max_frames) + 1));
            pending_command = clock_command{clock_command::kind::kFrames, 0, count, dt};
            return value{};
        }
        if (command == "config") {
            object o;
            o.set("seed", value{static_cast<std::int64_t>(seed)}).set("property_runs", value{static_cast<std::int64_t>(options.property_runs)});
            if (options.fuzz_ms) {
                o.set("fuzz_ms", value{static_cast<std::int64_t>(*options.fuzz_ms)});
            }
            return o.done();
        }
        if (command == "output") {
            value::array lines;
            for (const std::string& l : output) {
                lines.emplace_back(l);
            }
            return value{std::move(lines)};
        }
        if (command == "emitted") {
            return value{value::array{emitted.begin(), emitted.end()}};
        }
        if (command == "failures") {
            return value{value::array{failures.begin(), failures.end()}};
        }
        if (command == "snapshot") {
            return snapshot(arg_text(0), arg_text(1));
        }
        if (command == "corpus_load") {
            return corpus_load(arg_text(0));
        }
        if (command == "corpus_save") {
            return corpus_save(arg_text(0), arg_text(1), arg_text(2));
        }
        if (command == "api") {
            return options.api ? *options.api : value{value::map{}};
        }
        if (command == "fake_calls") {
            value::array out;
            for (const auto& call : fake_registry::instance().calls(arg_text(0))) {
                out.emplace_back(value::array{call.begin(), call.end()});
            }
            return value{std::move(out)};
        }
        if (command == "fake_returns") {
            lua_fake_returns.push_back(arg_text(0));
            fake_registry::instance().set_returns(arg_text(0), std::vector<value>{args.begin() + (args.empty() ? 0 : 1), args.end()});
            return value{};
        }
        if (command == "fake_reset") {
            fake_registry::instance().reset(arg_text(0));
            return value{};
        }
        return fail(errc::kNotFound, std::format("the runner has no service '{}'", command));
    }

    // Snapshots of the current file: __snapshots__/<file name>.snap.lua next to it, a Lua chunk
    // returning {[key] = text}. Read with a sandbox of its own.
    void load_snapshots(snapshot_store& store) {
        store.loaded = true;
        std::error_code ec;
        if (!fs::exists(store.path, ec)) {
            return;
        }
        std::optional<error> failure;
        const std::string source = read_text(store.path, failure);
        if (failure) {
            store.broken = std::format("can't read {}: {}", generic(store.path), failure->message);
            return;
        }
        script::sandbox_options reader_options{.caller_role = role::kObserve, .output = [](std::string_view) {}};
        reader_options.limits.instructions = 100'000'000; // a corrupted file can't hang the run
        reader_options.limits.wall_ms = 10'000;
        sandbox reader{std::move(reader_options)};
        auto values = reader.exec(source, generic(store.path));
        const auto* as_array = values && !values->empty() ? values->front().get_if<value::array>() : nullptr;
        if (as_array != nullptr && as_array->empty()) {
            return; // `return {}`: no snapshots left
        }
        if (!values || values->empty() || values->front().get_if<value::map>() == nullptr) {
            store.broken = std::format("{} isn't a snapshot file (fix or delete it): {}", generic(store.path),
                                       !values ? std::format("{}", values.error()) : std::string{"it doesn't return a table"});
            return;
        }
        if (const auto* m = values->front().get_if<value::map>()) {
            for (const auto& [k, v] : *m) {
                const auto* key = k.get_if<std::string>();
                const auto* text = v.get_if<std::string>();
                if (key != nullptr && text != nullptr) {
                    store.stored[*key] = *text;
                }
            }
        }
    }

    value snapshot(const std::string& key, const std::string& text) {
        if (snapshots == nullptr) {
            return object{}.set("status", value{"missing"}).done();
        }
        snapshot_store& store = *snapshots;
        if (!store.loaded) {
            load_snapshots(store);
        }
        if (!store.broken.empty()) {
            return object{}.set("status", value{"broken"}).set("message", value{store.broken}).done();
        }
        if (const auto seen = store.written.find(key); seen != store.written.end() && seen->second != text) {
            return object{}
                .set("status", value{"broken"})
                .set("message", value{std::format("two snapshots are named '{}' in this run (tests with the same full name? name them: assert.snapshot(v, 'name'))", key)})
                .done();
        }
        store.written[key] = text;
        const auto it = store.stored.find(key);
        if (it == store.stored.end()) {
            if (options.ci && !options.update_snapshots) {
                return object{}.set("status", value{"missing"}).done();
            }
            store.dirty = true;
            return object{}.set("status", value{"new"}).done();
        }
        if (it->second == text) {
            return object{}.set("status", value{"match"}).done();
        }
        if (options.update_snapshots) {
            store.dirty = true;
            return object{}.set("status", value{"updated"}).done();
        }
        return object{}.set("status", value{"mismatch"}).set("stored", value{it->second}).done();
    }

    void save_snapshots(snapshot_store& store) {
        if (!store.loaded || !store.broken.empty()) {
            return;
        }
        // Keys no test checked are obsolete: kept, or dropped with --update-snapshots.
        std::map<std::string, std::string> out = store.written;
        std::size_t obsolete = 0;
        for (const auto& [k, v] : store.stored) {
            if (!store.written.contains(k)) {
                if (options.update_snapshots) {
                    store.dirty = true;
                } else {
                    out.emplace(k, v);
                }
                ++obsolete;
            } else if (!options.update_snapshots && store.written.at(k) != v) {
                out[k] = v; // a mismatch keeps the stored value
            }
        }
        if (obsolete != 0 && !options.update_snapshots) {
            run_notes.push_back(std::format("{}: {} snapshot(s) no test checked (obsolete: --update-snapshots removes them)", relative(store.path), obsolete));
        }
        if (!store.dirty) {
            return;
        }
        std::string text = std::format("-- Snapshots of {} (Rhp::test). Review changes to it like code.\nreturn {{\n", current_file);
        for (const auto& [k, v] : out) {
            text += std::format("  [{}] = {},\n", lua_quoted(k), long_bracket(v));
        }
        text += "}\n";
        if (auto written = write_text(store.path, text); !written) {
            run_notes.push_back(std::format("can't write {}: {}", relative(store.path), written.error()));
        }
    }

    fs::path corpus_dir(const std::string& name) const {
        std::string safe;
        for (const char c : name) {
            safe += (std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '-' || c == '_') ? c : '_';
        }
        if (safe.size() > 70) {
            safe.resize(70);
        }
        // The hash of the exact name: "a+b" and "a b", or names differing only in case, don't share inputs.
        safe = std::format("{}_{:08x}", safe, utils::crc32c(utils::as_bytes(name)));
        const fs::path file{current_file};
        return root / file.parent_path() / "__fuzz__" / file.stem() / safe;
    }

    value corpus_load(const std::string& name) {
        value::array out;
        std::error_code ec;
        const fs::path dir = corpus_dir(name);
        if (!fs::is_directory(dir, ec)) {
            return value{std::move(out)};
        }
        std::vector<fs::path> files;
        for (fs::directory_iterator it{dir, ec}, end; !ec && it != end; it.increment(ec)) {
            if (it->is_regular_file() && it->path().extension() == ".lua") {
                files.push_back(it->path());
            }
        }
        std::ranges::sort(files);
        for (const fs::path& p : files) {
            std::optional<error> failure;
            std::string text = read_text(p, failure);
            if (!failure) {
                out.emplace_back(std::move(text));
            }
        }
        return value{std::move(out)};
    }

    value corpus_save(const std::string& name, const std::string& text, const std::string& kind) {
        const std::uint32_t hash = utils::crc32c(utils::as_bytes(text));
        const std::string_view what = kind == "crash" || kind == "cov" ? std::string_view{kind} : std::string_view{"input"};
        const fs::path path = corpus_dir(name) / std::format("{}-{:08x}.lua", what, hash);
        std::error_code ec;
        if (!fs::exists(path, ec)) {
            if (auto written = write_text(path, text); !written) {
                run_notes.push_back(std::format("can't save a fuzz input to {}: {}", generic(path), written.error()));
            }
        }
        return value{generic(path)};
    }

    // ---- coverage ----

    void merge_coverage(const script::coverage_report& report, const std::string& test_file) {
        for (const script::coverage_chunk& c : report.chunks) {
            std::string file;
            if (const auto it = chunk_files.find(c.chunk); it != chunk_files.end()) {
                file = it->second;
            } else if (options.coverage_tests && c.chunk == test_file) {
                file = test_file;
            } else {
                continue; // the framework, exec chunks
            }
            auto& lines = coverage_lines[file];
            auto& hits = coverage_hits[file];
            for (std::size_t i = 0; i < c.lines.size(); ++i) {
                lines.insert(c.lines[i]);
                hits[c.lines[i]] += c.hits[i];
            }
        }
    }

    std::vector<file_coverage> coverage_result() const {
        std::vector<file_coverage> out;
        for (const auto& [file, lines] : coverage_lines) {
            std::set<std::uint32_t> skip;
            std::optional<error> failure;
            const std::string source = read_text(root / file, failure);
            if (!failure) {
                skip = excluded_lines(source);
            }
            file_coverage fc;
            fc.file = file;
            const auto& hits = coverage_hits.at(file);
            for (const std::uint32_t line : lines) {
                if (skip.contains(line)) {
                    continue;
                }
                fc.lines.push_back(line);
                const auto h = hits.find(line);
                fc.hits.push_back(h != hits.end() ? h->second : 0);
            }
            out.push_back(std::move(fc));
        }
        return out;
    }

    // ---- one file ----

    struct listed {
        std::uint64_t id = 0;
        test_info info;
        bool only = false;
    };

    std::vector<listed> list_tests(sandbox& box, std::vector<file_error>& errors) {
        std::vector<listed> out;
        auto r = box.exec("return __rhp_t.list()", "rhp.test/list");
        if (!r || r->empty()) {
            errors.push_back(file_error{std::format("listing the tests failed: {}", r ? std::string{"no answer"} : std::format("{}", r.error())), current_file, 0, {}});
            return out;
        }
        const value& listing = r->front();
        if (const auto* list = array_of(listing, "tests")) {
            for (const value& t : *list) {
                listed l;
                l.id = static_cast<std::uint64_t>(int_of(t, "id"));
                l.info.id = l.id;
                l.info.name = text_of(t, "name");
                l.info.file = current_file;
                l.info.line = static_cast<std::uint32_t>(int_of(t, "line"));
                l.info.tags = strings_of(t, "tags");
                l.info.skipped = bool_of(t, "skip");
                l.info.pending = bool_of(t, "pending");
                l.only = bool_of(t, "only");
                out.push_back(std::move(l));
            }
        }
        if (const auto* list = array_of(listing, "errors")) {
            for (const value& e : *list) {
                errors.push_back(file_error_of(e));
            }
        }
        return out;
    }

    bool selected(const test_info& t) const {
        for (const std::string& f : options.filters_out) {
            if (name_matches(t.name, f)) {
                return false;
            }
        }
        if (!options.filters.empty() && std::ranges::none_of(options.filters, [&](const std::string& f) { return name_matches(t.name, f); })) {
            return false;
        }
        const auto has_tag = [&](const std::string& tag) { return std::ranges::find(t.tags, tag) != t.tags.end(); };
        if (std::ranges::any_of(options.exclude_tags, has_tag)) {
            return false;
        }
        if (!options.tags.empty() && std::ranges::none_of(options.tags, has_tag)) {
            return false;
        }
        return true;
    }

    // The selected tests of a file in running order (.only applies within the file).
    std::vector<listed> selection(std::vector<listed> all) const {
        const bool any_only = std::ranges::any_of(all, [](const listed& l) { return l.only; });
        std::vector<listed> out;
        for (listed& l : all) {
            if (!selected(l.info)) {
                continue;
            }
            if (any_only && !l.only) {
                l.info.skipped = true;
            }
            out.push_back(std::move(l));
        }
        if (options.shuffle) {
            // Fisher-Yates over splitmix64: the same order for a seed with every standard library.
            std::uint64_t state = seed ^ utils::crc32c(utils::as_bytes(current_file));
            const auto next = [&state] {
                std::uint64_t z = (state += 0x9E3779B97F4A7C15ull);
                z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
                z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
                return z ^ (z >> 31);
            };
            for (std::size_t i = out.size(); i > 1; --i) {
                std::swap(out[i - 1], out[static_cast<std::size_t>(next() % i)]);
            }
        }
        return out;
    }

    // Loads a file into a fresh sandbox: the API, the framework, the modules, then the file itself.
    std::unique_ptr<sandbox> open_file(const std::string& source, std::vector<file_error>& errors, std::vector<file_error>& warnings) {
        auto box = make_sandbox(errors, warnings);
        if (!errors.empty()) {
            return box;
        }
        if (auto ran = box->exec_cached(source, current_file); !ran) { // with --isolation test it runs once per test
            const error& e = ran.error();
            errors.push_back(file_error{std::format("the test file failed to load: {}", e), current_file, 0, e.traceback});
        }
        return box;
    }

    struct opened_file {
        std::unique_ptr<sandbox> box;
        std::vector<listed> tests; // selected, in running order
    };

    // open_file, then the selected tests of a file that loaded. The module folders' warnings come after
    // the file's own errors.
    opened_file open_listed(const std::string& source, std::vector<file_error>& errors) {
        opened_file out;
        std::vector<file_error> warnings;
        out.box = open_file(source, errors, warnings);
        if (errors.empty()) {
            out.tests = selection(list_tests(*out.box, errors));
        }
        errors.insert(errors.end(), warnings.begin(), warnings.end());
        return out;
    }

    // What a test's checkpoint saw: the counts its revert must bring back, and the meter at its start.
    struct test_baseline {
        script::sandbox_stats stats{};
        std::size_t effects = 0;
        std::vector<script::tunable_info> vars;
        script::run_meter meter{};
    };

    // Before a test (after the setup of its blocks): the fakes' calls and Lua-set results go, then the
    // checkpoint and what it must come back to, a collection, the meter's start and the profiler.
    test_baseline begin_test(sandbox& box) {
        // fake<L>: calls and the results a test set from Lua belong to that test (results set from C++
        // before the run stay).
        fake_registry::instance().clear_calls();
        for (const std::string& path : std::exchange(lua_fake_returns, {})) {
            fake_registry::instance().reset(path);
        }
        (void)box.checkpoint("rhp.test");
        test_baseline before;
        before.stats = box.stats();
        before.effects = box.effects().size();
        if (auto vars = box.tunables()) {
            before.vars = std::move(*vars);
        }
        if (options.measure) {
            (void)box.collect_garbage(1);
        }
        box.reset_peak();
        before.meter = box.meter();
        if (options.profile) {
            (void)box.start_profile({.interval = options.profile_interval});
        }
        return before;
    }

    // What the test's request cost, from the meter at its start (`m0`).
    void collect_cost(sandbox& box, const script::run_meter& m0, std::uint64_t frames, test_result& r) {
        const script::run_meter m1 = box.meter();
        if (options.profile) {
            const script::profile_report p = box.stop_profile();
            r.profile = p.stacks;
            for (const auto& s : p.stacks) {
                profile[s.stack] += s.samples;
            }
        }
        if (options.measure) {
            (void)box.collect_garbage(1);
        }
        const script::run_meter m2 = box.meter();
        r.cost.instructions = m1.instructions - m0.instructions;
        r.cost.time_ms = std::chrono::duration<double, std::milli>{m1.active - m0.active}.count();
        r.cost.allocations = m1.allocations - m0.allocations;
        r.cost.bytes = m1.bytes_allocated - m0.bytes_allocated;
        r.cost.peak = m1.peak > m0.memory ? m1.peak - m0.memory : 0;
        r.cost.retained = options.measure ? static_cast<std::int64_t>(m2.memory) - static_cast<std::int64_t>(m0.memory) : 0;
        for (std::size_t i = 0; i < script::kAllocKinds; ++i) {
            r.cost.objects[i] = m1.objects[i] - m0.objects[i];
        }
        r.cost.frames = frames;
        r.output = output;
    }

    // A budget the test set: a passing test over it fails.
    static void apply_budget(const value& budget, test_result& r) {
        std::vector<std::string> over;
        const auto limit = [&](std::string_view key, double actual) {
            const value* l = field(budget, key);
            if (l == nullptr) {
                return;
            }
            const double max = number_of(budget, key);
            if (actual > max) {
                over.push_back(std::format("{} {} > {}", key, actual, max));
            }
        };
        limit("instructions", static_cast<double>(r.cost.instructions));
        limit("memory", static_cast<double>(r.cost.peak));
        limit("peak", static_cast<double>(r.cost.peak));
        limit("allocations", static_cast<double>(r.cost.allocations));
        limit("bytes", static_cast<double>(r.cost.bytes));
        limit("retained", static_cast<double>(r.cost.retained));
        limit("time_ms", r.cost.time_ms);
        if (!over.empty() && r.outcome == status::kPassed) {
            r.outcome = status::kFailed;
            r.message = std::format("over budget: {}", join(over, ", "));
        }
    }

    // The test's own outcome, from what __rhp_t.run returned.
    static void read_outcome(const result<value_list>& ran, test_result& r) {
        if (!ran) {
            r.outcome = status::kError;
            r.message = std::format("{}", ran.error());
            user_trace trace = user_traceback(ran.error().traceback);
            r.traceback = std::move(trace.text);
            r.fail_file = std::move(trace.file);
            r.fail_line = trace.line;
        } else if (ran->empty()) {
            r.outcome = status::kError;
            r.message = "the test returned no result";
        } else {
            const value& v = ran->front();
            const std::string s = text_of(v, "status");
            r.outcome = s == "passed" ? status::kPassed : s == "failed" ? status::kFailed
                                                      : s == "pending"  ? status::kPending
                                                                        : status::kError;
            r.message = text_of(v, "message");
            r.fail_file = text_of(v, "source");
            r.fail_line = static_cast<std::uint32_t>(int_of(v, "line"));
            r.traceback = text_of(v, "traceback");
            if (const value* e = field(v, "expected"); e != nullptr && e->get_if<std::string>() != nullptr) {
                r.expected = *e->get_if<std::string>();
            }
            if (const value* a = field(v, "actual"); a != nullptr && a->get_if<std::string>() != nullptr) {
                r.actual = *a->get_if<std::string>();
            }
            r.assertions = static_cast<std::uint64_t>(int_of(v, "assertions"));
            if (const auto* list = array_of(v, "measures")) {
                for (const value& m : *list) {
                    r.measures.push_back(measure{text_of(m, "name"), static_cast<std::uint64_t>(int_of(m, "instructions")),
                                                 static_cast<std::uint64_t>(int_of(m, "allocations")), static_cast<std::uint64_t>(int_of(m, "bytes")),
                                                 int_of(m, "peak"), int_of(m, "retained"), number_of(m, "time_ms")});
                }
            }
            if (const auto* list = array_of(v, "benches")) {
                for (const value& b : *list) {
                    const auto line = [&](std::string_view key) {
                        const value* s2 = field(b, key);
                        if (s2 == nullptr) {
                            return stats_line{};
                        }
                        return stats_line{number_of(*s2, "min"), number_of(*s2, "max"), number_of(*s2, "mean"), number_of(*s2, "median"), number_of(*s2, "stddev")};
                    };
                    r.benches.push_back(bench{text_of(b, "name"), static_cast<std::uint32_t>(int_of(b, "runs")), line("instructions"), line("time_ms"), line("bytes"), line("allocations")});
                }
            }
            // A budget the test set (test.budget or it(..., {budget = ...})).
            if (const value* budget = field(v, "budget"); budget != nullptr && budget->get_if<value::map>() != nullptr) {
                apply_budget(*budget, r);
            }
            note_globals(v, r.notes);
            if (bool_of(v, "strict_undo")) {
                r.notes.emplace_back("strict-undo");
            }
        }
    }

    // A test stopped by a limit, a timeout or a cancel never ran its cleanup: finally, after_each and
    // the removal of its globals run now, in a request of their own.
    void run_abort(sandbox& box, test_result& r) {
        std::uint64_t abort_frames = 0;
        bool abort_timed_out = false;
        auto aborted = run_request(box, "return __rhp_t.abort()", "rhp.test/abort", abort_frames, abort_timed_out);
        if (!aborted) {
            r.notes.push_back(std::format("its cleanup failed too: {}", aborted.error()));
        } else if (!aborted->empty()) {
            note_globals(aborted->front(), r.notes);
            if (const auto* errs = array_of(aborted->front(), "errors")) {
                for (const value& e : *errs) {
                    if (const auto* text = e.get_if<std::string>()) {
                        r.notes.push_back(std::format("its cleanup failed: {}", *text));
                    }
                }
            }
        }
    }

    // Undoes the test and checks that everything it did is gone: a leak fails a passing test.
    void check_leaks(sandbox& box, const test_baseline& before, test_result& r) {
        const bool strict = options.strict_undo || std::ranges::find(r.notes, std::string{"strict-undo"}) != r.notes.end();
        std::erase(r.notes, std::string{"strict-undo"});
        auto undone = box.revert_to("rhp.test");
        std::vector<std::string> leaks;
        if (!undone) {
            leaks.push_back(std::format("reverting the test failed: {}", undone.error()));
        } else {
            for (const error& f : undone->failures) {
                leaks.push_back(std::format("an undo failed: {}", f));
            }
            if (undone->irreversible != 0) {
                const std::string text = std::format("{} irreversible effect(s) stay (bindings marked Rhp::irreversible)", undone->irreversible);
                if (strict) {
                    leaks.push_back(text);
                } else {
                    r.notes.push_back(text);
                }
            }
        }
        const script::sandbox_stats after_stats = box.stats();
        const auto compare = [&](std::size_t had, std::size_t has, std::string_view what) {
            if (has > had) {
                leaks.push_back(std::format("{} {} left after the test was undone", has - had, what));
            }
        };
        compare(before.stats.schedule_entries, after_stats.schedule_entries, "timer(s) or frame callback(s)");
        compare(before.stats.subscriptions, after_stats.subscriptions, "subscription(s)");
        compare(before.stats.tasks, after_stats.tasks, "task(s)");
        compare(before.stats.waiting, after_stats.waiting, "waiting request(s)");
        compare(before.effects, box.effects().size(), "ledger effect(s)");
        if (auto vars = box.tunables()) {
            for (const script::tunable_info& now : *vars) {
                const auto was = std::ranges::find(before.vars, now.path, &script::tunable_info::path);
                if (was != before.vars.end() && was->current != now.current) {
                    leaks.push_back(std::format("{} is still changed after the test was undone", now.path));
                }
            }
        }
        if (!leaks.empty() && (r.outcome == status::kPassed || r.outcome == status::kPending)) {
            r.outcome = status::kError;
            r.message = std::format("not everything the test did was undone: {}", join(leaks, "; "));
        } else if (!leaks.empty()) {
            for (std::string& l : leaks) {
                r.notes.push_back(std::move(l));
            }
        }
    }

    test_result run_one(sandbox& box, const listed& t, std::uint32_t repeat, reporter& out) {
        test_result r;
        r.id = t.id;
        r.name = t.info.name;
        r.file = current_file;
        r.line = t.info.line;
        r.tags = t.info.tags;
        r.repeat = repeat;
        if (t.info.skipped) {
            r.outcome = status::kSkipped;
            return r;
        }
        out.test_started(t.info);
        output.clear();
        emitted.clear();
        failures.clear();
        std::uint64_t frames = 0;
        bool timed_out = false;
        const auto started = steady::now();

        // Setup of the blocks above it (lasts for the file: outside the test's checkpoint).
        auto prepared = run_request(box, std::format("return __rhp_t.prepare({})", t.id), "rhp.test/prepare", frames, timed_out);
        if (!prepared || prepared->empty() || !bool_of(prepared->front(), "ok")) {
            r.outcome = status::kError;
            if (!prepared) {
                r.message = std::format("setup failed: {}", prepared.error());
            } else if (!prepared->empty()) {
                r.message = text_of(prepared->front(), "message");
                r.fail_file = text_of(prepared->front(), "source");
                r.fail_line = static_cast<std::uint32_t>(int_of(prepared->front(), "line"));
                r.traceback = text_of(prepared->front(), "traceback");
            }
            r.where = where_of(r);
            return r;
        }

        const test_baseline before = begin_test(box);

        auto ran = run_request(box, std::format("return __rhp_t.run({})", t.id), "rhp.test/run", frames, timed_out);

        collect_cost(box, before.meter, frames, r);
        read_outcome(ran, r);
        if (!ran) {
            run_abort(box, r);
        }

        // Events the test published that are still queued reach their handlers now (within this
        // test, whose revert follows), not in the next test.
        for (int round = 0; round < 4 && box.stats().queued_events != 0; ++round) {
            pump(box, r.cost.frames);
        }

        check_leaks(box, before, r);
        if (timed_out && r.outcome == status::kPassed) {
            r.outcome = status::kError;
            r.message = "the test timed out";
        }
        r.cost.wall_ms = std::chrono::duration<double, std::milli>{steady::now() - started}.count();
        r.where = where_of(r);
        return r;
    }

    file_result run_file(const fs::path& path, reporter& out, bool& stop) {
        if constexpr (kLuaEnabled) {
            return run_lua_file(path, out, stop);
        } else {
            (void)stop;
            file_result fr;
            current_file = relative(path);
            fr.file = current_file;
            fr.errors.push_back(file_error{"this build has no Lua (RHP_ENABLE=OFF): Lua tests can't run", current_file, 0, {}});
            out.file_started(current_file, {});
            out.file_finished(fr);
            return fr;
        }
    }

    file_result run_lua_file(const fs::path& path, reporter& out, bool& stop) {
        file_result fr;
        current_file = relative(path);
        fr.file = current_file;
        const auto started = steady::now();
        std::optional<error> failure;
        const std::string source = read_text(path, failure);
        if (failure) {
            fr.errors.push_back(file_error{std::format("can't read the test file: {}", failure->message), current_file, 0, {}});
            out.file_started(current_file, {});
            out.file_finished(fr);
            return fr;
        }
        chunk_files.erase(current_file);
        snapshot_store store;
        store.path = path.parent_path() / "__snapshots__" / (path.stem().string() + ".snap.lua");
        snapshots = &store;

        auto [box, tests] = open_listed(source, fr.errors);
        std::vector<test_info> infos;
        for (const listed& l : tests) {
            infos.push_back(l.info);
        }
        out.file_started(current_file, infos);
        for (std::uint32_t round = 0; round < std::max<std::uint32_t>(options.repeat, 1) && !stop; ++round) {
            for (const listed& t : tests) {
                if (stop) {
                    break;
                }
                std::unique_ptr<sandbox> own;
                sandbox* use = box.get();
                if (options.share == isolation::kTest && !t.info.skipped) {
                    std::vector<file_error> errs;
                    std::vector<file_error> ignored; // the file's own sandbox reported them
                    own = open_file(source, errs, ignored);
                    if (!errs.empty()) {
                        fr.errors.insert(fr.errors.end(), errs.begin(), errs.end());
                        continue;
                    }
                    (void)list_tests(*own, errs);
                    use = own.get();
                }
                test_result r = run_one(*use, t, round, out);
                if (own) {
                    if (!options.coverage.empty()) {
                        merge_coverage(own->coverage(), current_file);
                    }
                    (void)own->exec("return __rhp_t.finish()", "rhp.test/finish");
                }
                out.test_finished(r);
                if (options.fail_fast && (r.outcome == status::kFailed || r.outcome == status::kError)) {
                    stop = true;
                }
                fr.tests.push_back(std::move(r));
            }
        }
        if (box && fr.errors.empty()) {
            std::uint64_t frames = 0;
            bool timed_out = false;
            auto finished_blocks = run_request(*box, "return __rhp_t.finish()", "rhp.test/finish", frames, timed_out);
            if (finished_blocks && !finished_blocks->empty()) {
                if (const auto* list = array_of(finished_blocks->front(), "errors")) {
                    for (const value& e : *list) {
                        fr.errors.push_back(file_error_of(e));
                    }
                }
            }
        }
        if (box && !options.coverage.empty() && options.share == isolation::kFile) {
            merge_coverage(box->coverage(), current_file);
        }
        save_snapshots(store);
        snapshots = nullptr;
        box.reset();
        fr.ms = std::chrono::duration<double, std::milli>{steady::now() - started}.count();
        out.file_finished(fr);
        return fr;
    }

    run_result run(reporter& out) {
        run_result rr;
        rr.seed = seed;
        const auto started = steady::now();
        // fake<L> libs are strict for this run when asked (and as they were afterwards).
        const bool was_strict = fake_registry::instance().strict();
        fake_registry::instance().set_strict(was_strict || options.strict_fakes);
        const utils::scope_guard restore{[was_strict]() noexcept { fake_registry::instance().set_strict(was_strict); }};
        const std::vector<fs::path> files = test_files();
        out.run_started(seed, files.size());
        bool stop = false;
        for (const fs::path& f : files) {
            if (stop) {
                break;
            }
            rr.files.push_back(run_file(f, out, stop));
        }
        for (const file_result& fr : rr.files) {
            rr.totals.file_errors += fr.errors.size();
            for (const test_result& t : fr.tests) {
                switch (t.outcome) {
                case status::kPassed: ++rr.totals.passed; break;
                case status::kFailed: ++rr.totals.failed; break;
                case status::kError: ++rr.totals.errors; break;
                case status::kPending: ++rr.totals.pending; break;
                case status::kSkipped: ++rr.totals.skipped; break;
                }
            }
        }
        if (!options.coverage.empty()) {
            rr.coverage = coverage_result();
        }
        for (const auto& [stack, samples] : profile) {
            rr.profile.push_back(script::profile_stack{stack, samples});
        }
        std::ranges::sort(rr.profile, [](const auto& a, const auto& b) { return a.samples > b.samples; });
        rr.notes = run_notes;
        rr.ms = std::chrono::duration<double, std::milli>{steady::now() - started}.count();
        out.run_finished(rr);
        return rr;
    }
};

runner::runner(run_options options, install_fn install) : impl_(std::make_unique<impl>(std::move(options), std::move(install))) {}
runner::~runner() = default;
runner::runner(runner&&) noexcept = default;
runner& runner::operator=(runner&&) noexcept = default;

run_result runner::run(reporter& out) {
    return impl_->run(out);
}

std::vector<std::pair<file_result, std::vector<test_info>>> runner::list() {
    std::vector<std::pair<file_result, std::vector<test_info>>> out;
    for (const fs::path& path : impl_->test_files()) {
        file_result fr;
        impl_->current_file = impl_->relative(path);
        fr.file = impl_->current_file;
        std::optional<error> failure;
        const std::string source = read_text(path, failure);
        std::vector<test_info> infos;
        if (failure) {
            fr.errors.push_back(file_error{failure->message, fr.file, 0, {}});
        } else {
            const auto opened = impl_->open_listed(source, fr.errors);
            for (const auto& l : opened.tests) {
                infos.push_back(l.info);
            }
        }
        out.emplace_back(std::move(fr), std::move(infos));
    }
    return out;
}

result<value> describe_api(const install_fn& install, role caller) {
    sandbox box{script::sandbox_options{.caller_role = caller}};
    if (install) {
        // With RHP_ENABLE=OFF installing is refused, but the libs are still described.
        if (auto installed = install(box); !installed && installed.error().code != errc::kDisabled) {
            return std::unexpected{std::move(installed).error()};
        }
    }
    return box.api();
}

// ---- reporter_list ---------------------------------------------------------------------------------------

void reporter_list::run_started(std::uint64_t seed, std::size_t files) {
    for (auto& r : list_) {
        r->run_started(seed, files);
    }
}
void reporter_list::file_started(const std::string& file, const std::vector<test_info>& tests) {
    for (auto& r : list_) {
        r->file_started(file, tests);
    }
}
void reporter_list::test_started(const test_info& test) {
    for (auto& r : list_) {
        r->test_started(test);
    }
}
void reporter_list::test_finished(const test_result& result) {
    for (auto& r : list_) {
        r->test_finished(result);
    }
}
void reporter_list::file_finished(const file_result& result) {
    for (auto& r : list_) {
        r->file_finished(result);
    }
}
void reporter_list::run_finished(const run_result& result) {
    for (auto& r : list_) {
        r->run_finished(result);
    }
}

// ---- fake_registry ----------------------------------------------------------------------------------------

fake_registry& fake_registry::instance() {
    static fake_registry registry;
    return registry;
}

void fake_registry::record(std::string_view path, std::vector<value> args) {
    const std::scoped_lock lock{mutex_};
    auto it = calls_.find(path);
    if (it == calls_.end()) {
        it = calls_.emplace(std::string{path}, std::vector<std::vector<value>>{}).first;
    }
    it->second.push_back(std::move(args));
}

std::vector<std::vector<value>> fake_registry::calls(std::string_view path) const {
    const std::scoped_lock lock{mutex_};
    const auto it = calls_.find(path);
    return it != calls_.end() ? it->second : std::vector<std::vector<value>>{};
}

void fake_registry::set_returns(std::string_view path, std::vector<value> values) {
    const std::scoped_lock lock{mutex_};
    returns_.insert_or_assign(std::string{path}, std::move(values));
}

std::optional<std::vector<value>> fake_registry::returns(std::string_view path) const {
    const std::scoped_lock lock{mutex_};
    const auto it = returns_.find(path);
    if (it == returns_.end()) {
        return std::nullopt;
    }
    return it->second;
}

void fake_registry::reset(std::string_view path) {
    const std::scoped_lock lock{mutex_};
    if (path.empty()) {
        calls_.clear();
        returns_.clear();
        return;
    }
    if (const auto it = calls_.find(path); it != calls_.end()) {
        calls_.erase(it);
    }
    if (const auto it = returns_.find(path); it != returns_.end()) {
        returns_.erase(it);
    }
}

void fake_registry::clear_calls() {
    const std::scoped_lock lock{mutex_};
    calls_.clear();
}

void fake_registry::set_strict(bool strict) {
    const std::scoped_lock lock{mutex_};
    strict_ = strict;
}

bool fake_registry::strict() const {
    const std::scoped_lock lock{mutex_};
    return strict_;
}

} // namespace Rhp::test

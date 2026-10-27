#pragma once

// Private to Src/rhp/script/puc_lua: the state of the profiler (profile.cpp), the debugger
// (debug.cpp) and line coverage (testing.cpp).

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <rhp/core/ids.hpp>
#include <rhp/script/debug.hpp>

namespace Rhp::script::detail {

struct string_hash {
    using is_transparent = void;
    [[nodiscard]] std::size_t operator()(std::string_view s) const noexcept { return std::hash<std::string_view>{}(s); }
};

struct frames_hash {
    [[nodiscard]] std::size_t operator()(const std::vector<std::uint32_t>& frames) const noexcept {
        std::uint64_t h = 1469598103934665603ull; // FNV-1a over the frame ids
        for (const std::uint32_t f : frames) {
            h = (h ^ f) * 1099511628211ull;
        }
        return static_cast<std::size_t>(h);
    }
};

// A frame as lua_getinfo reports it, by the addresses of its strings (they live while the function
// does); a hit is checked against the text it was made from, so a reused address can't mislabel.
struct frame_key {
    const char* source = nullptr;
    const char* name = nullptr;
    int line = 0;

    [[nodiscard]] bool operator==(const frame_key&) const = default;
};

struct frame_key_hash {
    [[nodiscard]] std::size_t operator()(const frame_key& k) const noexcept {
        const auto a = reinterpret_cast<std::uintptr_t>(k.source);
        const auto b = reinterpret_cast<std::uintptr_t>(k.name);
        return std::hash<std::uintptr_t>{}(a ^ (b * 0x9E3779B97F4A7C15ull) ^ static_cast<std::uintptr_t>(k.line));
    }
};

struct frame_slot {
    std::uint32_t id = 0;
    std::string source;
    std::string name;
};

struct profiler_state {
    profile_options options;
    std::chrono::steady_clock::time_point started;
    std::uint64_t samples = 0;
    std::uint64_t dropped = 0;
    std::uint64_t pending = 0;                                                              // instructions since the last sample
    std::unordered_map<std::string, std::uint32_t, string_hash, std::equal_to<>> frame_ids; // frame text -> id
    std::vector<std::string> frames;                                                        // id -> frame text
    std::unordered_map<std::vector<std::uint32_t>, std::uint64_t, frames_hash> stacks;      // innermost frame first
    std::vector<std::uint32_t> scratch;                                                     // one sample's frame ids, reused
    std::string text;                                                                       // one frame's text, reused
    std::unordered_map<frame_key, frame_slot, frame_key_hash> known;                        // frames seen, by the addresses of their strings
};

struct debugger_state {
    struct stepping {
        request_id request{};
        step_mode mode = step_mode::kContinue;
        int depth = 0; // the request's stack depth when it resumed
    };

    std::map<std::string, std::vector<std::uint32_t>, std::less<>> breakpoints; // source -> sorted lines
    std::vector<bool> lines;                                                    // any breakpoint on this line
    bool pause_next = false;                                                    // the next pausable line pauses
    std::optional<stepping> step;
    std::map<request_id, debug_stop> paused;
    std::set<std::string, std::less<>> reported; // "source:line" of hits already reported (until the breakpoints change)

    // The last function scope_lines looked at: its source name's characters and first and last line
    // decide the answer (a reused prototype address can't make it stale), until breakpoints change.
    struct scope_answer {
        const char* source = nullptr;
        int first = 0;
        int last = 0;
        bool on = false;
    } last_scope;

    void rebuild_lines() {
        last_scope = {};
        lines.clear();
        for (const auto& [source, at] : breakpoints) {
            for (const std::uint32_t line : at) {
                if (line >= lines.size()) {
                    lines.resize(static_cast<std::size_t>(line) + 1, false);
                }
                lines[line] = true;
            }
        }
    }

    // Line events are needed (the hook adds LUA_MASKLINE).
    [[nodiscard]] bool wants_lines() const noexcept { return !breakpoints.empty() || pause_next || step.has_value(); }
    // ... on every line: a pause or a step stops at the next line, wherever it is. With breakpoints
    // only, functions without one run without line events (sandbox_impl::scope_lines).
    [[nodiscard]] bool wants_every_line() const noexcept { return pause_next || step.has_value(); }

    // A breakpoint lies in `source` (the chunk name without its '@' / '='), lines first..last of a
    // function (first 0: a chunk's main function, whose lines are the whole chunk's).
    [[nodiscard]] bool has_breakpoint(std::string_view source, int first, int last) const {
        const auto it = breakpoints.find(source);
        if (it == breakpoints.end()) {
            return false;
        }
        if (first <= 0) {
            return !it->second.empty();
        }
        const auto at = std::ranges::lower_bound(it->second, static_cast<std::uint32_t>(first));
        return at != it->second.end() && *at <= static_cast<std::uint32_t>(last);
    }
};

// Line coverage (testing.cpp): hit counts per chunk, found from the running function's prototype.
struct coverage_state {
    struct chunk_hits {
        std::string name;
        std::vector<std::uint32_t> lines;             // executable lines, sorted
        std::vector<std::uint64_t> hits;              // per entry of `lines`
        std::vector<std::uint32_t> slot;              // line -> index in `lines` + 1 (0: not executable)
        std::map<std::uint32_t, std::uint64_t> extra; // lines that ran but weren't known
        std::uint64_t distinct = 0;                   // entries of `lines` hit at least once
    };

    std::vector<chunk_hits> chunks;
    std::unordered_map<std::string, std::uint32_t, string_hash, std::equal_to<>> by_name;
    std::unordered_map<const void*, std::uint32_t> by_proto; // function prototype -> chunk
    const void* last_proto = nullptr;                        // the prototype of the last line event
    const char* last_source = nullptr;                       // and its source name's characters
    std::uint32_t last_chunk = 0;
    std::uint64_t distinct = 0; // (chunk, line) pairs hit at least once, `extra` included

    // The chunk named `name` (created without lines when it is new).
    std::uint32_t chunk(std::string_view name) {
        if (const auto it = by_name.find(name); it != by_name.end()) {
            return it->second;
        }
        const auto index = static_cast<std::uint32_t>(chunks.size());
        chunks.push_back(chunk_hits{std::string{name}, {}, {}, {}, {}, 0});
        by_name.emplace(std::string{name}, index);
        return index;
    }

    // Adds executable lines to a chunk (a module compiled again keeps the lines of before too).
    void add_lines(std::uint32_t index, const std::vector<std::uint32_t>& lines) {
        chunk_hits& c = chunks[index];
        for (const std::uint32_t line : lines) {
            if (line < c.slot.size() && c.slot[line] != 0) {
                continue;
            }
            const auto pos = std::ranges::lower_bound(c.lines, line);
            const auto at = static_cast<std::size_t>(pos - c.lines.begin());
            c.lines.insert(pos, line);
            c.hits.insert(c.hits.begin() + static_cast<std::ptrdiff_t>(at), std::uint64_t{0});
            if (const auto e = c.extra.find(line); e != c.extra.end()) { // ran before it was known
                c.hits[at] = e->second;
                c.distinct += e->second != 0 ? 1 : 0; // already in the sandbox-wide count
                c.extra.erase(e);
            }
        }
        std::uint32_t top = c.lines.empty() ? 0 : c.lines.back();
        c.slot.assign(static_cast<std::size_t>(top) + 1, 0);
        for (std::size_t i = 0; i < c.lines.size(); ++i) {
            c.slot[c.lines[i]] = static_cast<std::uint32_t>(i + 1);
        }
    }

    void hit(std::uint32_t index, std::uint32_t line) {
        chunk_hits& c = chunks[index];
        if (line < c.slot.size() && c.slot[line] != 0) {
            if (c.hits[c.slot[line] - 1]++ == 0) {
                ++c.distinct;
                ++distinct;
            }
            return;
        }
        if (c.extra[line]++ == 0) {
            ++distinct;
        }
    }
};

} // namespace Rhp::script::detail

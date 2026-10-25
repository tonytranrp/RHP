#pragma once

// Private to Src/rhp/script/puc_lua: the profiler's and the debugger's state (profile.cpp, debug.cpp).

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
    std::uint64_t pending = 0; // instructions since the last sample
    std::unordered_map<std::string, std::uint32_t, string_hash, std::equal_to<>> frame_ids; // frame text -> id
    std::vector<std::string> frames;                                                        // id -> frame text
    std::unordered_map<std::vector<std::uint32_t>, std::uint64_t, frames_hash> stacks;      // innermost frame first
    std::vector<std::uint32_t> scratch;                                                     // one sample's frame ids, reused
    std::string text;                                                                       // one frame's text, reused
    std::unordered_map<frame_key, frame_slot, frame_key_hash> known; // frames seen, by the addresses of their strings
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

    void rebuild_lines() {
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
};

} // namespace Rhp::script::detail

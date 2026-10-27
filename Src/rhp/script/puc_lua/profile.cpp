// The sampling profiler: every hook_count() instructions the count hook records the running Lua
// stack (as interned frame ids) and counts how often each distinct stack was seen.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <lua.h>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/script/debug.hpp>
#include <rhp/script/puc_lua/sandbox_impl.hpp>
#include <rhp/script/puc_lua/tools.hpp>

namespace Rhp::script::detail {

namespace {

constexpr std::uint32_t kMinInterval = 100;
constexpr std::size_t kMaxDepth = 256;
constexpr std::size_t kMaxStacks = 100'000;

// The chunk name a module or exec was compiled under ("@game.combat", "=exec") without its marker.
std::string_view chunk_of(const lua_Debug& ar) noexcept {
    const std::string_view source = ar.source != nullptr ? std::string_view{ar.source, ar.srclen} : std::string_view{};
    return has_chunk_marker(source) ? source.substr(1) : std::string_view{"?"};
}

// "boost (game.combat:40)", "game.combat (main)", "spawn [C]". `name` stands in when Lua knows none.
void frame_text(std::string& out, const lua_Debug& ar, std::string_view name = "?") {
    out.clear();
    const std::string_view what = ar.what != nullptr ? std::string_view{ar.what} : std::string_view{};
    if (ar.name != nullptr) {
        name = ar.name;
    }
    if (what == "C") {
        out += name;
        out += " [C]";
    } else if (what == "main") {
        out += chunk_of(ar);
        out += " (main)";
    } else {
        out += name;
        std::format_to(std::back_inserter(out), " ({}:{})", chunk_of(ar), ar.linedefined);
    }
    for (char& c : out) { // the folded format separates frames with ';' and stacks with newlines
        if (c == ';' || c == '\n' || c == '\r') {
            c = ' ';
        }
    }
}

} // namespace

void sandbox_impl::profile_tick(lua_State* L, std::uint64_t elapsed) noexcept {
    profiler_state& p = *profiler_;
    p.pending += elapsed;
    if (p.pending < p.options.interval) {
        return; // the hook fires every min(check interval, profile interval) instructions
    }
    p.pending %= p.options.interval;
    profile_sample(L);
}

void sandbox_impl::profile_sample(lua_State* L) noexcept {
    profiler_state& p = *profiler_;
    const auto intern = [&p] {
        auto it = p.frame_ids.find(std::string_view{p.text});
        if (it == p.frame_ids.end()) {
            it = p.frame_ids.emplace(p.text, static_cast<std::uint32_t>(p.frames.size())).first;
            p.frames.push_back(p.text);
        }
        return it->second;
    };
    try {
        p.scratch.clear();
        lua_Debug ar{};
        bool unnamed_outer = false; // the last frame read is a Lua function Lua has no name for
        int level = 0;
        for (; static_cast<std::size_t>(level) < p.options.max_depth && lua_getstack(L, level, &ar) != 0; ++level) {
            if (lua_getinfo(L, "Sn", &ar) == 0) {
                break;
            }
            unnamed_outer = ar.name == nullptr && ar.what != nullptr && std::string_view{ar.what} == "Lua";
            const std::string_view source = ar.source != nullptr ? std::string_view{ar.source, ar.srclen} : std::string_view{};
            const std::string_view name = ar.name != nullptr ? std::string_view{ar.name} : std::string_view{};
            const frame_key key{ar.source, ar.name, ar.linedefined};
            if (const auto known = p.known.find(key); known != p.known.end() && known->second.source == source && known->second.name == name) {
                p.scratch.push_back(known->second.id); // seen before: no text to build
                continue;
            }
            if (p.frames.size() >= 4 * p.options.max_stacks) {
                ++p.dropped; // too many distinct frames (code that keeps making new ones)
                return;
            }
            frame_text(p.text, ar);
            const std::uint32_t id = intern();
            if (p.known.size() < p.options.max_stacks) {
                p.known.insert_or_assign(key, frame_slot{id, std::string{source}, std::string{name}});
            }
            p.scratch.push_back(id);
        }
        // The request's own function was called by C++: name it from the request.
        const active_run& top = running_.back();
        if (unnamed_outer && top.thread == L && top.request != nullptr && lua_getstack(L, level, &ar) == 0 && lua_getstack(L, level - 1, &ar) != 0 &&
            lua_getinfo(L, "Sn", &ar) != 0) {
            frame_text(p.text, ar, outer_name(*top.request));
            p.scratch.back() = intern();
        }
        if (p.scratch.empty()) {
            return; // the hook fired outside any Lua function
        }
        ++p.samples;
        if (const auto it = p.stacks.find(p.scratch); it != p.stacks.end()) {
            ++it->second;
        } else if (p.stacks.size() < p.options.max_stacks) {
            p.stacks.emplace(p.scratch, 1);
        } else {
            ++p.dropped;
        }
    } catch (...) { // out of memory: this sample is lost, the script goes on
        ++p.dropped;
    }
}

result<void> sandbox_impl::start_profile(const profile_options& options) {
    if (profiler_) {
        return fail(errc::kAlreadyLoaded, "the profiler is running", "profile");
    }
    auto p = std::make_unique<profiler_state>();
    p->options = options;
    p->options.interval = std::max(options.interval, kMinInterval);
    p->options.max_depth = std::clamp<std::size_t>(options.max_depth, 1, kMaxDepth);
    p->options.max_stacks = std::clamp<std::size_t>(options.max_stacks, 1, kMaxStacks);
    p->started = steady::now();
    profiler_ = std::move(p);
    rearm_all();
    return {};
}

profile_report sandbox_impl::profile() const {
    profile_report out;
    if (!profiler_) {
        return out;
    }
    const profiler_state& p = *profiler_;
    out.running = true;
    out.interval = p.options.interval;
    out.samples = p.samples;
    out.dropped = p.dropped;
    out.elapsed = std::chrono::duration_cast<std::chrono::microseconds>(steady::now() - p.started);
    out.stacks.reserve(p.stacks.size());
    for (const auto& [frames, samples] : p.stacks) {
        std::string text;
        for (auto it = frames.rbegin(); it != frames.rend(); ++it) { // outermost first
            if (!text.empty()) {
                text += ';';
            }
            text += p.frames[*it];
        }
        out.stacks.push_back(profile_stack{std::move(text), samples});
    }
    std::ranges::sort(out.stacks, [](const profile_stack& a, const profile_stack& b) {
        return a.samples != b.samples ? a.samples > b.samples : a.stack < b.stack;
    });
    return out;
}

profile_report sandbox_impl::stop_profile() {
    profile_report out = profile();
    out.running = false;
    profiler_.reset();
    rearm_all();
    return out;
}

} // namespace Rhp::script::detail

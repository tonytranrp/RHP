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

// The chunk name a module or exec was compiled under ("@game.combat", "=exec") without its marker.
std::string_view chunk_of(const lua_Debug& ar) noexcept {
    const std::string_view source = ar.source != nullptr ? std::string_view{ar.source, ar.srclen} : std::string_view{};
    if (!source.empty() && (source.front() == '@' || source.front() == '=')) {
        return source.substr(1);
    }
    return "?";
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
}

} // namespace

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
            frame_text(p.text, ar);
            unnamed_outer = ar.name == nullptr && ar.what != nullptr && std::string_view{ar.what} == "Lua";
            p.scratch.push_back(intern());
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
    p->options.max_depth = std::max<std::size_t>(options.max_depth, 1);
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

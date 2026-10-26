// frame_loop: a pretend game loop that pumps one sandbox per frame. It shows the Stage 2 scheduler:
// a script spreads its work over frames, a runaway `while true do end` is time-sliced instead of
// freezing the game, a module reloads without losing its state, C++ events reach Lua, and the
// LuaLS editor stubs are written to a file.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <print>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#include <rhp/rhp.hpp>

#if !defined(RHP_FRAME_LOOP_SCRIPTS_DIR)
#define RHP_FRAME_LOOP_SCRIPTS_DIR "scripts"
#endif
#if !defined(RHP_FRAME_LOOP_OUT_DIR)
#define RHP_FRAME_LOOP_OUT_DIR "."
#endif

// ---- the "game" --------------------------------------------------------------------------------

namespace game {

int g_frame = 0;
float g_wind = 0.0f;
int g_score = 0;

// Fired by C++ when someone scores; scripts subscribe with rhp.on("game.goal", fn).
inline constexpr Rhp::lua_event<"game.goal", int> goal{};

using game_lib = Rhp::lib<"game"> //
    ::ro<"frame", &g_frame>       // read-only for scripts
    ::var<"wind", &g_wind>        // writes are journaled
    ::var<"score", &g_score>;

} // namespace game

// ---- the host ----------------------------------------------------------------------------------

namespace {

constexpr int kFrames = 120;
constexpr int kReloadFrame = 40;
constexpr int kCancelFrame = 60;
constexpr std::uint32_t kSliceUs = 2'000;             // each pump() gives scripts at most ~2 ms
constexpr std::chrono::milliseconds kFrameLimit{250}; // generous: Debug and sanitizer builds are slow

using clock = std::chrono::steady_clock;

std::optional<std::string> read_file(const std::filesystem::path& path) {
    std::ifstream in{path, std::ios::binary};
    if (!in) {
        return std::nullopt;
    }
    std::ostringstream text;
    text << in.rdbuf();
    return std::move(text).str();
}

std::optional<std::string> script(std::string_view name) {
    const auto path = std::filesystem::path{RHP_FRAME_LOOP_SCRIPTS_DIR} / name;
    auto text = read_file(path);
    if (!text) {
        std::println(stderr, "frame_loop: cannot read {}", path.string());
    }
    return text;
}

// The first value a call returned, as an int (-1 if there is none).
int first_int(const Rhp::result<Rhp::script::value_list>& r) {
    if (!r || r->empty()) {
        return -1;
    }
    return Rhp::from_value<int>(r->front()).value_or(-1);
}

int fail(std::string_view step, const Rhp::error& err) {
    std::println(stderr, "frame_loop: {} failed: {}", step, err);
    if (!err.traceback.empty()) {
        std::println(stderr, "{}", err.traceback);
    }
    return 1;
}

std::string describe(const Rhp::value& v) {
    if (const auto* s = v.get_if<std::string>()) {
        return *s;
    }
    if (const auto* i = v.get_if<std::int64_t>()) {
        return std::to_string(*i);
    }
    if (const auto* d = v.get_if<double>()) {
        return std::format("{:.2f}", *d);
    }
    if (const auto* m = v.get_if<Rhp::value::map>()) {
        std::string out = "{";
        for (const auto& [k, item] : *m) {
            out += std::format("{}{} = {}", out.size() > 1 ? ", " : "", describe(k), describe(item));
        }
        return out + "}";
    }
    return "?";
}

} // namespace

int main() {
    Rhp::request_id runaway;
    std::optional<Rhp::errc> runaway_end;

    Rhp::script::sandbox_options options;
    options.limits.slice_us = kSliceUs;
    options.output = [](std::string_view line) { std::println("[lua] {}", line); };
    options.on_emit = [](Rhp::request_id, Rhp::module_id, const Rhp::value& v) { std::println("[emit] {}", describe(v)); };
    options.on_result = [&](Rhp::request_id id, const Rhp::result<Rhp::script::value_list>& r) {
        if (id == runaway) {
            runaway_end = r ? Rhp::errc::kOk : r.error().code;
        }
        std::println("[request {}] {}", id, r ? std::string{"finished"} : std::format("{}", r.error()));
    };
    Rhp::script::sandbox box{std::move(options)};

    if (auto installed = box.install<game::game_lib>(); !installed) {
        return fail("install", installed.error());
    }

    // 1. A module with a forever loop that waits between gusts (started by a timer).
    const auto weather_first = script("weather.lua");
    const auto weather_revised = script("weather_revised.lua");
    if (!weather_first || !weather_revised) {
        return 1;
    }
    const auto weather = box.load("weather", *weather_first);
    if (!weather) {
        return fail("load weather", weather.error());
    }

    // 2. A runaway script. With slicing it returns after one slice instead of hanging here.
    const auto started = clock::now();
    if (auto spun = box.exec("local n = 0 while true do n = n + 1 end", "runaway"); !spun) {
        return fail("exec runaway", spun.error());
    }
    runaway = box.last_request();
    std::println("runaway script suspended after {} ms (request {})",
                 std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - started).count(), runaway);

    // 3. The game loop.
    clock::duration worst{};
    int gusts_before_reload = 0;
    for (int frame = 1; frame <= kFrames; ++frame) {
        const auto frame_start = clock::now();
        game::g_frame = frame;
        if (frame % 30 == 0) {
            game::goal.fire(frame);
        }
        if (frame == kReloadFrame) {
            gusts_before_reload = first_int(box.call(*weather, "gust_count"));
            const auto revision = box.reload(*weather, *weather_revised);
            if (!revision) {
                return fail("reload weather", revision.error());
            }
            std::println("reloaded weather as revision {} with {} gusts carried over", *revision, gusts_before_reload);
        }
        if (frame == kCancelFrame) {
            box.cancel(runaway);
        }
        box.pump();
        worst = std::max(worst, clock::now() - frame_start);
    }
    const auto worst_ms = std::chrono::duration_cast<std::chrono::milliseconds>(worst);
    std::println("{} frames, worst frame {} ms (slice {} us)", kFrames, worst_ms.count(), kSliceUs);

    // 4. Editor stubs for this identity.
    const auto stubs_path = std::filesystem::path{RHP_FRAME_LOOP_OUT_DIR} / "rhp_api.lua";
    {
        std::ofstream out{stubs_path, std::ios::binary};
        out << box.stubs();
    }
    const auto stubs = read_file(stubs_path);
    std::println("wrote LuaLS stubs to {}", stubs_path.string());

    // 5. Check the Stage 2 promises, then put everything back.
    bool ok = true;
    const auto expect = [&ok](bool good, std::string_view what) {
        if (!good) {
            std::println(stderr, "frame_loop: {}", what);
            ok = false;
        }
    };
    const int gusts_after = first_int(box.call(*weather, "gust_count"));
    expect(worst < kFrameLimit, std::format("a frame took {} ms", worst_ms.count()));
    expect(runaway_end == Rhp::errc::kCancelled, "the runaway script was not cancelled");
    expect(gusts_before_reload > 0 && gusts_after > gusts_before_reload, std::format("gusts {} -> {}: state was not kept", gusts_before_reload, gusts_after));
    // Goals before the reload were counted by revision 1, whose effects the reload reverted like any
    // other effect of the old revision; only state handed over by on_save / on_restore survives.
    constexpr int kGoalsAfterReload = kFrames / 30 - kReloadFrame / 30;
    expect(game::g_score == kGoalsAfterReload, std::format("score {} (expected {})", game::g_score, kGoalsAfterReload));
    expect(stubs && stubs->find("function rhp.wait(frames) end") != std::string::npos && stubs->find("---@field wind number") != std::string::npos,
           "stubs are incomplete");

    const auto report = box.revert_all();
    expect(report.clean(), "revert_all reported failures");
    expect(game::g_wind == 0.0f && game::g_score == 0, "revert_all left the game changed");
    if (!ok) {
        return 1;
    }
    std::println("everything restored");
    return 0;
}

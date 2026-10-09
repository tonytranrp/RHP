// hello_console: a tiny pretend game exposed to Lua with Rhp::lib, a patch point, and a module
// that changes everything and is then reverted — leaving the game exactly as it was.
#include <algorithm>
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
#include <vector>

#include <rhp/rhp.hpp>

#if !defined(RHP_HELLO_SCRIPTS_DIR)
#define RHP_HELLO_SCRIPTS_DIR "scripts"
#endif

// ---- the "game" --------------------------------------------------------------------------------

namespace game {

struct entity_id {
    int v = 0;
    bool operator==(const entity_id&) const = default;
};

} // namespace game

// Lets Lua's tostring() show "entity(3)".
template <>
struct std::formatter<game::entity_id> : std::formatter<int> {
    auto format(const game::entity_id& e, std::format_context& ctx) const { return std::formatter<int>::format(e.v, ctx); }
};

namespace game {

float g_gravity = -9.8f;
std::vector<entity_id> g_entities;
int g_next_id = 1;

entity_id spawn(float x, float y) {
    std::println("  [c++] spawn at ({}, {})", x, y);
    const entity_id e{g_next_id++};
    g_entities.push_back(e);
    return e;
}

void despawn(entity_id e) {
    std::println("  [c++] despawn entity {}", e.v);
    std::erase(g_entities, e);
}

bool is_alive(const entity_id& e) {
    return std::ranges::find(g_entities, e) != g_entities.end();
}

int entity_count() {
    return static_cast<int>(g_entities.size());
}

float default_damage(float base, float multiplier) {
    return base * multiplier;
}

// A call site scripts may override.
inline constexpr Rhp::patch_point<"combat.damage", &default_damage> damage{};

// What Lua sees as the global `game`.
using game_lib = Rhp::lib<"game">              //
    ::fn<"spawn", &spawn, Rhp::undo<&despawn>> // reversible: revert calls despawn(result)
    ::fn<"count", &entity_count>               // pure
    ::var<"gravity", &g_gravity>               // writes are journaled
    ::handle<"entity", entity_id, &is_alive>;  // opaque userdata with a validity check

} // namespace game

// ---- the host ----------------------------------------------------------------------------------

namespace {

constexpr float kBase = 10.0f;
constexpr float kMultiplier = 1.5f;

int fail(std::string_view step, const Rhp::error& err) {
    std::println(stderr, "hello_console: {} failed: {}", step, err);
    if (!err.traceback.empty()) {
        std::println(stderr, "{}", err.traceback);
    }
    return 1;
}

std::optional<std::string> read_file(const std::filesystem::path& path) {
    std::ifstream in{path, std::ios::binary};
    if (!in) {
        return std::nullopt;
    }
    std::ostringstream text;
    text << in.rdbuf();
    return std::move(text).str();
}

void print_state(std::string_view when) {
    std::println("{}: gravity {}, entities {}, damage({}, {}) = {}, patch depth {}", when, game::g_gravity, game::entity_count(),
                 kBase, kMultiplier, game::damage(kBase, kMultiplier), game::damage.depth());
}

} // namespace

int main() {
    Rhp::script::sandbox_options options;
    options.output = [](std::string_view line) { std::println("[lua] {}", line); };
    Rhp::script::sandbox box{std::move(options)};

    if (auto installed = box.install<game::game_lib>(); !installed) {
        return fail("install", installed.error());
    }

    // 1. Run a snippet in the scratch module.
    const auto gravity = box.exec<double>("return game.gravity");
    if (!gravity) {
        return fail("exec", gravity.error());
    }
    std::println("exec 'return game.gravity' -> {}", *gravity);

    const float original_gravity = game::g_gravity;
    const float original_damage = game::damage(kBase, kMultiplier);
    print_state("before");

    // 2. Load a module that changes gravity, spawns entities and patches combat.damage.
    const std::filesystem::path script_path = std::filesystem::path{RHP_HELLO_SCRIPTS_DIR} / "low_grav.lua";
    const auto source = read_file(script_path);
    if (!source) {
        std::println(stderr, "hello_console: cannot read {}", script_path.string());
        return 1;
    }
    const auto mod = box.load("low_grav", *source);
    if (!mod) {
        return fail("load", mod.error());
    }
    print_state("after load");

    // 3. Call a function the module exports.
    const auto boosted = box.call(*mod, "boost", 3);
    if (!boosted) {
        return fail("call", boosted.error());
    }
    if (boosted->empty()) {
        std::println(stderr, "hello_console: boost returned nothing");
        return 1;
    }
    const auto boost_value = Rhp::from_value<int>(boosted->front());
    if (!boost_value) {
        return fail("reading boost's result", boost_value.error());
    }
    std::println("low_grav.boost(3) -> {}", *boost_value);

    if (const auto info = box.status(*mod)) {
        std::println("module {} is {} with {} effects", info->name, info->state, info->effects);
    }

    // 4. Revert the module: every effect is undone, newest first.
    const auto report = box.revert(*mod);
    if (!report) {
        return fail("revert", report.error());
    }
    std::println("revert: {} undone, {} irreversible, {} failures", report->undone, report->irreversible, report->failures.size());
    for (const auto& failure : report->failures) {
        std::println(stderr, "  {}", failure);
    }
    print_state("after revert");

    // 5. Prove it.
    bool restored = report->clean();
    const auto expect = [&restored](bool ok, std::string_view what) {
        if (!ok) {
            std::println(stderr, "hello_console: not restored: {}", what);
            restored = false;
        }
    };
    expect(game::g_gravity == original_gravity, "gravity");
    expect(game::g_entities.empty(), "entities (despawn undo)");
    expect(game::damage(kBase, kMultiplier) == original_damage, "combat.damage result");
    expect(game::damage.depth() == 0, "combat.damage patch depth");
    if (!restored) {
        return 1;
    }
    std::println("everything restored");
    return 0;
}

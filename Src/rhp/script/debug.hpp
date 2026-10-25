#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/ids.hpp>

namespace Rhp::script {

// ---- debugger ------------------------------------------------------------------------------------
//
// A sandbox pauses a request at a breakpoint, a step or a pause() by suspending its coroutine:
// the program keeps running (pump() goes on, other requests run), only that script waits until
// debug_resume(). A line that can't be paused at (a handler run from game code, a coroutine the
// script made itself, code a C function called) is reported as a "hit" instead.

// What debug_resume does next.
enum class step_mode : std::uint8_t {
    kContinue, // run until the next breakpoint
    kInto,     // stop at the next line, entering calls
    kOver,     // stop at the next line of this function or its callers
    kOut,      // stop at the next line of a caller
};

[[nodiscard]] constexpr std::string_view to_string(step_mode m) noexcept {
    switch (m) {
    case step_mode::kContinue: return "continue";
    case step_mode::kInto: return "into";
    case step_mode::kOver: return "over";
    case step_mode::kOut: return "out";
    }
    return "unknown";
}

// Which variables debug_variables lists.
enum class debug_scope : std::uint8_t {
    kLocals,   // the frame's locals (and varargs)
    kUpvalues, // the frame function's upvalues
    kGlobals,  // the frame's module environment (its own globals, not the shared libs)
};

[[nodiscard]] constexpr std::string_view to_string(debug_scope s) noexcept {
    switch (s) {
    case debug_scope::kLocals: return "locals";
    case debug_scope::kUpvalues: return "upvalues";
    case debug_scope::kGlobals: return "globals";
    }
    return "unknown";
}

// A paused request.
struct debug_stop {
    request_id request{};
    std::string label;  // the request's label ("combat.boost", "exec", "timer")
    std::string reason; // "breakpoint", "step" or "pause"
    std::string source; // the module (or exec chunk) name
    std::uint32_t line = 0;
    module_id module{};

    [[nodiscard]] bool operator==(const debug_stop&) const = default;
};

// One frame of a paused request's stack, innermost first.
struct debug_frame {
    std::uint32_t level = 0;
    std::string name;          // the function's name as the caller knew it ("?" when unknown)
    std::string what;          // "Lua", "main" or "C"
    std::string source;        // module or chunk name ("[C]" for C functions)
    std::uint32_t line = 0;    // current line (0: unknown)
    std::uint32_t defined = 0; // first line of the function

    [[nodiscard]] bool operator==(const debug_frame&) const = default;
};

// One variable, rendered without running any Lua (no metamethods, no __tostring).
struct debug_variable {
    std::string name;
    std::string type;        // a Lua type name, or a handle's name for RHP handles
    std::string text;        // its value, shortened ("{...}" tables show their size)
    bool expandable = false; // a table: debug_variables with its path lists its fields

    [[nodiscard]] bool operator==(const debug_variable&) const = default;
};

// ---- profiler ------------------------------------------------------------------------------------
//
// Samples the Lua stack every `interval` VM instructions of this sandbox's scripts (requests and
// handlers). Time spent inside C++ bindings isn't sampled: it costs no instructions.

struct profile_options {
    std::uint32_t interval = 1000;   // instructions per sample (at least 100)
    std::size_t max_depth = 64;      // frames kept per sample (the outermost are cut)
    std::size_t max_stacks = 10'000; // distinct stacks kept; more are counted as dropped
};

// One distinct stack, outermost frame first: "game.combat:12;boost (game.combat:40)".
struct profile_stack {
    std::string stack;
    std::uint64_t samples = 0;

    [[nodiscard]] bool operator==(const profile_stack&) const = default;
};

struct profile_report {
    bool running = false;
    std::uint32_t interval = 0;
    std::uint64_t samples = 0; // samples * interval ~ instructions run
    std::uint64_t dropped = 0; // samples not kept (max_stacks, or out of memory)
    std::chrono::microseconds elapsed{0};
    std::vector<profile_stack> stacks; // most samples first
};

} // namespace Rhp::script

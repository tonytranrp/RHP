#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>

namespace Rhp::script {

// ---- measuring what Lua costs (sandbox::meter) -----------------------------------------------------

// What Lua allocated objects as (the type Lua passes its allocator for a new object).
enum class alloc_kind : std::uint8_t {
    kString,
    kTable,
    kFunction, // closures
    kUserdata,
    kThread,
    kUpvalue,
    kPrototype, // compiled functions
    kOther      // arrays, buffers, stacks: memory that isn't an object of its own
};

inline constexpr std::size_t kAllocKinds = 8;

[[nodiscard]] constexpr std::string_view to_string(alloc_kind k) noexcept {
    switch (k) {
    case alloc_kind::kString: return "string";
    case alloc_kind::kTable: return "table";
    case alloc_kind::kFunction: return "function";
    case alloc_kind::kUserdata: return "userdata";
    case alloc_kind::kThread: return "thread";
    case alloc_kind::kUpvalue: return "upvalue";
    case alloc_kind::kPrototype: return "prototype";
    case alloc_kind::kOther: return "other";
    }
    return "unknown";
}

// Counters of one sandbox's Lua, from its creation. They only grow (memory and peak excepted):
// subtract two readings for what ran between them.
struct run_meter {
    std::uint64_t instructions = 0;                   // VM instructions, exact while metering (start_metering), else 0
    std::chrono::nanoseconds active{};                // time spent running Lua while metering (requests, handlers)
    std::uint64_t allocations = 0;                    // blocks allocated
    std::uint64_t frees = 0;                          // blocks freed
    std::uint64_t bytes_allocated = 0;                // bytes asked for: new blocks, plus what a block grew by
    std::size_t memory = 0;                           // in use now
    std::size_t peak = 0;                             // the most in use since the sandbox started or reset_peak()
    std::array<std::uint64_t, kAllocKinds> objects{}; // new objects by alloc_kind
};

// Lua's garbage collector mode (sandbox::set_gc_mode). Measurements compare only within one mode.
enum class gc_mode : std::uint8_t {
    kIncremental,
    kGenerational // Lua 5.5's default
};

// ---- coverage (sandbox::start_coverage) ---------------------------------------------------------------

// One chunk (a module, an exec chunk, a test file) and how often each line ran.
struct coverage_chunk {
    std::string chunk;                // the chunk name without its marker ("game.combat", "tests/x_spec.lua")
    std::vector<std::uint32_t> lines; // every line a hook can stop at, sorted
    std::vector<std::uint64_t> hits;  // runs of lines[i]
    std::vector<std::uint32_t> extra; // lines that ran but weren't known as executable (code load() compiled)
};

struct coverage_report {
    std::vector<coverage_chunk> chunks; // by chunk name

    [[nodiscard]] const coverage_chunk* find(std::string_view chunk) const noexcept {
        for (const coverage_chunk& c : chunks) {
            if (c.chunk == chunk) {
                return &c;
            }
        }
        return nullptr;
    }
};

// ---- the test bridge (sandbox::enable_testing) --------------------------------------------------------

// A service a test runner offers the Lua test framework (snapshot files, fixtures, ...): the
// framework calls it as `__rhp_test.host(command, ...)`. Errors are raised in the calling script.
using test_host_fn = std::function<result<value>(std::string_view command, std::span<const value> args)>;

struct testing_options {
    test_host_fn host{};
    // os.time() and os.clock() follow the script clock (sandbox_options::clock): os.time() is
    // `epoch` plus the seconds the clock advanced since enable_testing; os.clock() those seconds.
    std::optional<std::int64_t> fake_os_epoch{};
};

} // namespace Rhp::script

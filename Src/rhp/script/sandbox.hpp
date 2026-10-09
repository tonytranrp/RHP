#pragma once

#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/detail/lib_builder.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/stack.hpp>

#if !defined(RHP_ENABLE)
#define RHP_ENABLE 1
#endif

namespace Rhp::script {

using value_list = std::vector<value>;

enum class module_state : std::uint8_t {
    kActive,   // loaded, effects live
    kReverted, // loaded, every effect undone; inert until unloaded (reload arrives in Stage 2)
    kFaulted   // a runtime error auto-reverted it; kept for inspection until unloaded
};

[[nodiscard]] constexpr std::string_view to_string(module_state s) noexcept {
    switch (s) {
    case module_state::kActive: return "active";
    case module_state::kReverted: return "reverted";
    case module_state::kFaulted: return "faulted";
    }
    return "unknown";
}

struct module_info {
    module_id id;
    std::string name;
    module_state state = module_state::kActive;
    bool scratch = false;    // the identity's exec() module
    std::size_t effects = 0; // live ledger entries
    std::size_t irreversible_effects = 0;
    std::optional<error> fault; // why it is kFaulted
};

struct sandbox_options {
    // Role of the identity this sandbox runs for. Local C++ callers default to kPatch.
    role caller_role = role::kPatch;
    Rhp::limits limits{};
    // Every Lua allocation of this sandbox; nullptr = std::pmr::get_default_resource().
    std::pmr::memory_resource* memory = nullptr;
    // Receives each print() line (without the newline); empty = standard output.
    std::function<void(std::string_view)> output{};
    // Shown in errors and module listings.
    std::string identity = "local";
};

namespace detail {
class sandbox_impl;
} // namespace detail

// One identity's script runtime: one lua_State, one _ENV per module, one undo ledger.
//
// Single-threaded: use it from one thread (the pump thread). The only exceptions are cancel(),
// which any thread may call, and patch points, which any thread may hit (they run the C++
// default off the owning thread).
//
//   Rhp::script::sandbox box;
//   box.install<game_lib>();
//   auto mod = box.load("low_grav", "game.gravity = -1.6");
//   box.revert(*mod);                        // gravity is back
//
// With RHP_ENABLE=0 every operation fails with errc::kDisabled and no Lua is linked.
class sandbox {
public:
    explicit sandbox(sandbox_options options = {});
    ~sandbox(); // reverts and unloads everything, then closes the state

    sandbox(const sandbox&) = delete;
    sandbox& operator=(const sandbox&) = delete;
    sandbox(sandbox&&) noexcept;
    sandbox& operator=(sandbox&&) noexcept;

    // Makes a lib visible to every module of this sandbox as a global (`game`).
    // Fails with kAlreadyLoaded if the name is taken.
    template <installable L>
    result<void> install() {
#if RHP_ENABLE
        return install_lib(L::name, &detail::install_lib_tree<L>);
#else
        return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", std::string{L::name});
#endif
    }

    // Runs source in the scratch module; effects are kept and owned by the scratch module.
    // On error only the effects of this run are reverted. Returns every value the chunk returned.
    result<value_list> exec(std::string_view source, std::string_view chunk_name = "exec");

    // Same, converting the first returned value (nil if none).
    template <from_value_convertible T>
    result<T> exec(std::string_view source, std::string_view chunk_name = "exec") {
        auto values = exec(source, chunk_name);
        if (!values) {
            return std::unexpected{std::move(values).error()};
        }
        return from_value<T>(values->empty() ? value{} : values->front());
    }

    // Compiles (text only) and runs a module chunk with its own _ENV, then calls M.on_load().
    // The chunk's returned table is the module's export table (its _ENV if it returns nothing).
    // Names are dotted lowercase. Fails with kAlreadyLoaded if the name is loaded (reload: Stage 2).
    // A runtime error auto-reverts the module and leaves it kFaulted.
    result<module_id> load(std::string_view name, std::string_view source);

    // Calls an exported function of an active module. A runtime error faults the module.
    result<value_list> call(module_id mod, std::string_view function, std::span<const value> args = {});

    template <to_value_convertible A0, to_value_convertible... A>
    result<value_list> call(module_id mod, std::string_view function, const A0& a0, const A&... rest) {
        const value args[] = {to_value(a0), to_value(rest)...};
        return call(mod, function, std::span<const value>{args});
    }

    // Undoes every effect of the module, newest first; the module stays loaded but kReverted.
    result<revert_report> revert(module_id mod);
    // M.on_unload() (errors ignored), revert, forget the module.
    result<revert_report> unload(module_id mod);

    // Global marks over this sandbox's ledger. revert_to undoes every effect recorded after the
    // mark (any module) and drops later checkpoints.
    result<void> checkpoint(std::string_view tag);
    result<revert_report> revert_to(std::string_view tag);

    // Panic button: unloads every module and reverts the scratch module.
    revert_report revert_all();

    [[nodiscard]] result<module_id> find(std::string_view name) const;
    [[nodiscard]] std::optional<module_info> status(module_id mod) const;
    [[nodiscard]] std::vector<module_info> list() const;
    [[nodiscard]] module_id scratch_module() const noexcept;

    // Stops the script running right now (sticky until it returns). Callable from any thread;
    // a no-op while nothing runs.
    void cancel() noexcept;

    // Housekeeping between frames: reverts modules whose patch handlers failed since the last call.
    // Stage 2 adds the coroutine scheduler here.
    void pump();

    [[nodiscard]] role caller_role() const noexcept;
    [[nodiscard]] std::size_t memory_used() const noexcept;
    [[nodiscard]] const ledger& effects() const noexcept;

private:
    result<void> install_lib(std::string_view name, c_function build);

    std::unique_ptr<detail::sandbox_impl> impl_;
};

} // namespace Rhp::script

template <>
struct std::formatter<Rhp::script::module_state> : std::formatter<std::string_view> {
    auto format(Rhp::script::module_state s, std::format_context& ctx) const {
        return std::formatter<std::string_view>::format(Rhp::script::to_string(s), ctx);
    }
};

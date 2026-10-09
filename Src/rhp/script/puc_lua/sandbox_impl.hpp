#pragma once

// Private to Src/rhp/script/puc_lua: the sandbox behind Rhp::script::sandbox. Deliberately free of
// lua.h (the .cpp files that include this one include lua.h themselves).

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/script/detail/context.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/script/stack.hpp>

struct lua_Debug;

namespace Rhp::script::detail {

// Converts the Lua error object on top of the stack (popped) into an Rhp::error. `status` is the
// lua_pcall status. Recovers the structured error raised by stack::raise when it's the same one.
[[nodiscard]] error take_lua_error(lua_State* L, int status);

// Message handler for lua_pcall: stores a traceback in the sandbox and returns the error unchanged.
int traceback_handler(lua_State* L);

struct module_record {
    module_id id;
    std::string name;
    module_state state = module_state::kActive;
    bool scratch = false;
    int env_ref = -2;     // LUA_NOREF
    int exports_ref = -2; // LUA_NOREF
    std::optional<error> fault;
};

// Stops a run for good once a limit is hit: re-raised at every hook tick, so pcall can't swallow it.
enum class sticky_stop : std::uint8_t {
    kNone,
    kCancelled,
    kBudget,
    kMemory
};

class sandbox_impl final : public context {
public:
    explicit sandbox_impl(sandbox_options options);
    ~sandbox_impl();

    sandbox_impl(const sandbox_impl&) = delete;
    sandbox_impl& operator=(const sandbox_impl&) = delete;

    // ---- context ----------------------------------------------------------------------------
    [[nodiscard]] role caller_role() const noexcept override { return options_.caller_role; }
    [[nodiscard]] module_id current_module() const noexcept override { return current_; }
    void record_effect(std::string label, std::unique_ptr<effect> e) override;
    [[nodiscard]] module_id swap_current_module(module_id owner) noexcept override;
    void report_fault(module_id owner, error err) noexcept override;
    [[nodiscard]] lua_State* main_state() const noexcept override { return state_; }

    // ---- sandbox operations ------------------------------------------------------------------
    result<void> install_lib(std::string_view name, c_function build);
    result<value_list> exec(std::string_view source, std::string_view chunk_name);
    result<module_id> load(std::string_view name, std::string_view source);
    result<value_list> call(module_id mod, std::string_view function, std::span<const value> args);
    result<revert_report> revert(module_id mod);
    result<revert_report> unload(module_id mod);
    result<void> checkpoint(std::string_view tag);
    result<revert_report> revert_to(std::string_view tag);
    revert_report revert_all();
    [[nodiscard]] result<module_id> find(std::string_view name) const;
    [[nodiscard]] std::optional<module_info> status(module_id mod) const;
    [[nodiscard]] std::vector<module_info> list() const;
    [[nodiscard]] module_id scratch_module() const noexcept { return scratch_; }
    void cancel() noexcept { cancel_requested_.store(true, std::memory_order_release); }
    void pump();
    [[nodiscard]] std::size_t memory_used() const noexcept { return memory_used_; }
    [[nodiscard]] const ledger& effects() const noexcept { return ledger_; }

    // ---- used by stack.cpp, the hook, the allocator and the Lua-side builtins -------------------
    struct raised_error {
        std::string text;
        error err;
    };
    std::optional<raised_error> last_raised;
    std::string pending_traceback;

    void output_line(std::string_view line);
    [[nodiscard]] module_record* record(module_id mod) noexcept;
    [[nodiscard]] const module_record* record(module_id mod) const noexcept;

    static void* allocate(void* ud, void* ptr, std::size_t old_size, std::size_t new_size) noexcept;
    static void count_hook(lua_State* L, lua_Debug* ar);

private:
    struct run_scope;

    void open_libraries();
    void reset_hook() noexcept;
    [[nodiscard]] int new_environment();
    // Pushes the compiled chunk with its _ENV set; fails with kCompile.
    [[nodiscard]] result<void> compile(std::string_view source, const std::string& chunk_name, int env_ref);
    // Calls the function below `nargs` args under the run rules (limits, sticky stops, traceback).
    [[nodiscard]] result<void> run_call(module_id owner, int nargs, int nresults);
    [[nodiscard]] value_list collect_results(int first);
    void fault(module_record& mod, error err);
    void process_faults();
    void release(module_record& mod) noexcept;

    sandbox_options options_;
    std::pmr::memory_resource* memory_;
    std::size_t memory_used_ = 0;
    lua_State* state_ = nullptr;

    ledger ledger_;
    std::map<module_id, module_record> modules_;
    std::map<std::string, std::uint64_t, std::less<>> checkpoints_;
    id_generator<module_id> ids_;
    module_id scratch_;
    module_id current_;
    std::vector<std::pair<module_id, error>> pending_faults_;

    // Run state. cancel_requested_ is the only member touched by other threads.
    std::atomic<bool> cancel_requested_{false};
    int run_depth_ = 0;
    sticky_stop sticky_ = sticky_stop::kNone;
    std::uint64_t instructions_ = 0;
};

} // namespace Rhp::script::detail

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <format>
#include <memory>
#include <memory_resource>
#include <new>
#include <string>
#include <string_view>
#include <utility>

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <rhp/script/detail/patch_layers.hpp>
#include <rhp/script/detail/patch_registry.hpp>
#include <rhp/script/puc_lua/sandbox_impl.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/utils/fixed_string.hpp>

namespace Rhp::script {

namespace detail {

namespace {

constexpr std::size_t kAlignment = alignof(std::max_align_t);
constexpr std::uint32_t kDefaultCheckInterval = 1'000;

sandbox_impl& impl_of(lua_State* L) noexcept {
    return static_cast<sandbox_impl&>(**static_cast<context**>(lua_getextraspace(L)));
}

int on_panic(lua_State* L) {
    const char* message = lua_tostring(L, -1);
    std::fprintf(stderr, "[rhp critical] unprotected Lua error: %s\n", message != nullptr ? message : "(no message)");
    std::abort();
}

// Runs a callable inside lua_pcall, so every Lua API call it makes is protected (an allocation
// failure under a memory limit becomes an error result instead of a panic).
template <class F>
result<void> protect(lua_State* L, F&& fn) {
    struct holder {
        std::remove_reference_t<F>* fn;
    } h{&fn};
    return stack{L}.run_protected(
        [](lua_State* inner) -> int {
            (*static_cast<holder*>(lua_touserdata(inner, 1))->fn)();
            return 0;
        },
        &h);
}

// ---- Lua-side builtins ---------------------------------------------------------------------------

// print(...) → the sandbox's output callback, arguments joined by tabs.
int lua_print(lua_State* L) {
    const int n = lua_gettop(L);
    std::string line;
    for (int i = 1; i <= n; ++i) {
        std::size_t len = 0;
        const char* s = luaL_tolstring(L, i, &len);
        if (i > 1) {
            line.push_back('\t');
        }
        line.append(s, len);
        lua_pop(L, 1);
    }
    std::optional<error> thrown;
    try {
        impl_of(L).output_line(line);
    } catch (const std::exception& e) {
        thrown = make_error(errc::kRuntime, e.what(), "print");
    }
    if (thrown) {
        stack{L}.raise(*thrown);
    }
    return 0;
}

// load(chunk [, chunkname [, mode [, env]]]): text chunks only, for every role; without an env
// argument the chunk sees the calling module's environment instead of the shared base table.
// Upvalue 1: the standard load.
int lua_safe_load(lua_State* L) {
    const int argc = lua_gettop(L);
    lua_settop(L, 4); // pad missing arguments with nil so indices 1..4 are stable
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_pushvalue(L, 1);
    lua_pushvalue(L, 2);
    lua_pushliteral(L, "t");
    if (argc >= 4) {
        lua_pushvalue(L, 4);
    } else {
        auto& impl = impl_of(L);
        const module_record* mod = impl.record(impl.current_module());
        if (mod == nullptr) {
            mod = impl.record(impl.scratch_module());
        }
        lua_rawgeti(L, LUA_REGISTRYINDEX, mod != nullptr ? mod->env_ref : LUA_NOREF);
    }
    lua_call(L, 4, LUA_MULTRET);
    return lua_gettop(L) - 4;
}

// rhp.patch(id, handler): overrides a C++ patch point until the calling module is reverted.
int lua_rhp_patch(lua_State* L) {
    stack s{L};
    auto& impl = impl_of(L);
    if (!allows(impl.caller_role(), role::kPatch)) {
        s.raise(make_error(errc::kForbidden, std::format("needs role {}", role::kPatch), "rhp.patch"));
    }
    const auto id = s.to_string(1);
    if (!id) {
        s.raise(make_error(errc::kTypeMismatch, std::format("expected a patch point id, got {}", s.type_name(1)), "rhp.patch"));
    }
    std::optional<error> failure;
    {
        auto point = find_point(*id);
        if (!point) {
            failure = std::move(point).error();
        } else {
            auto fx = (*point)->attach_lua(s, 2);
            if (!fx) {
                failure = std::move(fx).error();
            } else {
                impl.record_effect(std::format("patch {}", *id), std::move(*fx));
            }
        }
    }
    if (failure) {
        if (failure->where.empty()) {
            failure->where = "rhp.patch";
        }
        s.raise(*failure);
    }
    return 0;
}

} // namespace

// ---- run scope -------------------------------------------------------------------------------------

// One top-level run (exec / load / call): resets the stop state on entry and makes `owner` the
// current module. Nested runs (a binding re-entering the sandbox) share the outer run's state.
struct sandbox_impl::run_scope {
    sandbox_impl& self;
    module_id previous;

    run_scope(sandbox_impl& s, module_id owner) : self(s), previous(s.current_) {
        if (self.run_depth_++ == 0) {
            self.cancel_requested_.store(false, std::memory_order_release);
            self.sticky_ = sticky_stop::kNone;
            self.instructions_ = 0;
        }
        self.current_ = owner;
    }

    run_scope(const run_scope&) = delete;
    run_scope& operator=(const run_scope&) = delete;

    ~run_scope() {
        if (--self.run_depth_ == 0 && self.sticky_ != sticky_stop::kNone) {
            self.reset_hook(); // the count hook went to every instruction while stopping
        }
        self.current_ = previous;
    }
};

// ---- construction --------------------------------------------------------------------------------

sandbox_impl::sandbox_impl(sandbox_options options)
    : options_(std::move(options)),
      memory_(options_.memory != nullptr ? options_.memory : std::pmr::get_default_resource()) {
    state_ = lua_newstate(&sandbox_impl::allocate, this, luaL_makeseed(nullptr));
    if (state_ == nullptr) {
        throw std::bad_alloc{};
    }
    *static_cast<context**>(lua_getextraspace(state_)) = static_cast<context*>(this);
    lua_atpanic(state_, &on_panic);

    reset_hook();

    scratch_ = ids_.next();
    current_ = scratch_;
    auto opened = protect(state_, [this] {
        open_libraries();
        module_record scratch;
        scratch.id = scratch_;
        scratch.name = "scratch";
        scratch.scratch = true;
        scratch.env_ref = new_environment();
        modules_.emplace(scratch_, std::move(scratch));
    });
    if (!opened) {
        lua_close(state_);
        state_ = nullptr;
        throw Rhp::exception{std::move(opened).error()};
    }
}

sandbox_impl::~sandbox_impl() {
    if (state_ == nullptr) {
        return;
    }
    try {
        (void)revert_all();
    } catch (...) { // a destructor must not throw; effects are still undone below
    }
    (void)ledger_.revert_all();
    modules_.clear();
    lua_close(state_);
}

void sandbox_impl::open_libraries() {
    lua_State* L = state_;
    const bool admin = options_.caller_role == role::kAdmin;
    if (admin) {
        luaL_openselectedlibs(L, ~0, 0);
    } else {
        luaL_openselectedlibs(L, LUA_GLIBK | LUA_COLIBK | LUA_MATHLIBK | LUA_OSLIBK | LUA_STRLIBK | LUA_TABLIBK | LUA_UTF8LIBK, 0);
        for (const char* name : {"dofile", "loadfile", "collectgarbage", "require"}) {
            lua_pushnil(L);
            lua_setglobal(L, name);
        }
        // string.dump would hand out binary chunks; os keeps only the clock.
        lua_getglobal(L, "string");
        lua_pushnil(L);
        lua_setfield(L, -2, "dump");
        lua_pop(L, 1);
        lua_getglobal(L, "os");
        lua_createtable(L, 0, 2);
        lua_getfield(L, -2, "time");
        lua_setfield(L, -2, "time");
        lua_getfield(L, -2, "clock");
        lua_setfield(L, -2, "clock");
        lua_setglobal(L, "os");
        lua_pop(L, 1);
    }

    // Binary chunks are never loaded, whatever the role: they are unverified and can crash the VM.
    lua_getglobal(L, "load");
    lua_pushcclosure(L, &lua_safe_load, 1);
    lua_setglobal(L, "load");

    lua_pushcfunction(L, &lua_print);
    lua_setglobal(L, "print");

    lua_createtable(L, 0, 2);
    lua_pushcfunction(L, &lua_rhp_patch);
    lua_setfield(L, -2, "patch");
    stack{L}.push_string(to_string(options_.caller_role));
    lua_setfield(L, -2, "role");
    lua_setglobal(L, "rhp");

    // The token behind `original` in patch handlers.
    const std::string original_key{kOriginalTokenKey};
    luaL_newmetatable(L, original_key.c_str());
    lua_pushliteral(L, "locked");
    lua_setfield(L, -2, "__metatable");
    lua_pop(L, 1);
}

// A module's _ENV: its own globals, reading through to the shared base (stdlib + libs + rhp).
// _G is the module's own environment, so `_G.x = 1` stays inside the module.
int sandbox_impl::new_environment() {
    lua_State* L = state_;
    lua_createtable(L, 0, 4);
    lua_createtable(L, 0, 2);
    lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS);
    lua_setfield(L, -2, "__index");
    lua_pushliteral(L, "locked");
    lua_setfield(L, -2, "__metatable");
    lua_setmetatable(L, -2);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "_G");
    return luaL_ref(L, LUA_REGISTRYINDEX);
}

// ---- allocator and hook ----------------------------------------------------------------------------

void sandbox_impl::reset_hook() noexcept {
    const std::uint32_t interval =
        options_.limits.cancel_check_instructions != 0 ? options_.limits.cancel_check_instructions : kDefaultCheckInterval;
    lua_sethook(state_, &sandbox_impl::count_hook, LUA_MASKCOUNT, static_cast<int>(interval));
}

void* sandbox_impl::allocate(void* ud, void* ptr, std::size_t old_size, std::size_t new_size) noexcept {
    auto& self = *static_cast<sandbox_impl*>(ud);
    if (ptr == nullptr) {
        old_size = 0; // Lua passes the object type here for new blocks
    }
    if (new_size == 0) {
        if (ptr != nullptr) {
            self.memory_->deallocate(ptr, old_size, kAlignment);
            self.memory_used_ -= old_size;
        }
        return nullptr;
    }
    if (new_size > old_size) {
        const std::uint64_t limit = self.options_.limits.memory;
        const bool in_run = self.run_depth_ > 0;
        if (in_run && self.sticky_ == sticky_stop::kMemory) {
            return nullptr;
        }
        if (limit != 0 && self.memory_used_ - old_size + new_size > limit) {
            if (in_run) {
                self.sticky_ = sticky_stop::kMemory;
            }
            return nullptr;
        }
    }
    void* block = nullptr;
    try {
        block = self.memory_->allocate(new_size, kAlignment);
    } catch (...) {
        return nullptr;
    }
    if (ptr != nullptr) {
        std::memcpy(block, ptr, std::min(old_size, new_size));
        self.memory_->deallocate(ptr, old_size, kAlignment);
    }
    self.memory_used_ = self.memory_used_ - old_size + new_size;
    return block;
}

void sandbox_impl::count_hook(lua_State* L, lua_Debug*) {
    auto& self = impl_of(L);
    if (self.run_depth_ == 0) {
        return; // patch handlers called from game code outside a run aren't limited
    }
    if (self.sticky_ == sticky_stop::kNone) {
        if (self.cancel_requested_.load(std::memory_order_acquire)) {
            self.sticky_ = sticky_stop::kCancelled;
        } else if (const std::uint64_t budget = self.options_.limits.instructions; budget != 0) {
            const std::uint32_t interval = self.options_.limits.cancel_check_instructions != 0
                                               ? self.options_.limits.cancel_check_instructions
                                               : kDefaultCheckInterval;
            self.instructions_ += interval;
            if (self.instructions_ > budget) {
                self.sticky_ = sticky_stop::kBudget;
            }
        }
    }
    if (self.sticky_ == sticky_stop::kNone) {
        return;
    }
    // From now on fire on every instruction (this thread and the main one), so a script that keeps
    // re-entering pcall can't swallow the stop between two widely spaced hook ticks.
    lua_sethook(L, &sandbox_impl::count_hook, LUA_MASKCOUNT, 1);
    lua_sethook(self.state_, &sandbox_impl::count_hook, LUA_MASKCOUNT, 1);
    switch (self.sticky_) {
    case sticky_stop::kNone: return;
    case sticky_stop::kCancelled: stack{L}.raise(make_error(errc::kCancelled, "script cancelled"));
    case sticky_stop::kBudget:
        stack{L}.raise(make_error(errc::kBudgetExceeded, std::format("instruction limit of {} exceeded", self.options_.limits.instructions)));
    case sticky_stop::kMemory:
        stack{L}.raise(make_error(errc::kMemoryExceeded, std::format("memory limit of {} bytes exceeded", self.options_.limits.memory)));
    }
}

// ---- context -------------------------------------------------------------------------------------

void sandbox_impl::record_effect(std::string label, std::unique_ptr<effect> e) {
    const module_id owner = record(current_) != nullptr ? current_ : scratch_;
    ledger_.record(owner, std::move(label), std::move(e));
}

module_id sandbox_impl::swap_current_module(module_id owner) noexcept {
    return std::exchange(current_, owner);
}

void sandbox_impl::report_fault(module_id owner, error err) noexcept {
    try {
        pending_faults_.emplace_back(owner, std::move(err));
    } catch (...) { // out of memory: the fault is dropped, the patch keeps falling back
    }
}

void sandbox_impl::output_line(std::string_view line) {
    if (options_.output) {
        options_.output(line);
    } else {
        std::fwrite(line.data(), 1, line.size(), stdout);
        std::fputc('\n', stdout);
    }
}

module_record* sandbox_impl::record(module_id mod) noexcept {
    const auto it = modules_.find(mod);
    return it != modules_.end() ? &it->second : nullptr;
}

const module_record* sandbox_impl::record(module_id mod) const noexcept {
    const auto it = modules_.find(mod);
    return it != modules_.end() ? &it->second : nullptr;
}

// ---- running code ----------------------------------------------------------------------------------

result<void> sandbox_impl::compile(std::string_view source, const std::string& chunk_name, int env_ref) {
    lua_State* L = state_;
    const int status = luaL_loadbufferx(L, source.data(), source.size(), chunk_name.c_str(), "t");
    if (status != LUA_OK) {
        error err = take_lua_error(L, status);
        if (err.code == errc::kRuntime) {
            err.code = errc::kCompile;
        }
        return std::unexpected{std::move(err)};
    }
    lua_rawgeti(L, LUA_REGISTRYINDEX, env_ref);
    lua_setupvalue(L, -2, 1); // a main chunk's first upvalue is _ENV
    return {};
}

result<void> sandbox_impl::run_call(module_id owner, int nargs, int nresults) {
    const run_scope scope{*this, owner};
    const int base = lua_gettop(state_) - nargs - 1;
    auto called = stack{state_}.call(nargs, nresults);
    // A sticky stop wins even if the script swallowed it with pcall and returned normally.
    if (sticky_ != sticky_stop::kNone && scope.self.run_depth_ == 1) {
        const errc code = sticky_ == sticky_stop::kCancelled ? errc::kCancelled
                          : sticky_ == sticky_stop::kBudget  ? errc::kBudgetExceeded
                                                             : errc::kMemoryExceeded;
        if (called) {
            lua_settop(state_, base);
            const std::string_view what = code == errc::kCancelled ? "script cancelled" : code == errc::kBudgetExceeded ? "instruction limit exceeded"
                                                                                                                        : "memory limit exceeded";
            return fail(code, std::string{what});
        }
        called.error().code = code;
    }
    return called;
}

value_list sandbox_impl::collect_results(int first) {
    value_list out;
    const stack s{state_};
    const int last = lua_gettop(state_);
    out.reserve(static_cast<std::size_t>(std::max(0, last - first + 1)));
    for (int i = first; i <= last; ++i) {
        auto v = s.to_value(i);
        if (v) {
            out.push_back(std::move(*v));
        } else {
            out.emplace_back(std::format("{}: {}", luaL_typename(state_, i), lua_topointer(state_, i)));
        }
    }
    return out;
}

void sandbox_impl::fault(module_record& mod, error err) {
    auto report = ledger_.revert(mod.id);
    if (!report.clean()) {
        err.message += std::format(" (revert left {} effect(s) in place)", report.failures.size());
    }
    if (mod.scratch) {
        return;
    }
    mod.state = module_state::kFaulted;
    mod.fault = std::move(err);
}

void sandbox_impl::process_faults() {
    auto pending = std::exchange(pending_faults_, {});
    for (auto& [owner, err] : pending) {
        if (module_record* mod = record(owner); mod != nullptr && mod->state == module_state::kActive) {
            fault(*mod, std::move(err));
        }
    }
}

void sandbox_impl::release(module_record& mod) noexcept {
    luaL_unref(state_, LUA_REGISTRYINDEX, mod.exports_ref);
    luaL_unref(state_, LUA_REGISTRYINDEX, mod.env_ref);
    mod.exports_ref = LUA_NOREF;
    mod.env_ref = LUA_NOREF;
}

// ---- operations ----------------------------------------------------------------------------------

result<void> sandbox_impl::install_lib(std::string_view name, c_function build) {
    process_faults();
    result<void> out{};
    auto glue = protect(state_, [&] {
        lua_State* L = state_;
        lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS);
        stack{L}.push_string(name);
        if (lua_rawget(L, -2) != LUA_TNIL) {
            out = fail(errc::kAlreadyLoaded, std::format("the global '{}' already exists", name), std::string{name});
            lua_pop(L, 2);
            return;
        }
        lua_pop(L, 1);
        lua_pushcfunction(L, build);
        lua_call(L, 0, 1);
        stack{L}.set_field(-2, name);
        lua_pop(L, 1);
    });
    if (!glue) {
        return std::unexpected{std::move(glue).error()};
    }
    return out;
}

result<value_list> sandbox_impl::exec(std::string_view source, std::string_view chunk_name) {
    process_faults();
    const std::uint64_t mark = ledger::mark();
    const std::string chunk = std::format("={}", chunk_name);
    result<value_list> out = value_list{};
    auto glue = protect(state_, [&] {
        const int base = lua_gettop(state_);
        if (auto compiled = compile(source, chunk, record(scratch_)->env_ref); !compiled) {
            out = std::unexpected{std::move(compiled).error()};
            return;
        }
        if (auto ran = run_call(scratch_, 0, LUA_MULTRET); !ran) {
            out = std::unexpected{std::move(ran).error()};
            lua_settop(state_, base);
            return;
        }
        out = collect_results(base + 1);
        lua_settop(state_, base);
    });
    if (!glue) {
        out = std::unexpected{std::move(glue).error()};
    }
    if (!out) {
        (void)ledger_.revert_after(scratch_, mark); // only this run's effects
    }
    return out;
}

result<module_id> sandbox_impl::load(std::string_view name, std::string_view source) {
    process_faults();
    if (!utils::is_dotted_name(name)) {
        return fail(errc::kInvalidArgument, std::format("'{}' is not a module name (dotted lowercase, e.g. combat.low_grav)", name));
    }
    if (find(name)) {
        return fail(errc::kAlreadyLoaded, std::format("module '{}' is already loaded", name), std::string{name});
    }
    const module_id id = ids_.next();
    module_record& mod = modules_.emplace(id, module_record{}).first->second;
    mod.id = id;
    mod.name = std::string{name};

    const std::string chunk = std::format("@{}", name);
    bool compiled_ok = false;
    std::optional<error> failure;
    auto glue = protect(state_, [&] {
        lua_State* L = state_;
        const int base = lua_gettop(L);
        mod.env_ref = new_environment();
        if (auto compiled = compile(source, chunk, mod.env_ref); !compiled) {
            failure = std::move(compiled).error();
            return;
        }
        compiled_ok = true;
        if (auto ran = run_call(id, 0, 1); !ran) {
            failure = std::move(ran).error();
            lua_settop(L, base);
            return;
        }
        if (lua_type(L, -1) != LUA_TTABLE) {
            lua_pop(L, 1);
            lua_rawgeti(L, LUA_REGISTRYINDEX, mod.env_ref);
        }
        mod.exports_ref = luaL_ref(L, LUA_REGISTRYINDEX);

        lua_rawgeti(L, LUA_REGISTRYINDEX, mod.exports_ref);
        lua_getfield(L, -1, "on_load");
        lua_remove(L, -2);
        if (lua_type(L, -1) == LUA_TFUNCTION) {
            if (auto loaded = run_call(id, 0, 0); !loaded) {
                failure = std::move(loaded).error();
            }
        }
        lua_settop(L, base);
    });
    if (!glue && !failure) {
        failure = std::move(glue).error();
    }
    if (!failure) {
        return id;
    }
    if (!compiled_ok) {
        release(mod);
        modules_.erase(id);
        return std::unexpected{std::move(*failure)};
    }
    if (failure->where.empty()) {
        failure->where = std::string{name};
    }
    fault(mod, *failure);
    return std::unexpected{std::move(*failure)};
}

result<value_list> sandbox_impl::call(module_id id, std::string_view function, std::span<const value> args) {
    process_faults();
    module_record* mod = record(id);
    if (mod == nullptr || mod->scratch) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (mod->state != module_state::kActive) {
        return fail(errc::kInvalidArgument, std::format("module '{}' is {}", mod->name, mod->state), mod->name);
    }
    result<value_list> out = value_list{};
    bool faulted = false;
    auto glue = protect(state_, [&] {
        lua_State* L = state_;
        const int base = lua_gettop(L);
        lua_rawgeti(L, LUA_REGISTRYINDEX, mod->exports_ref);
        stack{L}.push_string(function);
        lua_gettable(L, -2);
        lua_remove(L, -2);
        if (lua_type(L, -1) != LUA_TFUNCTION) {
            out = fail(errc::kNotFound, std::format("module '{}' exports no function '{}'", mod->name, function), mod->name);
            lua_settop(L, base);
            return;
        }
        luaL_checkstack(L, static_cast<int>(args.size()) + 2, "rhp: too many arguments");
        for (const auto& arg : args) {
            stack{L}.push_value(arg);
        }
        if (auto ran = run_call(id, static_cast<int>(args.size()), LUA_MULTRET); !ran) {
            out = std::unexpected{std::move(ran).error()};
            faulted = true;
            lua_settop(L, base);
            return;
        }
        out = collect_results(base + 1);
        lua_settop(L, base);
    });
    if (!glue) {
        return std::unexpected{std::move(glue).error()};
    }
    if (faulted) {
        if (out.error().where.empty()) {
            out.error().where = std::format("{}.{}", mod->name, function);
        }
        fault(*mod, out.error());
    }
    return out;
}

result<revert_report> sandbox_impl::revert(module_id id) {
    process_faults();
    module_record* mod = record(id);
    if (mod == nullptr) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    auto report = ledger_.revert(id);
    if (!mod->scratch && mod->state == module_state::kActive) {
        mod->state = module_state::kReverted;
    }
    return report;
}

result<revert_report> sandbox_impl::unload(module_id id) {
    process_faults();
    module_record* mod = record(id);
    if (mod == nullptr) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (mod->scratch) {
        return fail(errc::kInvalidArgument, "the scratch module can't be unloaded; revert it instead", mod->name);
    }
    if (mod->state == module_state::kActive) {
        // on_unload errors are ignored: the module is going away regardless.
        (void)protect(state_, [&] {
            lua_State* L = state_;
            const int base = lua_gettop(L);
            lua_rawgeti(L, LUA_REGISTRYINDEX, mod->exports_ref);
            lua_getfield(L, -1, "on_unload");
            lua_remove(L, -2);
            if (lua_type(L, -1) == LUA_TFUNCTION) {
                (void)run_call(id, 0, 0);
            }
            lua_settop(L, base);
        });
    }
    auto report = ledger_.revert(id);
    release(*mod);
    modules_.erase(id);
    return report;
}

result<void> sandbox_impl::checkpoint(std::string_view tag) {
    checkpoints_.insert_or_assign(std::string{tag}, ledger::mark());
    return {};
}

result<revert_report> sandbox_impl::revert_to(std::string_view tag) {
    process_faults();
    const auto it = checkpoints_.find(tag);
    if (it == checkpoints_.end()) {
        return fail(errc::kNotFound, std::format("no checkpoint '{}'", tag));
    }
    const std::uint64_t mark = it->second;
    auto report = ledger_.revert_after(mark);
    std::erase_if(checkpoints_, [mark](const auto& entry) { return entry.second > mark; });
    return report;
}

revert_report sandbox_impl::revert_all() {
    process_faults();
    revert_report report;
    std::vector<module_id> ids;
    for (const auto& [id, mod] : modules_) {
        if (!mod.scratch) {
            ids.push_back(id);
        }
    }
    for (auto it = ids.rbegin(); it != ids.rend(); ++it) {
        if (auto unloaded = unload(*it)) {
            report += std::move(*unloaded);
        }
    }
    report += ledger_.revert(scratch_);
    return report;
}

result<module_id> sandbox_impl::find(std::string_view name) const {
    for (const auto& [id, mod] : modules_) {
        if (!mod.scratch && mod.name == name) {
            return id;
        }
    }
    return fail(errc::kNotFound, std::format("no module '{}'", name));
}

std::optional<module_info> sandbox_impl::status(module_id id) const {
    const module_record* mod = record(id);
    if (mod == nullptr) {
        return std::nullopt;
    }
    return module_info{mod->id, mod->name, mod->state, mod->scratch, ledger_.count(id), ledger_.irreversible_count(id), mod->fault};
}

std::vector<module_info> sandbox_impl::list() const {
    std::vector<module_info> out;
    out.reserve(modules_.size());
    for (const auto& [id, mod] : modules_) {
        out.push_back(*status(id));
    }
    return out;
}

void sandbox_impl::pump() {
    process_faults();
}

} // namespace detail

// ---- sandbox (public) ------------------------------------------------------------------------------

sandbox::sandbox(sandbox_options options) : impl_(std::make_unique<detail::sandbox_impl>(std::move(options))) {}

sandbox::~sandbox() = default;
sandbox::sandbox(sandbox&&) noexcept = default;
sandbox& sandbox::operator=(sandbox&&) noexcept = default;

result<void> sandbox::install_lib(std::string_view name, c_function build) {
    return impl_->install_lib(name, build);
}

result<value_list> sandbox::exec(std::string_view source, std::string_view chunk_name) {
    return impl_->exec(source, chunk_name);
}

result<module_id> sandbox::load(std::string_view name, std::string_view source) {
    return impl_->load(name, source);
}

result<value_list> sandbox::call(module_id mod, std::string_view function, std::span<const value> args) {
    return impl_->call(mod, function, args);
}

result<revert_report> sandbox::revert(module_id mod) {
    return impl_->revert(mod);
}

result<revert_report> sandbox::unload(module_id mod) {
    return impl_->unload(mod);
}

result<void> sandbox::checkpoint(std::string_view tag) {
    return impl_->checkpoint(tag);
}

result<revert_report> sandbox::revert_to(std::string_view tag) {
    return impl_->revert_to(tag);
}

revert_report sandbox::revert_all() {
    return impl_->revert_all();
}

result<module_id> sandbox::find(std::string_view name) const {
    return impl_->find(name);
}

std::optional<module_info> sandbox::status(module_id mod) const {
    return impl_->status(mod);
}

std::vector<module_info> sandbox::list() const {
    return impl_->list();
}

module_id sandbox::scratch_module() const noexcept {
    return impl_->scratch_module();
}

void sandbox::cancel() noexcept {
    impl_->cancel();
}

void sandbox::pump() {
    impl_->pump();
}

role sandbox::caller_role() const noexcept {
    return impl_->caller_role();
}

std::size_t sandbox::memory_used() const noexcept {
    return impl_->memory_used();
}

const ledger& sandbox::effects() const noexcept {
    return impl_->effects();
}

} // namespace Rhp::script

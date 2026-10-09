#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <format>
#include <functional>
#include <memory>
#include <memory_resource>
#include <mutex>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <rhp/script/detail/event_registry.hpp>
#include <rhp/script/detail/patch_layers.hpp>
#include <rhp/script/detail/patch_registry.hpp>
#include <rhp/script/puc_lua/sandbox_impl.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/script/stubs.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/utils/crc32c.hpp>
#include <rhp/utils/fixed_string.hpp>

namespace Rhp::script {

namespace detail {

namespace {

constexpr std::size_t kAlignment = alignof(std::max_align_t);
constexpr std::uint32_t kDefaultCheckInterval = 1'000;
constexpr double kMaxMilliseconds = 1e12;                         // ~31 years: keeps duration conversions in range
constexpr const char* kModuleProxyKey = "rhp.module";             // metatable of require() proxies
constexpr const char* kModuleProxiesKey = "rhp.module_proxies";   // registry: module id → its proxy
constexpr const char* kRequestThreadsKey = "rhp.request_threads"; // registry: weak set of request coroutines

// Every load / reload request runs this: the module's top level, then on_load, then the exports.
constexpr std::string_view kLoaderSource = R"lua(
local type = type
return function(chunk, env)
    local exports = chunk()
    if type(exports) ~= "table" then
        exports = env
    end
    local on_load = exports.on_load
    if type(on_load) == "function" then
        on_load()
    end
    return exports
end
)lua";

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

std::uint32_t source_hash(std::string_view source) noexcept {
    return utils::crc32c(utils::bytes_view{reinterpret_cast<const std::byte*>(source.data()), source.size()});
}

steady::duration milliseconds(double ms) {
    return std::chrono::duration_cast<steady::duration>(std::chrono::duration<double, std::milli>{std::min(ms, kMaxMilliseconds)});
}

// Milliseconds argument (>= 0) or a raised error naming `where`.
double checked_ms(lua_State* L, int index, std::string_view where) {
    const stack s{L};
    const auto ms = s.to_number(index);
    if (!ms || !(*ms >= 0.0)) {
        s.raise(make_error(errc::kInvalidArgument, std::format("expected milliseconds >= 0, got {}", s.type_name(index)), std::string{where}));
    }
    return *ms;
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
        lua_rawgeti(L, LUA_REGISTRYINDEX, impl_of(L).current_env());
    }
    lua_call(L, 4, LUA_MULTRET);
    return lua_gettop(L) - 4;
}

// coroutine.resume / coroutine.close, refusing request coroutines: only the scheduler resumes them.
// Upvalue 1: the standard function.
int lua_guarded_coroutine(lua_State* L) {
    if (lua_type(L, 1) == LUA_TTHREAD) {
        lua_getfield(L, LUA_REGISTRYINDEX, kRequestThreadsKey);
        lua_pushvalue(L, 1);
        const bool request = lua_rawget(L, -2) != LUA_TNIL;
        lua_pop(L, 2);
        if (request) {
            stack{L}.raise(make_error(errc::kInvalidArgument, "this coroutine is a script request; only the scheduler resumes it"));
        }
    }
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);
    lua_call(L, lua_gettop(L) - 1, LUA_MULTRET);
    return lua_gettop(L);
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

// rhp.wait([frames]): suspends the request for `frames` pump() calls (at least 1).
int lua_rhp_wait(lua_State* L) {
    const stack s{L};
    std::int64_t frames = 1;
    if (!s.is_none_or_nil(1)) {
        const auto n = s.to_integer(1);
        if (!n) {
            s.raise(make_error(errc::kTypeMismatch, std::format("expected a frame count, got {}", s.type_name(1)), "rhp.wait"));
        }
        frames = std::max<std::int64_t>(*n, 1);
    }
    auto& impl = impl_of(L);
    impl.suspendable(L, "rhp.wait").wake_frame = impl.frame() + static_cast<std::uint64_t>(frames);
    return lua_yield(L, 0);
}

// rhp.next_frame(): suspends the request until the next pump().
int lua_rhp_next_frame(lua_State* L) {
    auto& impl = impl_of(L);
    impl.suspendable(L, "rhp.next_frame").wake_frame = impl.frame() + 1;
    return lua_yield(L, 0);
}

// rhp.sleep(ms): suspends the request until the script clock has advanced `ms` milliseconds.
int lua_rhp_sleep(lua_State* L) {
    const double ms = checked_ms(L, 1, "rhp.sleep");
    auto& impl = impl_of(L);
    impl.suspendable(L, "rhp.sleep").wake_time = impl.script_now() + milliseconds(ms);
    return lua_yield(L, 0);
}

// rhp.frame(): pump() calls so far.
int lua_rhp_frame(lua_State* L) {
    lua_pushinteger(L, static_cast<lua_Integer>(impl_of(L).frame()));
    return 1;
}

// rhp.emit(value): streams a value to the host (sandbox_options::on_emit).
int lua_rhp_emit(lua_State* L) {
    const stack s{L};
    std::optional<error> failure;
    {
        auto v = s.to_value(1);
        if (!v) {
            failure = std::move(v).error();
            failure->where = "rhp.emit";
        } else {
            try {
                impl_of(L).emit(*v);
            } catch (const std::exception& e) {
                failure = make_error(errc::kRuntime, e.what(), "rhp.emit");
            }
        }
    }
    if (failure) {
        s.raise(*failure);
    }
    return 0;
}

// rhp.timer(ms, fn [, repeating]) → id: calls fn as its own request after ms (every ms if repeating).
int lua_rhp_timer(lua_State* L) {
    const stack s{L};
    const double ms = checked_ms(L, 1, "rhp.timer");
    if (lua_type(L, 2) != LUA_TFUNCTION) {
        s.raise(make_error(errc::kTypeMismatch, std::format("expected function, got {}", s.type_name(2)), "rhp.timer"));
    }
    const bool repeating = lua_toboolean(L, 3) != 0;
    lua_pushinteger(L, static_cast<lua_Integer>(impl_of(L).add_timer(L, ms, 2, repeating)));
    return 1;
}

// rhp.on(event, handler) → id: runs handler as its own request each time C++ fires the event.
int lua_rhp_on(lua_State* L) {
    const stack s{L};
    const auto event = s.to_string(1);
    if (!event) {
        s.raise(make_error(errc::kTypeMismatch, std::format("expected an event name, got {}", s.type_name(1)), "rhp.on"));
    }
    if (lua_type(L, 2) != LUA_TFUNCTION) {
        s.raise(make_error(errc::kTypeMismatch, std::format("expected function, got {}", s.type_name(2)), "rhp.on"));
    }
    lua_pushinteger(L, static_cast<lua_Integer>(impl_of(L).subscribe(L, *event, 2)));
    return 1;
}

// rhp.off(id): removes a timer or subscription the calling module made.
int lua_rhp_off(lua_State* L) {
    const stack s{L};
    const auto id = s.to_integer(1);
    if (!id || *id <= 0) {
        s.raise(make_error(errc::kTypeMismatch, std::format("expected a timer or subscription id, got {}", s.type_name(1)), "rhp.off"));
    }
    impl_of(L).remove_by_id(L, static_cast<std::uint64_t>(*id));
    return 0;
}

// require(name): a read-only live proxy of a loaded module of this identity.
int lua_require(lua_State* L) {
    const stack s{L};
    const auto name = s.to_string(1);
    if (!name) {
        s.raise(make_error(errc::kTypeMismatch, std::format("expected a module name, got {}", s.type_name(1)), "require"));
    }
    impl_of(L).push_required(L, *name);
    return 1;
}

// ---- require() proxies ---------------------------------------------------------------------------

// Userdata payload of a proxy; user value 1 is the module name (for messages after unload).
struct module_proxy {
    std::uint64_t id;
};

std::string proxy_name(lua_State* L, int index) {
    lua_getiuservalue(L, index, 1);
    std::size_t len = 0;
    const char* s = lua_tolstring(L, -1, &len);
    std::string name = s != nullptr ? std::string{s, len} : std::string{"?"};
    lua_pop(L, 1);
    return name;
}

int module_index(lua_State* L) {
    const auto* proxy = static_cast<const module_proxy*>(luaL_checkudata(L, 1, kModuleProxyKey));
    const module_record* mod = impl_of(L).record(module_id{proxy->id});
    if (mod == nullptr || mod->live.exports_ref == kNoRef) {
        stack{L}.raise(make_error(errc::kUnloaded, std::format("module '{}' was unloaded", proxy_name(L, 1))));
    }
    lua_rawgeti(L, LUA_REGISTRYINDEX, mod->live.exports_ref);
    lua_pushvalue(L, 2);
    lua_gettable(L, -2);
    return 1;
}

int module_newindex(lua_State* L) {
    (void)luaL_checkudata(L, 1, kModuleProxyKey);
    stack{L}.raise(make_error(errc::kInvalidArgument, std::format("module '{}' is read-only to require()rs", proxy_name(L, 1))));
}

int module_tostring(lua_State* L) {
    (void)luaL_checkudata(L, 1, kModuleProxyKey);
    const std::string name = proxy_name(L, 1);
    lua_pushfstring(L, "module: %s", name.c_str());
    return 1;
}

} // namespace

// ---- run scopes --------------------------------------------------------------------------------------

// One entry on the run stack: makes `owner` the running code and accounts its time to `budget`.
// The outermost scope clears a cancel() that arrived while nothing ran, and resets the hook after a
// stop switched it to every instruction.
struct sandbox_impl::active_scope {
    sandbox_impl& self;
    effect_owner previous;

    active_scope(sandbox_impl& s, run_budget* budget, lua_State* thread, request_record* request, const effect_owner& owner)
        : self(s), previous(s.current_) {
        if (self.running_.empty()) {
            self.cancel_running_.store(false, std::memory_order_release);
        }
        self.running_.push_back(active_run{budget, thread, request, steady::now()});
        self.current_ = owner;
    }

    active_scope(const active_scope&) = delete;
    active_scope& operator=(const active_scope&) = delete;

    ~active_scope() {
        const active_run& top = self.running_.back();
        if (top.budget != nullptr) {
            top.budget->active += steady::now() - top.started;
        }
        self.running_.pop_back();
        self.current_ = previous;
        if (self.running_.empty() && self.hook_dirty_) {
            self.hook_dirty_ = false;
            self.reset_hook();
        }
    }
};

// limits.slice_us of wall time for everything started from here (an operation, pump(), an event).
struct sandbox_impl::slice_scope {
    sandbox_impl& self;
    bool owns;

    explicit slice_scope(sandbox_impl& s)
        : self(s), owns(s.options_.limits.slice_us != 0 && !s.slice_deadline_ && s.running_.empty()) {
        if (owns) {
            self.slice_deadline_ = steady::now() + std::chrono::microseconds{self.options_.limits.slice_us};
        }
    }

    slice_scope(const slice_scope&) = delete;
    slice_scope& operator=(const slice_scope&) = delete;

    ~slice_scope() {
        if (owns) {
            self.slice_deadline_.reset();
        }
    }
};

// ---- construction --------------------------------------------------------------------------------

sandbox_impl::sandbox_impl(sandbox_options options)
    : options_(std::move(options)),
      memory_(options_.memory != nullptr ? options_.memory : std::pmr::get_default_resource()),
      thread_(std::this_thread::get_id()) {
    state_ = lua_newstate(&sandbox_impl::allocate, this, luaL_makeseed(nullptr));
    if (state_ == nullptr) {
        throw std::bad_alloc{};
    }
    *static_cast<context**>(lua_getextraspace(state_)) = static_cast<context*>(this);
    lua_atpanic(state_, &on_panic);

    reset_hook();

    scratch_ = ids_.next();
    current_ = effect_owner{scratch_};
    auto opened = protect(state_, [this] {
        open_libraries();
        module_record scratch;
        scratch.id = scratch_;
        scratch.name = "scratch";
        scratch.scratch = true;
        scratch.live.env_ref = new_environment();
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
        std::vector<module_id> ids;
        for (const auto& [id, mod] : modules_) {
            if (!mod.scratch) {
                ids.push_back(id);
            }
        }
        for (auto it = ids.rbegin(); it != ids.rend(); ++it) {
            if (module_record* mod = record(*it)) {
                (void)unload_module(*mod);
            }
        }
        abandon_requests([](const request_record&) { return true; }, "the sandbox was destroyed");
    } catch (...) { // a destructor must not throw; effects are still undone below
    }
    (void)ledger_.revert_all();
    for (const auto& [name, state] : attached_) {
        state->detach(this);
    }
    attached_.clear();
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
        for (const char* name : {"dofile", "loadfile", "collectgarbage"}) {
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

    // require only finds loaded modules of this identity — never the file system, admin included.
    lua_pushcfunction(L, &lua_require);
    lua_setglobal(L, "require");

    // Request coroutines belong to the scheduler.
    lua_newtable(L);
    lua_createtable(L, 0, 1);
    lua_pushliteral(L, "k");
    lua_setfield(L, -2, "__mode");
    lua_setmetatable(L, -2);
    lua_setfield(L, LUA_REGISTRYINDEX, kRequestThreadsKey);
    lua_getglobal(L, "coroutine");
    for (const char* name : {"resume", "close"}) {
        lua_getfield(L, -1, name);
        lua_pushcclosure(L, &lua_guarded_coroutine, 1);
        lua_setfield(L, -2, name);
    }
    lua_pop(L, 1);

    struct builtin {
        const char* name;
        lua_CFunction fn;
    };
    constexpr builtin builtins[] = {
        {"patch", &lua_rhp_patch},
        {"wait", &lua_rhp_wait},
        {"next_frame", &lua_rhp_next_frame},
        {"sleep", &lua_rhp_sleep},
        {"frame", &lua_rhp_frame},
        {"emit", &lua_rhp_emit},
        {"timer", &lua_rhp_timer},
        {"on", &lua_rhp_on},
        {"off", &lua_rhp_off},
    };
    lua_createtable(L, 0, static_cast<int>(std::size(builtins)) + 1);
    for (const auto& [name, fn] : builtins) {
        lua_pushcfunction(L, fn);
        lua_setfield(L, -2, name);
    }
    stack{L}.push_string(to_string(options_.caller_role));
    lua_setfield(L, -2, "role");
    lua_setglobal(L, "rhp");

    // The token behind `original` in patch handlers.
    const std::string original_key{kOriginalTokenKey};
    luaL_newmetatable(L, original_key.c_str());
    lua_pushliteral(L, "locked");
    lua_setfield(L, -2, "__metatable");
    lua_pop(L, 1);

    // require() proxies, one per module (cached so require("x") == require("x")).
    luaL_newmetatable(L, kModuleProxyKey);
    lua_pushcfunction(L, &module_index);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, &module_newindex);
    lua_setfield(L, -2, "__newindex");
    lua_pushcfunction(L, &module_tostring);
    lua_setfield(L, -2, "__tostring");
    lua_pushliteral(L, "module");
    lua_setfield(L, -2, "__name");
    lua_pushliteral(L, "locked");
    lua_setfield(L, -2, "__metatable");
    lua_pop(L, 1);
    lua_newtable(L);
    lua_setfield(L, LUA_REGISTRYINDEX, kModuleProxiesKey);

    // The module loader, compiled once against the base globals.
    if (luaL_loadbufferx(L, kLoaderSource.data(), kLoaderSource.size(), "=rhp.loader", "t") != LUA_OK) {
        lua_error(L);
    }
    lua_call(L, 0, 1);
    loader_ref_ = luaL_ref(L, LUA_REGISTRYINDEX);
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

std::uint32_t sandbox_impl::check_interval() const noexcept {
    return options_.limits.cancel_check_instructions != 0 ? options_.limits.cancel_check_instructions : kDefaultCheckInterval;
}

void sandbox_impl::reset_hook() noexcept {
    lua_sethook(state_, &sandbox_impl::count_hook, LUA_MASKCOUNT, static_cast<int>(check_interval()));
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
        run_budget* budget = nullptr; // innermost run with its own budget
        for (auto it = self.running_.rbegin(); it != self.running_.rend() && budget == nullptr; ++it) {
            budget = it->budget;
        }
        if (budget != nullptr && budget->sticky == sticky_stop::kMemory) {
            return nullptr;
        }
        if (limit != 0 && self.memory_used_ - old_size + new_size > limit) {
            if (budget != nullptr && budget->sticky == sticky_stop::kNone) {
                budget->sticky = sticky_stop::kMemory;
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

void sandbox_impl::check_cancels() noexcept {
    if (cancel_running_.exchange(false, std::memory_order_acq_rel)) {
        for (active_run& run : running_) {
            if (run.budget != nullptr && run.budget->sticky == sticky_stop::kNone) {
                run.budget->sticky = sticky_stop::kCancelled;
            }
        }
    }
    if (!cancel_ids_pending_.load(std::memory_order_acquire)) {
        return;
    }
    const std::scoped_lock lock{inbox_mutex_};
    // Running requests stop here; suspended ones are ended before they resume (take_cancel) or by
    // the next drain(), so their ids stay pending.
    std::erase_if(cancel_ids_, [this](request_id id) {
        for (active_run& run : running_) {
            if (run.request != nullptr && run.request->id == id) {
                if (run.budget->sticky == sticky_stop::kNone) {
                    run.budget->sticky = sticky_stop::kCancelled;
                }
                return true;
            }
        }
        return false;
    });
    cancel_ids_pending_.store(!cancel_ids_.empty(), std::memory_order_release);
}

bool sandbox_impl::take_cancel(request_id id) {
    if (!cancel_ids_pending_.load(std::memory_order_acquire)) {
        return false;
    }
    const std::scoped_lock lock{inbox_mutex_};
    const auto it = std::ranges::find(cancel_ids_, id);
    if (it == cancel_ids_.end()) {
        return false;
    }
    cancel_ids_.erase(it);
    cancel_ids_pending_.store(!cancel_ids_.empty(), std::memory_order_release);
    return true;
}

void sandbox_impl::count_hook(lua_State* L, lua_Debug*) {
    auto& self = impl_of(L);
    if (self.running_.empty()) {
        return; // a handler called from game code runs inside run_handler, so this is GC / setup code
    }
    self.check_cancels();
    const auto& limits = self.options_.limits;
    const bool timed = limits.wall_ms != 0 || self.slice_deadline_.has_value();
    const steady::time_point now = timed ? steady::now() : steady::time_point{};
    sticky_stop stop = sticky_stop::kNone;
    for (active_run& run : self.running_) {
        if (run.budget == nullptr) {
            continue;
        }
        run_budget& budget = *run.budget;
        if (budget.sticky == sticky_stop::kNone) {
            if (limits.instructions != 0 && (budget.instructions += self.check_interval()) > limits.instructions) {
                budget.sticky = sticky_stop::kBudget;
            } else if (limits.wall_ms != 0 && budget.active + (now - run.started) > std::chrono::milliseconds{limits.wall_ms}) {
                budget.sticky = sticky_stop::kWall;
            }
        }
        if (budget.sticky != sticky_stop::kNone) {
            stop = budget.sticky; // the innermost stopped run decides the error
        }
    }
    if (stop != sticky_stop::kNone) {
        // From now on fire on every instruction (this thread and the main one), so a script that keeps
        // re-entering pcall can't swallow the stop between two widely spaced hook ticks.
        self.hook_dirty_ = true;
        lua_sethook(L, &sandbox_impl::count_hook, LUA_MASKCOUNT, 1);
        lua_sethook(self.state_, &sandbox_impl::count_hook, LUA_MASKCOUNT, 1);
        stack{L}.raise(self.sticky_error(stop));
    }
    // End of the time slice: yield the request's own thread (never a coroutine it created, never
    // across a C call); it continues at the next pump().
    if (self.slice_deadline_ && now >= *self.slice_deadline_) {
        const active_run& top = self.running_.back();
        if (top.thread == L && top.request != nullptr && lua_isyieldable(L) != 0) {
            top.request->sliced = true;
            (void)lua_yield(L, 0);
        }
    }
}

error sandbox_impl::sticky_error(sticky_stop stop) const {
    const auto& limits = options_.limits;
    switch (stop) {
    case sticky_stop::kCancelled: return make_error(errc::kCancelled, "script cancelled");
    case sticky_stop::kBudget: return make_error(errc::kBudgetExceeded, std::format("instruction limit of {} exceeded", limits.instructions));
    case sticky_stop::kMemory: return make_error(errc::kMemoryExceeded, std::format("memory limit of {} bytes exceeded", limits.memory));
    case sticky_stop::kWall: return make_error(errc::kTimeout, std::format("wall time limit of {} ms exceeded", limits.wall_ms));
    case sticky_stop::kNone: break;
    }
    return make_error(errc::kRuntime);
}

// ---- context -------------------------------------------------------------------------------------

std::uint64_t sandbox_impl::record_effect(std::string label, std::unique_ptr<effect> e) {
    effect_owner owner = current_;
    if (record(owner.module) == nullptr) {
        owner = effect_owner{scratch_};
    }
    return ledger_.record(owner, std::move(label), std::move(e));
}

result<void> sandbox_impl::run_handler(const effect_owner& owner, c_function fn, void* data) {
    // Inside a running script the handler is part of that run; from game code it is a run of its own.
    run_budget local;
    run_budget* budget = running_.empty() ? &local : nullptr;
    result<void> ran;
    {
        const active_scope scope{*this, budget, nullptr, nullptr, owner};
        ran = stack{state_}.run_protected(fn, data);
    }
    if (budget != nullptr && local.sticky != sticky_stop::kNone) {
        error stop = sticky_error(local.sticky);
        if (ran) {
            return std::unexpected{std::move(stop)};
        }
        ran.error().code = stop.code;
    }
    return ran;
}

void sandbox_impl::report_fault(const effect_owner& owner, error err) noexcept {
    // A stop of the run around the handler (cancel, a limit) is that run's failure, not the handler's.
    for (const active_run& run : running_) {
        if (run.budget != nullptr && run.budget->sticky != sticky_stop::kNone) {
            return;
        }
    }
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

void sandbox_impl::emit(const value& v) {
    if (options_.on_emit) {
        options_.on_emit(current_.request, current_.module, v);
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

module_instance* sandbox_impl::instance_of(module_record& mod, revision_id revision) noexcept {
    if (mod.pending && mod.pending->revision == revision) {
        return &*mod.pending;
    }
    return mod.live.revision == revision ? &mod.live : nullptr;
}

int sandbox_impl::current_env() const noexcept {
    const module_record* mod = record(current_.module);
    if (mod == nullptr) {
        mod = record(scratch_);
    }
    if (mod->pending && mod->pending->revision == current_.revision) {
        return mod->pending->env_ref;
    }
    return mod->live.env_ref;
}

steady::time_point sandbox_impl::script_now() const {
    return options_.clock ? options_.clock() : steady::now();
}

request_record& sandbox_impl::suspendable(lua_State* L, std::string_view what) {
    if (!running_.empty()) {
        const active_run& top = running_.back();
        if (top.thread == L && top.request != nullptr && lua_isyieldable(L) != 0) {
            return *top.request;
        }
    }
    stack{L}.raise(make_error(errc::kInvalidArgument,
                              "only a script's own thread can suspend (not a patch handler, on_save / on_restore / on_unload, "
                              "a coroutine it created, or a callback of a C function such as table.sort)",
                              std::string{what}));
}

// ---- timers and subscriptions ----------------------------------------------------------------------

namespace {

class timer_effect final : public effect {
public:
    timer_effect(sandbox_impl& box, std::uint64_t key) : box_(&box), key_(key) {}
    timer_effect(const timer_effect&) = delete;
    timer_effect& operator=(const timer_effect&) = delete;
    ~timer_effect() override { box_->remove_timer(key_); }

    void undo() override { box_->remove_timer(key_); }

private:
    sandbox_impl* box_;
    std::uint64_t key_;
};

class subscription_effect final : public effect {
public:
    subscription_effect(sandbox_impl& box, std::string event, std::uint64_t key) : box_(&box), event_(std::move(event)), key_(key) {}
    subscription_effect(const subscription_effect&) = delete;
    subscription_effect& operator=(const subscription_effect&) = delete;
    ~subscription_effect() override { box_->unsubscribe(event_, key_); }

    void undo() override { box_->unsubscribe(event_, key_); }

private:
    sandbox_impl* box_;
    std::string event_;
    std::uint64_t key_;
};

} // namespace

std::uint64_t sandbox_impl::add_timer(lua_State* L, double ms, int fn_index, bool repeating) {
    lua_pushvalue(L, fn_index);
    const int fn_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    const std::uint64_t key = ++timer_keys_;
    const steady::duration interval = milliseconds(ms);
    timers_.emplace(key, timer_record{current_, fn_ref, script_now() + interval, interval, repeating, 0});
    const std::uint64_t seq = record_effect(repeating ? "rhp.timer (repeating)" : "rhp.timer", std::make_unique<timer_effect>(*this, key));
    if (const auto it = timers_.find(key); it != timers_.end()) {
        it->second.seq = seq;
    }
    return seq;
}

void sandbox_impl::remove_timer(std::uint64_t key) noexcept {
    const auto it = timers_.find(key);
    if (it == timers_.end()) {
        return;
    }
    luaL_unref(state_, LUA_REGISTRYINDEX, it->second.fn_ref);
    timers_.erase(it);
}

std::uint64_t sandbox_impl::subscribe(lua_State* L, std::string_view event, int fn_index) {
    std::optional<error> failure;
    event_state* state = nullptr;
    {
        auto found = find_event(event);
        if (found) {
            state = (*found)->state;
        } else {
            failure = std::move(found).error();
            failure->where = "rhp.on";
        }
    }
    if (failure) {
        stack{L}.raise(*failure);
    }
    lua_pushvalue(L, fn_index);
    const int fn_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    const std::uint64_t key = ++subscription_keys_;
    auto& subs = subscriptions_[std::string{event}];
    subs.push_back(subscription{key, current_, fn_ref, 0});
    if (!attached_.contains(event)) {
        attached_.emplace(std::string{event}, state);
        state->attach(this);
    }
    const std::uint64_t seq =
        record_effect(std::format("rhp.on {}", event), std::make_unique<subscription_effect>(*this, std::string{event}, key));
    for (subscription& sub : subscriptions_[std::string{event}]) {
        if (sub.key == key) {
            sub.seq = seq;
        }
    }
    return seq;
}

void sandbox_impl::unsubscribe(const std::string& event, std::uint64_t key) noexcept {
    const auto it = subscriptions_.find(event);
    if (it == subscriptions_.end()) {
        return;
    }
    auto& subs = it->second;
    const auto sub = std::ranges::find(subs, key, &subscription::key);
    if (sub == subs.end()) {
        return;
    }
    luaL_unref(state_, LUA_REGISTRYINDEX, sub->fn_ref);
    subs.erase(sub);
    if (!subs.empty()) {
        return;
    }
    subscriptions_.erase(it);
    if (const auto attached = attached_.find(event); attached != attached_.end()) {
        attached->second->detach(this);
        attached_.erase(attached);
    }
}

void sandbox_impl::remove_by_id(lua_State* L, std::uint64_t seq) {
    const ledger::entry* entry = ledger_.find(seq);
    bool known = false;
    if (entry != nullptr && entry->owner == current_.module) {
        known = std::ranges::any_of(timers_, [seq](const auto& t) { return t.second.seq == seq; });
        for (const auto& [event, subs] : subscriptions_) {
            known = known || std::ranges::any_of(subs, [seq](const subscription& s) { return s.seq == seq; });
        }
    }
    if (!known) {
        stack{L}.raise(make_error(errc::kNotFound, std::format("no timer or subscription {} of this module", seq), "rhp.off"));
    }
    (void)ledger_.revert_entry(seq);
}

// ---- events ------------------------------------------------------------------------------------------

void sandbox_impl::deliver(std::string_view event, event_pusher args) {
    (void)protect(state_, [&] {
        const slice_scope slice{*this};
        const auto it = subscriptions_.find(event);
        if (it == subscriptions_.end()) {
            return;
        }
        const std::vector<subscription> snapshot = it->second; // handlers may (un)subscribe
        for (const subscription& sub : snapshot) {
            const auto now = subscriptions_.find(event);
            if (now == subscriptions_.end() || std::ranges::find(now->second, sub.key, &subscription::key) == now->second.end()) {
                continue;
            }
            const module_record* mod = record(sub.owner.module);
            std::string label = std::format("{} (event {})", mod != nullptr ? mod->name : "?", event);
            lua_rawgeti(state_, LUA_REGISTRYINDEX, sub.fn_ref);
            stack s{state_};
            const int nargs = args(s);
            request_record& req = start_request(request_kind::kEvent, sub.owner, std::move(label), nargs, false);
            (void)step(req, nargs);
        }
    });
}

void sandbox_impl::enqueue(std::string_view event, std::function<int(stack&)> args) noexcept {
    try {
        const std::scoped_lock lock{inbox_mutex_};
        inbox_.emplace_back(std::string{event}, std::move(args));
    } catch (...) { // out of memory: this sandbox misses the event
    }
}

// ---- require -------------------------------------------------------------------------------------------

bool sandbox_impl::depends_on(module_id from, module_id to, std::vector<module_id>& path) const {
    path.push_back(from);
    if (from == to) {
        return true;
    }
    if (const module_record* mod = record(from)) {
        const auto visit = [&](const std::set<module_id>& deps) {
            return std::ranges::any_of(deps, [&](module_id dep) { return std::ranges::find(path, dep) == path.end() && depends_on(dep, to, path); });
        };
        if (visit(mod->live.dependencies) || (mod->pending && visit(mod->pending->dependencies))) {
            return true;
        }
    }
    path.pop_back();
    return false;
}

void sandbox_impl::push_required(lua_State* L, std::string_view name) {
    const stack s{L};
    module_record* target = nullptr;
    for (auto& [id, mod] : modules_) {
        if (!mod.scratch && mod.name == name) {
            target = &mod;
        }
    }
    if (target == nullptr) {
        s.raise(make_error(errc::kNotFound, std::format("module '{}' is not loaded (require only finds loaded modules of this identity)", name), "require"));
    }
    if (target->id == current_.module) {
        s.raise(make_error(errc::kInvalidArgument, std::format("module '{}' can't require itself", name), "require"));
    }
    if (target->live.exports_ref == kNoRef) {
        const std::string why = target->state == module_state::kLoading ? "is still loading" : std::format("has no exports (it is {})", target->state);
        s.raise(make_error(errc::kInvalidArgument, std::format("module '{}' {}", name, why), "require"));
    }
    if (module_record* self = record(current_.module); self != nullptr && !self->scratch) {
        if (module_instance* instance = instance_of(*self, current_.revision); instance != nullptr && !instance->dependencies.contains(target->id)) {
            std::vector<module_id> path;
            if (depends_on(target->id, self->id, path)) {
                std::string chain = self->name;
                for (const module_id id : path) {
                    const module_record* step = record(id);
                    chain += std::format(" -> {}", step != nullptr ? step->name : "?");
                }
                s.raise(make_error(errc::kInvalidArgument, std::format("require cycle: {}", chain), "require"));
            }
            instance->dependencies.insert(target->id);
        }
    }

    const auto key = static_cast<lua_Integer>(target->id.value());
    lua_getfield(L, LUA_REGISTRYINDEX, kModuleProxiesKey);
    if (lua_rawgeti(L, -1, key) == LUA_TUSERDATA) {
        lua_remove(L, -2);
        return;
    }
    lua_pop(L, 1);
    auto* proxy = static_cast<module_proxy*>(lua_newuserdatauv(L, sizeof(module_proxy), 1));
    proxy->id = target->id.value();
    s.push_string(target->name);
    lua_setiuservalue(L, -2, 1);
    luaL_setmetatable(L, kModuleProxyKey);
    lua_pushvalue(L, -1);
    lua_rawseti(L, -3, key);
    lua_remove(L, -2);
}

void sandbox_impl::forget_proxy(module_id mod) noexcept {
    lua_getfield(state_, LUA_REGISTRYINDEX, kModuleProxiesKey);
    lua_pushnil(state_);
    lua_rawseti(state_, -2, static_cast<lua_Integer>(mod.value()));
    lua_pop(state_, 1);
}

std::vector<std::string> sandbox_impl::dependents_of(module_id mod) const {
    std::vector<std::string> out;
    for (const auto& [id, other] : modules_) {
        if (id != mod && (other.live.dependencies.contains(mod) || (other.pending && other.pending->dependencies.contains(mod)))) {
            out.push_back(other.name);
        }
    }
    return out;
}

// ---- requests --------------------------------------------------------------------------------------

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

template <class Pred>
void sandbox_impl::abandon_requests(Pred pred, std::string_view why) {
    std::vector<request_id> doomed;
    for (const auto& [id, req] : requests_) {
        if (!req->running && pred(*req)) {
            doomed.push_back(id);
        }
    }
    for (const request_id id : doomed) {
        auto node = requests_.extract(id);
        request_record& req = *node.mapped();
        close_thread(req, true);
        if (req.suspended_once) {
            finished_.emplace_back(id, fail(errc::kCancelled, std::string{why}, req.label));
        }
    }
}

request_record& sandbox_impl::start_request(request_kind kind, const effect_owner& owner, std::string label, int nargs, bool from_operation) {
    lua_State* L = state_;
    auto req = std::make_unique<request_record>();
    req->id = request_ids_.next();
    req->kind = kind;
    req->owner = owner;
    req->owner.request = req->id;
    req->label = std::move(label);

    lua_State* co = lua_newthread(L);
    lua_sethook(co, &sandbox_impl::count_hook, LUA_MASKCOUNT, static_cast<int>(check_interval()));
    lua_getfield(L, LUA_REGISTRYINDEX, kRequestThreadsKey);
    lua_pushvalue(L, -2);
    lua_pushboolean(L, 1);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    req->thread = co;
    req->thread_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_xmove(L, co, nargs + 1); // the function and its arguments

    if (from_operation) {
        last_request_ = req->id;
    }
    request_record& out = *req;
    requests_.emplace(out.id, std::move(req));
    return out;
}

std::optional<result<value_list>> sandbox_impl::step(request_record& req, int nargs) {
    if (take_cancel(req.id)) {
        return complete(req.id, std::unexpected{make_error(errc::kCancelled, "script cancelled")}); // never resumed again
    }
    req.sliced = false;
    req.wake_frame = 0;
    req.wake_time.reset();
    req.running = true;
    lua_State* from = running_.empty() || running_.back().thread == nullptr ? state_ : running_.back().thread;
    int status = LUA_OK;
    int nresults = 0;
    {
        const active_scope scope{*this, &req.budget, req.thread, &req, req.owner};
        status = lua_resume(req.thread, from, nargs, &nresults);
    }
    req.running = false;
    const sticky_stop stop = req.budget.sticky;

    if (status == LUA_YIELD) {
        lua_pop(req.thread, nresults);
        if (stop == sticky_stop::kNone) {
            if (req.wake_frame == 0 && !req.wake_time) {
                req.wake_frame = frame_ + 1; // a time slice ran out, or a plain coroutine.yield()
            }
            req.suspended_once = true;
            return std::nullopt;
        }
        return complete(req.id, std::unexpected{sticky_error(stop)});
    }
    if (status == LUA_OK) {
        // A stop wins even if the script swallowed it with pcall and returned normally.
        if (stop != sticky_stop::kNone) {
            return complete(req.id, std::unexpected{sticky_error(stop)});
        }
        return complete(req.id, nresults);
    }
    // The dead coroutine's stack is still intact: take the traceback before the error object
    // (unless memory ran out: building it would need more).
    if (status != LUA_ERRMEM && stop != sticky_stop::kMemory) {
        luaL_traceback(state_, req.thread, nullptr, 0);
        pending_traceback = lua_tostring(state_, -1);
        lua_pop(state_, 1);
    }
    lua_xmove(req.thread, state_, 1);
    error err = take_lua_error(state_, status);
    if (stop != sticky_stop::kNone) {
        err.code = sticky_error(stop).code;
    }
    return complete(req.id, std::unexpected{std::move(err)});
}

result<value_list> sandbox_impl::complete(request_id id, result<int> outcome) {
    auto node = requests_.extract(id);
    if (node.empty()) {
        return fail(errc::kNotFound, std::format("no request {}", id));
    }
    request_record& req = *node.mapped();
    module_record* mod = record(req.owner.module);

    result<value_list> out = value_list{};
    if (!outcome) {
        out = std::unexpected{std::move(outcome).error()};
    } else if (req.kind == request_kind::kExec || req.kind == request_kind::kCall) {
        out = collect_results(req.thread, 1, *outcome);
    } else if (req.kind == request_kind::kLoad) {
        out = mod != nullptr ? complete_load(*mod, req.owner.revision, req.thread) : fail(errc::kNotFound, "the module was unloaded");
    }

    if (!out) {
        if (out.error().where.empty() && !req.label.empty()) {
            out.error().where = req.label;
        }
        if (req.kind == request_kind::kExec) {
            (void)ledger_.revert_request(scratch_, req.id); // only this request's effects
        } else if (req.kind == request_kind::kLoad && mod != nullptr && mod->pending && mod->pending->revision == req.owner.revision) {
            abort_reload(*mod); // the old revision is untouched
        } else {
            fault_or_defer(req.owner, out.error());
        }
    }
    close_thread(req, !out.has_value());
    if (req.suspended_once) {
        finished_.emplace_back(req.id, out);
    }
    return out;
}

result<value_list> sandbox_impl::complete_load(module_record& mod, revision_id revision, lua_State* thread) {
    lua_State* L = state_;
    lua_xmove(thread, L, 1); // the exports table the loader returned
    if (mod.state == module_state::kLoading && mod.live.revision == revision) {
        mod.live.exports_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        mod.state = module_state::kActive;
        return value_list{};
    }
    if (!mod.pending || mod.pending->revision != revision) {
        lua_pop(L, 1);
        return fail(errc::kCancelled, "the reload was superseded");
    }
    mod.pending->exports_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // Carry state over: new.on_restore(old.on_save()).
    const effect_owner old_owner{mod.id, mod.live.revision};
    const effect_owner new_owner{mod.id, revision};
    const int base = lua_gettop(L);
    lua_pushnil(L); // the saved state
    if (mod.state == module_state::kActive && mod.live.exports_ref != kNoRef) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, mod.live.exports_ref);
        lua_getfield(L, -1, "on_save");
        lua_remove(L, -2);
        if (lua_type(L, -1) == LUA_TFUNCTION) {
            if (auto saved = call_sync(old_owner, 0, 1); !saved) {
                lua_settop(L, base);
                saved.error().where = std::format("{}.on_save", mod.name);
                return std::unexpected{std::move(saved).error()};
            }
            lua_replace(L, base + 1);
        } else {
            lua_pop(L, 1);
        }
    }
    lua_rawgeti(L, LUA_REGISTRYINDEX, mod.pending->exports_ref);
    lua_getfield(L, -1, "on_restore");
    lua_remove(L, -2);
    if (lua_type(L, -1) == LUA_TFUNCTION) {
        lua_pushvalue(L, base + 1);
        if (auto restored = call_sync(new_owner, 1, 0); !restored) {
            lua_settop(L, base);
            restored.error().where = std::format("{}.on_restore", mod.name);
            return std::unexpected{std::move(restored).error()};
        }
    } else {
        lua_pop(L, 1);
    }
    lua_settop(L, base);

    // Swap: the old revision goes, the new one is live.
    const revision_id old_revision = mod.live.revision;
    abandon_requests([&](const request_record& r) { return r.owner.module == mod.id && r.owner.revision == old_revision; },
                     "its module revision was replaced by a reload");
    (void)ledger_.revert_revision(mod.id, old_revision);
    release(mod.live);
    mod.live = std::move(*mod.pending);
    mod.pending.reset();
    if (mod.pending_source) {
        mod.history.push_back(std::move(*mod.pending_source));
        mod.pending_source.reset();
    }
    while (mod.history.size() > std::max<std::size_t>(options_.limits.revisions, 1)) {
        mod.history.pop_front();
    }
    mod.state = module_state::kActive;
    mod.fault.reset();
    return value_list{};
}

void sandbox_impl::close_thread(request_record& req, bool failed) noexcept {
    if (failed) {
        // Runs the pending to-be-closed variables of a coroutine that didn't return normally.
        (void)protect(state_, [&] {
            run_budget local;
            const active_scope scope{*this, running_.empty() ? &local : nullptr, nullptr, nullptr, req.owner};
            (void)lua_closethread(req.thread, state_);
        });
    }
    luaL_unref(state_, LUA_REGISTRYINDEX, req.thread_ref);
    req.thread_ref = kNoRef;
    req.thread = nullptr;
}

result<void> sandbox_impl::call_sync(const effect_owner& owner, int nargs, int nresults) {
    run_budget local;
    run_budget* budget = running_.empty() ? &local : nullptr;
    const int base = lua_gettop(state_) - nargs - 1;
    result<void> called;
    {
        const active_scope scope{*this, budget, nullptr, nullptr, owner};
        called = stack{state_}.call(nargs, nresults);
    }
    if (budget != nullptr && local.sticky != sticky_stop::kNone) {
        error stop = sticky_error(local.sticky);
        if (called) {
            lua_settop(state_, base);
            return std::unexpected{std::move(stop)};
        }
        called.error().code = stop.code;
    }
    return called;
}

value_list sandbox_impl::collect_results(lua_State* L, int first, int last) {
    value_list out;
    out.reserve(static_cast<std::size_t>(std::max(0, last - first + 1)));
    const stack s{L};
    for (int i = first; i <= last; ++i) {
        auto v = s.to_value(i);
        if (v) {
            out.push_back(std::move(*v));
        } else {
            out.emplace_back(std::format("{}: {}", luaL_typename(L, i), lua_topointer(L, i)));
        }
    }
    return out;
}

// ---- faults --------------------------------------------------------------------------------------

void sandbox_impl::fault_or_defer(const effect_owner& owner, error err) {
    if (running_.empty()) {
        fault(owner, std::move(err));
    } else {
        pending_faults_.emplace_back(owner, std::move(err));
    }
}

void sandbox_impl::fault(const effect_owner& owner, error err) {
    module_record* mod = record(owner.module);
    if (mod == nullptr) {
        return;
    }
    if (mod->scratch) {
        // Scratch code faults only its own request's effects (earlier exec effects stay).
        if (owner.request) {
            abandon_requests([&](const request_record& r) { return r.id == owner.request; }, "the script faulted");
            (void)ledger_.revert_request(scratch_, owner.request);
        } else {
            (void)ledger_.revert(scratch_);
        }
        return;
    }
    if (mod->pending && owner.revision == mod->pending->revision) {
        abort_reload(*mod); // a fault of the incoming revision fails the reload; the live one stays
        return;
    }
    if (owner.revision && owner.revision != mod->live.revision) {
        return; // a revision that was already replaced
    }
    if (mod->state != module_state::kActive && mod->state != module_state::kLoading) {
        return;
    }
    abandon_requests([&](const request_record& r) { return r.owner.module == mod->id; }, "its module faulted");
    abort_reload(*mod);
    auto report = ledger_.revert(mod->id);
    if (!report.clean()) {
        err.message += std::format(" (revert left {} effect(s) in place)", report.failures.size());
    }
    mod->state = module_state::kFaulted;
    mod->fault = std::move(err);
}

void sandbox_impl::abort_reload(module_record& mod) noexcept {
    if (!mod.pending) {
        return;
    }
    const revision_id revision = mod.pending->revision;
    try {
        abandon_requests([&](const request_record& r) { return r.owner.module == mod.id && r.owner.revision == revision; },
                         "the reload was abandoned");
        (void)ledger_.revert_revision(mod.id, revision);
    } catch (...) { // out of memory while reporting: the revision's effects are still owned by the ledger
    }
    release(*mod.pending);
    mod.pending.reset();
    mod.pending_source.reset();
}

void sandbox_impl::release(module_instance& instance) noexcept {
    luaL_unref(state_, LUA_REGISTRYINDEX, instance.exports_ref);
    luaL_unref(state_, LUA_REGISTRYINDEX, instance.env_ref);
    instance.exports_ref = kNoRef;
    instance.env_ref = kNoRef;
}

// ---- deferred work -----------------------------------------------------------------------------------

bool sandbox_impl::defer_if_running(std::function<void()> op) {
    if (running_.empty()) {
        return false;
    }
    deferred_.push_back(std::move(op));
    return true;
}

void sandbox_impl::drain() {
    if (!running_.empty()) {
        return;
    }
    std::vector<request_id> cancels;
    {
        const std::scoped_lock lock{inbox_mutex_};
        cancels.swap(cancel_ids_);
        cancel_ids_pending_.store(false, std::memory_order_release);
    }
    for (const request_id id : cancels) {
        if (const auto it = requests_.find(id); it != requests_.end() && !it->second->running) {
            (void)complete(id, std::unexpected{make_error(errc::kCancelled, "script cancelled")});
        }
    }
    for (auto& [owner, err] : std::exchange(pending_faults_, {})) {
        fault(owner, std::move(err));
    }
    for (auto& op : std::exchange(deferred_, {})) {
        op();
    }
    // Last: the callback may re-enter the sandbox.
    if (options_.on_result) {
        for (auto& [id, r] : std::exchange(finished_, {})) {
            options_.on_result(id, r);
        }
    } else {
        finished_.clear();
    }
}

// ---- the frame ---------------------------------------------------------------------------------------

void sandbox_impl::fire_timers() {
    const steady::time_point now = script_now();
    std::vector<std::pair<steady::time_point, std::uint64_t>> due;
    for (const auto& [key, timer] : timers_) {
        if (timer.due <= now) {
            due.emplace_back(timer.due, key);
        }
    }
    std::ranges::sort(due);
    for (const auto& [when, key] : due) {
        const auto it = timers_.find(key);
        if (it == timers_.end()) {
            continue; // an earlier callback removed it
        }
        timer_record& timer = it->second;
        const effect_owner owner = timer.owner;
        std::uint64_t retire = 0;
        if (timer.repeating) {
            timer.due += timer.interval;
            if (timer.due <= now) {
                timer.due = now + timer.interval; // fell behind: no burst of catch-up calls
            }
        } else {
            retire = timer.seq;
        }
        const module_record* mod = record(owner.module);
        std::string label = std::format("{} (timer)", mod != nullptr ? mod->name : "?");
        lua_rawgeti(state_, LUA_REGISTRYINDEX, timer.fn_ref);
        request_record& req = start_request(request_kind::kTimer, owner, std::move(label), 0, false);
        if (retire != 0) {
            (void)ledger_.revert_entry(retire); // a one-shot timer is spent once its call starts
        }
        (void)step(req, 0);
    }
}

void sandbox_impl::resume_ready() {
    const steady::time_point now = script_now();
    std::vector<request_id> ready;
    for (const auto& [id, req] : requests_) {
        if (!req->running && ((req->wake_frame != 0 && frame_ >= req->wake_frame) || (req->wake_time && now >= *req->wake_time))) {
            ready.push_back(id);
        }
    }
    // Round robin from the request after the one resumed last, so with slicing on a busy request
    // can't take every slice.
    std::ranges::rotate(ready, std::ranges::upper_bound(ready, last_resumed_));
    for (const request_id id : ready) {
        if (slice_deadline_ && steady::now() >= *slice_deadline_) {
            return; // the rest stay ready for the next pump()
        }
        if (const auto it = requests_.find(id); it != requests_.end()) {
            last_resumed_ = id;
            (void)step(*it->second, 0);
        }
    }
}

// ---- operations ----------------------------------------------------------------------------------

result<void> sandbox_impl::install_lib(std::string_view name, c_function build, std::string (*describe)(role)) {
    drain();
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
    if (out) {
        describers_.push_back(describe);
    }
    return out;
}

result<value_list> sandbox_impl::exec(std::string_view source, std::string_view chunk_name) {
    drain();
    const std::string chunk = std::format("={}", chunk_name);
    result<value_list> out = value_list{};
    auto glue = protect(state_, [&] {
        const slice_scope slice{*this};
        if (auto compiled = compile(source, chunk, record(scratch_)->live.env_ref); !compiled) {
            out = std::unexpected{std::move(compiled).error()};
            return;
        }
        request_record& req = start_request(request_kind::kExec, effect_owner{scratch_}, std::string{}, 0, true);
        if (auto done = step(req, 0)) {
            out = std::move(*done);
        }
    });
    if (!glue) {
        out = std::unexpected{std::move(glue).error()};
    }
    drain();
    return out;
}

result<module_id> sandbox_impl::load(std::string_view name, std::string_view source) {
    drain();
    if (!utils::is_dotted_name(name)) {
        return fail(errc::kInvalidArgument, std::format("'{}' is not a module name (dotted lowercase, e.g. combat.low_grav)", name));
    }
    if (const auto existing = find(name)) {
        auto reloaded = reload(*existing, source);
        if (!reloaded) {
            return std::unexpected{std::move(reloaded).error()};
        }
        return *existing;
    }
    const module_id id = ids_.next();
    {
        module_record mod;
        mod.id = id;
        mod.name = std::string{name};
        mod.state = module_state::kLoading;
        mod.revisions_made = 1;
        mod.live.revision = revision_id{1};
        mod.history.push_back(revision_source{revision_id{1}, std::string{source}, source_hash(source)});
        modules_.emplace(id, std::move(mod));
    }

    const std::string chunk = std::format("@{}", name);
    bool compiled_ok = false;
    std::optional<error> failure;
    auto glue = protect(state_, [&] {
        lua_State* L = state_;
        const slice_scope slice{*this};
        module_record& mod = *record(id);
        mod.live.env_ref = new_environment();
        if (auto compiled = compile(source, chunk, mod.live.env_ref); !compiled) {
            failure = std::move(compiled).error();
            return;
        }
        compiled_ok = true;
        lua_rawgeti(L, LUA_REGISTRYINDEX, loader_ref_);
        lua_insert(L, -2);
        lua_rawgeti(L, LUA_REGISTRYINDEX, mod.live.env_ref);
        request_record& req = start_request(request_kind::kLoad, effect_owner{id, mod.live.revision}, mod.name, 2, true);
        if (auto done = step(req, 2); done && !*done) {
            failure = std::move(*done).error();
        }
    });
    if (!glue && !failure) {
        failure = std::move(glue).error();
        if (compiled_ok) {
            fault_or_defer(effect_owner{id, revision_id{1}}, *failure);
        }
    }
    if (failure && !compiled_ok) {
        if (module_record* mod = record(id)) {
            release(mod->live);
        }
        modules_.erase(id);
    }
    drain();
    if (failure) {
        if (failure->where.empty()) {
            failure->where = std::string{name};
        }
        return std::unexpected{std::move(*failure)};
    }
    return id;
}

result<revision_id> sandbox_impl::reload(module_id id, std::string_view source) {
    const module_record* found = record(id);
    if (found == nullptr || found->scratch) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (defer_if_running([this, id, src = std::string{source}] { (void)reload(id, src); })) {
        return revision_id{};
    }
    drain();
    module_record* mod = record(id);
    if (mod == nullptr) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (mod->state == module_state::kLoading) {
        return fail(errc::kInvalidArgument, std::format("module '{}' is still loading", mod->name), mod->name);
    }
    if (mod->pending) {
        return fail(errc::kInvalidArgument, std::format("a reload of module '{}' is already loading", mod->name), mod->name);
    }
    const revision_id revision{++mod->revisions_made};
    const std::string chunk = std::format("@{}", mod->name);
    result<revision_id> out = revision;
    auto glue = protect(state_, [&] {
        lua_State* L = state_;
        const slice_scope slice{*this};
        mod->pending = module_instance{revision};
        mod->pending_source = revision_source{revision, std::string{source}, source_hash(source)};
        mod->pending->env_ref = new_environment();
        if (auto compiled = compile(source, chunk, mod->pending->env_ref); !compiled) {
            out = std::unexpected{std::move(compiled).error()};
            return;
        }
        lua_rawgeti(L, LUA_REGISTRYINDEX, loader_ref_);
        lua_insert(L, -2);
        lua_rawgeti(L, LUA_REGISTRYINDEX, mod->pending->env_ref);
        request_record& req = start_request(request_kind::kLoad, effect_owner{id, revision}, mod->name, 2, true);
        if (auto done = step(req, 2)) {
            if (!*done) {
                out = std::unexpected{std::move(*done).error()};
            }
        } else {
            out = revision_id{}; // still loading: the swap happens in a later pump()
        }
    });
    if (!glue) {
        out = std::unexpected{std::move(glue).error()};
    }
    if (!out) {
        if (module_record* still = record(id); still != nullptr && still->pending && still->pending->revision == revision) {
            abort_reload(*still);
        }
        if (out.error().where.empty()) {
            out.error().where = std::string{record(id) != nullptr ? record(id)->name : std::string{}};
        }
    }
    drain();
    return out;
}

result<revision_id> sandbox_impl::rollback(module_id id, std::size_t steps) {
    const module_record* mod = record(id);
    if (mod == nullptr || mod->scratch) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (steps == 0 || steps >= mod->history.size()) {
        return fail(errc::kOutOfRange, std::format("module '{}' keeps {} revision(s); can't go back {}", mod->name, mod->history.size(), steps),
                    mod->name);
    }
    const std::string source = mod->history[mod->history.size() - 1 - steps].source;
    return reload(id, source);
}

result<value_list> sandbox_impl::call(module_id id, std::string_view function, std::span<const value> args) {
    drain();
    module_record* mod = record(id);
    if (mod == nullptr || mod->scratch) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (mod->state != module_state::kActive) {
        return fail(errc::kInvalidArgument, std::format("module '{}' is {}", mod->name, mod->state), mod->name);
    }
    result<value_list> out = value_list{};
    auto glue = protect(state_, [&] {
        lua_State* L = state_;
        const slice_scope slice{*this};
        const int base = lua_gettop(L);
        lua_rawgeti(L, LUA_REGISTRYINDEX, mod->live.exports_ref);
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
        request_record& req = start_request(request_kind::kCall, effect_owner{id, mod->live.revision}, std::format("{}.{}", mod->name, function),
                                            static_cast<int>(args.size()), true);
        if (auto done = step(req, static_cast<int>(args.size()))) {
            out = std::move(*done);
        }
    });
    if (!glue) {
        out = std::unexpected{std::move(glue).error()};
    }
    drain();
    return out;
}

revert_report sandbox_impl::revert_module(module_record& mod) {
    abandon_requests([&](const request_record& r) { return r.owner.module == mod.id; }, "its module was reverted");
    abort_reload(mod);
    auto report = ledger_.revert(mod.id);
    if (!mod.scratch && (mod.state == module_state::kActive || mod.state == module_state::kLoading)) {
        mod.state = module_state::kReverted;
    }
    return report;
}

result<revert_report> sandbox_impl::revert(module_id id) {
    if (record(id) == nullptr) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (defer_if_running([this, id] {
            if (module_record* mod = record(id)) {
                (void)revert_module(*mod);
            }
        })) {
        revert_report report;
        report.deferred = true;
        return report;
    }
    drain();
    module_record* mod = record(id);
    if (mod == nullptr) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    auto report = revert_module(*mod);
    drain();
    return report;
}

revert_report sandbox_impl::unload_module(module_record& mod) {
    if (mod.state == module_state::kActive && mod.live.exports_ref != kNoRef) {
        // on_unload errors are ignored: the module is going away regardless.
        (void)protect(state_, [&] {
            lua_State* L = state_;
            const int base = lua_gettop(L);
            lua_rawgeti(L, LUA_REGISTRYINDEX, mod.live.exports_ref);
            lua_getfield(L, -1, "on_unload");
            lua_remove(L, -2);
            if (lua_type(L, -1) == LUA_TFUNCTION) {
                (void)call_sync(effect_owner{mod.id, mod.live.revision}, 0, 0);
            }
            lua_settop(L, base);
        });
    }
    auto report = revert_module(mod);
    const module_id id = mod.id;
    release(mod.live);
    forget_proxy(id);
    for (auto& [other_id, other] : modules_) {
        other.live.dependencies.erase(id);
        if (other.pending) {
            other.pending->dependencies.erase(id);
        }
    }
    modules_.erase(id);
    return report;
}

result<revert_report> sandbox_impl::unload(module_id id, bool forced) {
    const module_record* found = record(id);
    if (found == nullptr) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (found->scratch) {
        return fail(errc::kInvalidArgument, "the scratch module can't be unloaded; revert it instead", found->name);
    }
    if (!forced) {
        if (const auto dependents = dependents_of(id); !dependents.empty()) {
            std::string names;
            for (const auto& name : dependents) {
                names += names.empty() ? name : ", " + name;
            }
            return fail(errc::kHasDependents, std::format("module '{}' is required by {} (unload them first, or force)", found->name, names),
                        found->name);
        }
    }
    if (defer_if_running([this, id] {
            if (module_record* mod = record(id)) {
                (void)unload_module(*mod);
            }
        })) {
        revert_report report;
        report.deferred = true;
        return report;
    }
    drain();
    module_record* mod = record(id);
    if (mod == nullptr) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    auto report = unload_module(*mod);
    drain();
    return report;
}

result<void> sandbox_impl::checkpoint(std::string_view tag) {
    checkpoints_.insert_or_assign(std::string{tag}, ledger::mark());
    return {};
}

result<revert_report> sandbox_impl::revert_to(std::string_view tag) {
    const auto it = checkpoints_.find(tag);
    if (it == checkpoints_.end()) {
        return fail(errc::kNotFound, std::format("no checkpoint '{}'", tag));
    }
    const std::uint64_t mark = it->second;
    const auto apply = [this, mark] {
        auto report = ledger_.revert_after(mark);
        std::erase_if(checkpoints_, [mark](const auto& entry) { return entry.second > mark; });
        return report;
    };
    if (defer_if_running([apply] { (void)apply(); })) {
        revert_report report;
        report.deferred = true;
        return report;
    }
    drain();
    auto report = apply();
    drain();
    return report;
}

revert_report sandbox_impl::revert_all() {
    const auto apply = [this] {
        revert_report report;
        std::vector<module_id> ids;
        for (const auto& [id, mod] : modules_) {
            if (!mod.scratch) {
                ids.push_back(id);
            }
        }
        for (auto it = ids.rbegin(); it != ids.rend(); ++it) {
            if (module_record* mod = record(*it)) {
                report += unload_module(*mod);
            }
        }
        report += revert_module(*record(scratch_));
        return report;
    };
    if (defer_if_running([apply] { (void)apply(); })) {
        revert_report report;
        report.deferred = true;
        return report;
    }
    drain();
    auto report = apply();
    drain();
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
    module_info info{mod->id, mod->name, mod->state, mod->scratch, ledger_.count(id), ledger_.irreversible_count(id), mod->fault};
    info.revision = mod->live.revision;
    info.source_hash = mod->history.empty() ? 0 : mod->history.back().hash;
    info.revisions = mod->history.size();
    info.reloading = mod->pending.has_value();
    info.dependencies.assign(mod->live.dependencies.begin(), mod->live.dependencies.end());
    return info;
}

std::vector<module_info> sandbox_impl::list() const {
    std::vector<module_info> out;
    out.reserve(modules_.size());
    for (const auto& [id, mod] : modules_) {
        out.push_back(*status(id));
    }
    return out;
}

void sandbox_impl::cancel() noexcept {
    cancel_running_.store(true, std::memory_order_release);
}

void sandbox_impl::cancel(request_id request) noexcept {
    try {
        const std::scoped_lock lock{inbox_mutex_};
        cancel_ids_.push_back(request);
        cancel_ids_pending_.store(true, std::memory_order_release);
    } catch (...) { // out of memory: the request keeps running
    }
}

void sandbox_impl::pump() {
    thread_.store(std::this_thread::get_id(), std::memory_order_release);
    drain();
    ++frame_;
    decltype(inbox_) inbox;
    {
        const std::scoped_lock lock{inbox_mutex_};
        inbox.swap(inbox_);
    }
    (void)protect(state_, [&] {
        const slice_scope slice{*this};
        for (auto& [event, args] : inbox) {
            deliver(event, event_pusher{&args, [](stack& s, const void* data) {
                                            return (*static_cast<const std::function<int(stack&)>*>(data))(s);
                                        }});
        }
        fire_timers();
        resume_ready();
    });
    drain();
}

std::size_t sandbox_impl::suspended() const noexcept {
    return static_cast<std::size_t>(std::ranges::count_if(requests_, [](const auto& entry) { return !entry.second->running; }));
}

std::string sandbox_impl::stubs() const {
    std::string out = script::stubs::rhp_api(options_.caller_role);
    for (const auto describe : describers_) {
        out += '\n';
        out += describe(options_.caller_role);
    }
    return out;
}

} // namespace detail

// ---- sandbox (public) ------------------------------------------------------------------------------

sandbox::sandbox(sandbox_options options) : impl_(std::make_unique<detail::sandbox_impl>(std::move(options))) {}

sandbox::~sandbox() = default;
sandbox::sandbox(sandbox&&) noexcept = default;
sandbox& sandbox::operator=(sandbox&&) noexcept = default;

result<void> sandbox::install_lib(std::string_view name, c_function build, stub_fn describe) {
    return impl_->install_lib(name, build, describe);
}

result<value_list> sandbox::exec(std::string_view source, std::string_view chunk_name) {
    return impl_->exec(source, chunk_name);
}

result<module_id> sandbox::load(std::string_view name, std::string_view source) {
    return impl_->load(name, source);
}

result<revision_id> sandbox::reload(module_id mod, std::string_view source) {
    return impl_->reload(mod, source);
}

result<revision_id> sandbox::rollback(module_id mod, std::size_t steps) {
    return impl_->rollback(mod, steps);
}

result<value_list> sandbox::call(module_id mod, std::string_view function, std::span<const value> args) {
    return impl_->call(mod, function, args);
}

result<revert_report> sandbox::revert(module_id mod) {
    return impl_->revert(mod);
}

result<revert_report> sandbox::unload(module_id mod) {
    return impl_->unload(mod, false);
}

result<revert_report> sandbox::unload(module_id mod, force_t) {
    return impl_->unload(mod, true);
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

void sandbox::cancel(request_id request) noexcept {
    impl_->cancel(request);
}

void sandbox::pump() {
    impl_->pump();
}

request_id sandbox::last_request() const noexcept {
    return impl_->last_request();
}

std::size_t sandbox::suspended() const noexcept {
    return impl_->suspended();
}

std::uint64_t sandbox::frame() const noexcept {
    return impl_->frame();
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

std::string sandbox::stubs() const {
    return impl_->stubs();
}

} // namespace Rhp::script

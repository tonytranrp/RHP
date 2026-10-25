// Test tools in the sandbox: the meter (exact instruction counts, time, allocations), line coverage,
// garbage collection control, and `__rhp_test`, the bridge the Lua test framework (Rhp::test) runs
// on: journaled swaps of lib members, module exports and handle members, firing events, calling
// patch points, the script clock and the runner's own services.

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <format>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <lauxlib.h>
#include <lua.h>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/detail/event_registry.hpp>
#include <rhp/script/detail/patch_registry.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/puc_lua/lua_internals.hpp>
#include <rhp/script/puc_lua/sandbox_impl.hpp>
#include <rhp/script/puc_lua/tools.hpp>
#include <rhp/script/stack.hpp>
#include <rhp/script/testing.hpp>
#include <rhp/utils/scope_guard.hpp>

namespace Rhp::script::detail {

namespace {

constexpr const char* kBridgeName = "__rhp_test";
constexpr const char* kLibMarker = "__rhp_lib";        // lib proxies' metatables (lib_proxy.cpp)
constexpr const char* kHandleTypeField = "__rhp_type"; // handle metatables (stack.cpp)
constexpr const char* kMethodsField = "__rhp_methods"; // a handle metatable's methods
constexpr const char* kGettersField = "__rhp_getters"; // and its properties

// Runs a callable inside lua_pcall (see sandbox.cpp): any Lua error becomes an error result.
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

double milliseconds_of(steady::duration d) {
    return std::chrono::duration<double, std::milli>{d}.count();
}

// Swapped table slots, put back when undone: {table, key, original} as registry references.
class slot_swap_effect final : public effect {
public:
    struct slot {
        int table = LUA_NOREF;
        int key = LUA_NOREF;
        int original = LUA_NOREF;
    };

    slot_swap_effect(lua_State* L, std::vector<slot> slots) : L_(L), slots_(std::move(slots)) {}

    slot_swap_effect(const slot_swap_effect&) = delete;
    slot_swap_effect& operator=(const slot_swap_effect&) = delete;

    ~slot_swap_effect() override { release(); }

    void undo() override {
        // Newest first; rawset on a key the table holds doesn't allocate, so this can't raise.
        for (auto it = slots_.rbegin(); it != slots_.rend(); ++it) {
            lua_rawgeti(L_, LUA_REGISTRYINDEX, it->table);
            lua_rawgeti(L_, LUA_REGISTRYINDEX, it->key);
            lua_rawgeti(L_, LUA_REGISTRYINDEX, it->original);
            lua_rawset(L_, -3);
            lua_pop(L_, 1);
        }
        release();
    }

private:
    void release() noexcept {
        for (slot& s : slots_) {
            for (int* ref : {&s.table, &s.key, &s.original}) {
                if (*ref != LUA_NOREF) {
                    luaL_unref(L_, LUA_REGISTRYINDEX, *ref);
                    *ref = LUA_NOREF;
                }
            }
        }
        slots_.clear();
    }

    lua_State* L_;
    std::vector<slot> slots_;
};

// What a value is to the bridge.
enum class target_kind : std::uint8_t {
    kLib,
    kModule,
    kHandle,
    kTable,
    kOther
};

bool metatable_has(lua_State* L, int index, const char* field) {
    if (lua_getmetatable(L, index) == 0) {
        return false;
    }
    lua_pushstring(L, field);
    const bool has = lua_rawget(L, -2) != LUA_TNIL;
    lua_pop(L, 2);
    return has;
}

target_kind kind_of(lua_State* L, int index) {
    switch (lua_type(L, index)) {
    case LUA_TTABLE: return target_kind::kTable;
    case LUA_TUSERDATA:
        if (metatable_has(L, index, kLibMarker)) {
            return target_kind::kLib;
        }
        if (luaL_testudata(L, index, "rhp.module") != nullptr) {
            return target_kind::kModule;
        }
        if (metatable_has(L, index, kHandleTypeField)) {
            return target_kind::kHandle;
        }
        return target_kind::kOther;
    default: return target_kind::kOther;
    }
}

// Pushes the members table of a lib proxy at `index` (its metatable's __index).
void push_lib_members(lua_State* L, int index) {
    lua_getmetatable(L, index);
    lua_getfield(L, -1, "__index");
    lua_remove(L, -2);
}

// Pushes the getters or setters table of a lib proxy: upvalue 1 of the members' __index
// (getters) or of the proxy's __newindex (setters).
void push_lib_accessors(lua_State* L, int index, bool setters) {
    if (setters) {
        lua_getmetatable(L, index);
        lua_getfield(L, -1, "__newindex");
    } else {
        push_lib_members(L, index);
        lua_getmetatable(L, -1);
        lua_getfield(L, -1, "__index");
        lua_remove(L, -2);
    }
    lua_getupvalue(L, -1, 1);
    lua_replace(L, -3);
    lua_pop(L, 1);
}

// Pushes field `field` (the methods or getters table) of a handle's metatable, or nil.
void push_handle_table(lua_State* L, int index, const char* field) {
    lua_getmetatable(L, index);
    lua_getfield(L, -1, field);
    lua_remove(L, -2);
}

int bridge_kind(lua_State* L) {
    switch (kind_of(L, 1)) {
    case target_kind::kLib: lua_pushliteral(L, "lib"); break;
    case target_kind::kModule: lua_pushliteral(L, "module"); break;
    case target_kind::kHandle: lua_pushliteral(L, "handle"); break;
    case target_kind::kTable: lua_pushliteral(L, "table"); break;
    case target_kind::kOther: lua_pushstring(L, luaL_typename(L, 1)); break;
    }
    return 1;
}

// members(target) -> {name = kind}: "function", "variable", "readonly", "lib" for a lib proxy;
// "method", "property" for a handle; the Lua type of each export / field otherwise.
int bridge_members(lua_State* L) {
    lua_settop(L, 1);
    lua_newtable(L);
    const int out = 2;
    const auto add_all = [&](int table, const char* forced) {
        lua_pushnil(L);
        while (lua_next(L, table) != 0) {
            lua_pushvalue(L, -2);
            if (forced != nullptr) {
                lua_pushstring(L, forced);
            } else if (lua_type(L, -2) == LUA_TUSERDATA && metatable_has(L, -2, kLibMarker)) {
                lua_pushliteral(L, "lib");
            } else {
                lua_pushstring(L, luaL_typename(L, -2));
            }
            lua_rawset(L, out);
            lua_pop(L, 1);
        }
    };
    switch (kind_of(L, 1)) {
    case target_kind::kLib: {
        push_lib_accessors(L, 1, false);
        const int getters = lua_gettop(L);
        push_lib_accessors(L, 1, true);
        const int setters = lua_gettop(L);
        lua_pushnil(L);
        while (lua_next(L, getters) != 0) {
            lua_pop(L, 1);
            lua_pushvalue(L, -1);
            lua_pushvalue(L, -1);
            const bool writable = lua_rawget(L, setters) != LUA_TNIL;
            lua_pop(L, 1);
            lua_pushstring(L, writable ? "variable" : "readonly");
            lua_rawset(L, out);
        }
        push_lib_members(L, 1);
        add_all(lua_gettop(L), nullptr);
        break;
    }
    case target_kind::kHandle: {
        push_handle_table(L, 1, kMethodsField);
        if (lua_istable(L, -1)) {
            add_all(lua_gettop(L), "method");
        }
        push_handle_table(L, 1, kGettersField);
        if (lua_istable(L, -1)) {
            add_all(lua_gettop(L), "property");
        }
        break;
    }
    case target_kind::kModule: {
        const module_record* mod = impl_of(L).module_of_proxy(L, 1);
        if (mod != nullptr && mod->live.exports_ref != kNoRef) {
            lua_rawgeti(L, LUA_REGISTRYINDEX, mod->live.exports_ref);
            add_all(lua_gettop(L), nullptr);
        }
        break;
    }
    case target_kind::kTable: add_all(1, nullptr); break;
    case target_kind::kOther: break;
    }
    lua_settop(L, out);
    return 1;
}

// swap(target, key, value) -> original: journaled (undone with the request's or checkpoint's
// effects). A lib: a function or sub-lib member. A module: one of its exports. A handle (any handle
// of the type): a method, or a property's getter (called with the handle). A table: a field.
int bridge_swap(lua_State* L) {
    lua_settop(L, 3);
    impl_of(L).swap_member(L, 1, 2);
    return 1;
}

// swap_var(lib, name, getter, setter) -> original getter, original setter (functions; setter may be
// nil for a read-only variable).
int bridge_swap_var(lua_State* L) {
    lua_settop(L, 4);
    impl_of(L).swap_variable(L, 1, 2, 3, 4);
    return 2;
}

// meter() -> {instructions, active_ms, allocations, frees, bytes, memory, peak, objects = {kind = n}}
int bridge_meter(lua_State* L) {
    auto& impl = impl_of(L);
    impl.credit_hook_progress(L); // the instructions this thread ran so far
    const run_meter m = impl.meter();
    lua_createtable(L, 0, 8);
    const auto set_int = [L](const char* name, std::uint64_t v) {
        lua_pushinteger(L, static_cast<lua_Integer>(std::min<std::uint64_t>(v, static_cast<std::uint64_t>((std::numeric_limits<lua_Integer>::max)()))));
        lua_setfield(L, -2, name);
    };
    set_int("instructions", m.instructions);
    lua_pushnumber(L, std::chrono::duration<double, std::milli>{m.active}.count());
    lua_setfield(L, -2, "active_ms");
    set_int("allocations", m.allocations);
    set_int("frees", m.frees);
    set_int("bytes", m.bytes_allocated);
    set_int("memory", m.memory);
    set_int("peak", m.peak);
    lua_createtable(L, 0, static_cast<int>(kAllocKinds));
    for (std::size_t i = 0; i < kAllocKinds; ++i) {
        const std::string_view name = to_string(static_cast<alloc_kind>(i));
        lua_pushinteger(L, static_cast<lua_Integer>(m.objects[i]));
        lua_setfield(L, -2, std::string{name}.c_str());
    }
    lua_setfield(L, -2, "objects");
    lua_pushboolean(L, impl.metering() ? 1 : 0);
    lua_setfield(L, -2, "metering");
    return 1;
}

int bridge_reset_peak(lua_State* L) {
    impl_of(L).reset_peak();
    return 0;
}

int bridge_gc(lua_State* L) {
    lua_gc(L, LUA_GCCOLLECT);
    lua_gc(L, LUA_GCCOLLECT);
    return 0;
}

// gc_mode("incremental" | "generational") -> the previous mode
int bridge_gc_mode(lua_State* L) {
    std::size_t len = 0;
    const char* mode = luaL_checklstring(L, 1, &len);
    const std::string_view m{mode, len};
    int previous = 0;
    if (m == "incremental") {
        previous = lua_gc(L, LUA_GCINC);
    } else if (m == "generational") {
        previous = lua_gc(L, LUA_GCGEN);
    } else {
        return luaL_argerror(L, 1, "expected 'incremental' or 'generational'");
    }
    lua_pushstring(L, previous == LUA_GCGEN ? "generational" : "incremental");
    return 1;
}

// next_due() -> milliseconds until the earliest timer or sleeping request (nil: none waits for time)
int bridge_next_due(lua_State* L) {
    auto& impl = impl_of(L);
    const auto due = impl.next_due();
    if (!due) {
        lua_pushnil(L);
        return 1;
    }
    lua_pushnumber(L, std::max(0.0, milliseconds_of(*due - impl.script_now())));
    return 1;
}

// now() -> milliseconds of script time since enable_testing
int bridge_now(lua_State* L) {
    lua_pushnumber(L, milliseconds_of(impl_of(L).script_elapsed()));
    return 1;
}

// The values of the arguments from `first` on (raises for one that has no value form).
std::vector<value> values_from(lua_State* L, int first) {
    const stack s{L};
    std::vector<value> out;
    const int top = lua_gettop(L);
    std::optional<error> failure;
    for (int i = first; i <= top && !failure; ++i) {
        auto v = s.to_value(i);
        if (!v) {
            failure = std::move(v).error();
            failure->where = std::format("argument {}", i - first + 1);
        } else {
            out.push_back(std::move(*v));
        }
    }
    if (failure) {
        out.clear();
        s.raise(*failure);
    }
    return out;
}

// host(command, ...) -> the runner's answer (a value)
int bridge_host(lua_State* L) {
    const stack s{L};
    auto& impl = impl_of(L);
    std::size_t len = 0;
    const char* command = luaL_checklstring(L, 1, &len);
    std::optional<error> failure;
    {
        const std::vector<value> args = values_from(L, 2);
        if (!impl.test_options().host) {
            failure = make_error(errc::kNotFound, "this sandbox's runner offers no services", "__rhp_test.host");
        } else {
            result<value> answer = [&]() -> result<value> {
                try {
                    return impl.test_options().host(std::string_view{command, len}, args);
                } catch (const std::exception& e) {
                    return fail(errc::kRuntime, e.what());
                }
            }();
            if (!answer) {
                failure = std::move(answer).error();
            } else {
                s.push_value(*answer);
            }
        }
    }
    if (failure) {
        if (failure->where.empty()) {
            failure->where = std::string{command, len};
        }
        s.raise(*failure);
    }
    return 1;
}

// The arguments of a fire from Lua: registry references to the values, pushed as they are.
struct ref_args {
    lua_State* L;
    std::vector<int> refs;
};

int push_ref_args(stack& s, const void* data) {
    const auto& args = *static_cast<const ref_args*>(data);
    for (const int ref : args.refs) {
        lua_rawgeti(s.state(), LUA_REGISTRYINDEX, ref); // shared by every thread of the state
    }
    return static_cast<int>(args.refs.size());
}

std::vector<value> ref_values(const void* data) {
    const auto& args = *static_cast<const ref_args*>(data);
    std::vector<value> out;
    const stack s{args.L};
    for (const int ref : args.refs) {
        lua_rawgeti(args.L, LUA_REGISTRYINDEX, ref);
        auto v = s.to_value(-1);
        out.push_back(v ? std::move(*v) : value{});
        lua_pop(args.L, 1);
    }
    return out;
}

std::function<int(stack&)> own_ref_args(const void* data) {
    // Another thread's sandbox gets the plain values (a handle or a function can't cross).
    std::vector<value> values = ref_values(data);
    return [values = std::move(values)](stack& s) {
        for (const value& v : values) {
            s.push_value(v);
        }
        return static_cast<int>(values.size());
    };
}

// fire(name, ...): fires a C++ event (Rhp::lua_event) by name, as C++ would.
int bridge_fire(lua_State* L) {
    const stack s{L};
    std::size_t len = 0;
    const char* text = luaL_checklstring(L, 1, &len);
    const std::string_view name{text, len};
    std::optional<error> failure;
    {
        auto event = find_event(name);
        if (!event) {
            failure = std::move(event).error();
        } else if (static_cast<std::size_t>(lua_gettop(L) - 1) != (*event)->arity) {
            failure = make_error(errc::kInvalidArgument, std::format("expected {} arguments, got {}", (*event)->arity, lua_gettop(L) - 1));
        } else {
            ref_args args{L, {}};
            const utils::scope_guard release{[&]() noexcept {
                for (const int ref : args.refs) {
                    luaL_unref(L, LUA_REGISTRYINDEX, ref);
                }
            }};
            args.refs.reserve(static_cast<std::size_t>(lua_gettop(L) - 1));
            for (int i = 2; i <= lua_gettop(L); ++i) {
                lua_pushvalue(L, i);
                args.refs.push_back(luaL_ref(L, LUA_REGISTRYINDEX));
            }
            try {
                (*event)->state->fire(name, event_args{&args, &push_ref_args, &own_ref_args, &ref_values});
            } catch (const std::exception& e) {
                failure = make_error(errc::kRuntime, e.what());
            }
        }
    }
    if (failure) {
        if (failure->where.empty()) {
            failure->where = std::format("fire {}", name);
        }
        s.raise(*failure);
    }
    return 0;
}

// call_point(id, ...) -> the point's results: calls a patch point as C++ would (overrides included).
int bridge_call_point(lua_State* L) {
    const stack s{L};
    std::size_t len = 0;
    const char* text = luaL_checklstring(L, 1, &len);
    std::optional<error> failure;
    int pushed = 0;
    {
        const std::vector<value> args = values_from(L, 2);
        auto out = impl_of(L).call_point(std::string_view{text, len}, args);
        if (!out) {
            failure = std::move(out).error();
        } else {
            for (const value& v : *out) {
                s.push_value(v);
            }
            pushed = static_cast<int>(out->size());
        }
    }
    if (failure) {
        s.raise(*failure);
    }
    return pushed;
}

// coverage() -> distinct (chunk, line) pairs that ran so far (0 while coverage is off)
int bridge_coverage(lua_State* L) {
    const coverage_report r = impl_of(L).coverage();
    std::uint64_t n = 0;
    for (const coverage_chunk& c : r.chunks) {
        n += static_cast<std::uint64_t>(std::ranges::count_if(c.hits, [](std::uint64_t h) { return h != 0; })) + c.extra.size();
    }
    lua_pushinteger(L, static_cast<lua_Integer>(n));
    return 1;
}

// os.time() on the script clock: the epoch (upvalue 2) plus the seconds since enable_testing; with a
// table argument the standard os.time (upvalue 1).
int fake_os_time(lua_State* L) {
    if (lua_isnoneornil(L, 1)) {
        const double seconds = milliseconds_of(impl_of(L).script_elapsed()) / 1000.0;
        lua_pushinteger(L, lua_tointeger(L, lua_upvalueindex(2)) + static_cast<lua_Integer>(std::floor(seconds)));
        return 1;
    }
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);
    lua_call(L, lua_gettop(L) - 1, 1);
    return 1;
}

// os.clock() on the script clock: seconds since enable_testing.
int fake_os_clock(lua_State* L) {
    lua_pushnumber(L, milliseconds_of(impl_of(L).script_elapsed()) / 1000.0);
    return 1;
}

} // namespace

// coroutine.wrap: the standard one (lcorolib.c's luaB_auxwrap), plus crediting the meter as the
// guarded resume does, so a wrapped coroutine's last instructions are counted too.
namespace {

int metered_auxwrap(lua_State* L) {
    lua_State* co = lua_tothread(L, lua_upvalueindex(1));
    const int narg = lua_gettop(L);
    if (lua_checkstack(co, narg) == 0) {
        return luaL_error(L, "too many arguments to resume");
    }
    lua_xmove(L, co, narg);
    int nres = 0;
    const int status = lua_resume(co, L, narg, &nres);
    impl_of(L).credit_hook_progress(co);
    if (status == LUA_OK || status == LUA_YIELD) {
        if (lua_checkstack(L, nres + 1) == 0) {
            lua_pop(co, nres);
            return luaL_error(L, "too many results to resume");
        }
        lua_xmove(co, L, nres);
        return nres;
    }
    int stat = lua_status(co);
    if (stat != LUA_OK && stat != LUA_YIELD) {
        stat = lua_closethread(co, L);
        lua_xmove(co, L, 1);
    } else {
        lua_xmove(co, L, 1);
    }
    if (stat != LUA_ERRMEM && lua_type(L, -1) == LUA_TSTRING) {
        luaL_where(L, 1);
        lua_insert(L, -2);
        lua_concat(L, 2);
    }
    return lua_error(L);
}

} // namespace

int lua_coroutine_wrap(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_State* co = lua_newthread(L);
    lua_pushvalue(L, 1);
    lua_xmove(L, co, 1);
    lua_pushcclosure(L, &metered_auxwrap, 1);
    return 1;
}


// ---- the API description ---------------------------------------------------------------------------

value sandbox_impl::api() const {
    value::array libs;
    for (const auto describe : api_describers_) {
        libs.push_back(describe(options_.caller_role));
    }
    value::array events;
    for (const event_descriptor* e : registered_events()) {
        value::map m;
        m.emplace_back(value{"name"}, value{std::string{e->name}});
        m.emplace_back(value{"arity"}, value{static_cast<std::int64_t>(e->arity)});
        events.emplace_back(std::move(m));
    }
    value::array points;
    if (allows(options_.caller_role, role::kPatch)) {
        for (const point_descriptor* p : registered_points()) {
            value::map m;
            m.emplace_back(value{"id"}, value{std::string{p->id}});
            m.emplace_back(value{"arity"}, value{static_cast<std::int64_t>(p->arity)});
            m.emplace_back(value{"callable"}, value{p->invoke != nullptr});
            points.emplace_back(std::move(m));
        }
    }
    const auto by = [](std::string_view field) {
        return [field](const value& a, const value& b) {
            const auto* x = a.find(field)->get_if<std::string>();
            const auto* y = b.find(field)->get_if<std::string>();
            return *x < *y;
        };
    };
    std::ranges::sort(events, by("name"));
    std::ranges::sort(points, by("id"));
    value::map out;
    out.emplace_back(value{"libs"}, value{std::move(libs)});
    out.emplace_back(value{"events"}, value{std::move(events)});
    out.emplace_back(value{"points"}, value{std::move(points)});
    return value{std::move(out)};
}

int lua_rhp_api(lua_State* L) {
    stack{L}.push_value(impl_of(L).api());
    return 1;
}

// ---- the meter -------------------------------------------------------------------------------------

void sandbox_impl::start_metering() {
    if (metering_) {
        return;
    }
    metering_ = true;
    rearm_all(); // every run counts now
}

void sandbox_impl::stop_metering() {
    if (!metering_) {
        return;
    }
    (void)meter(); // fold in what the threads ran so far
    metering_ = false;
    rearm_all();
}

void sandbox_impl::credit_hook_progress(lua_State* L) noexcept {
    if (!metering_ || L == nullptr) {
        return;
    }
    const std::uint32_t done = internals::take_hook_progress(L);
    if (done == 0) {
        return;
    }
    meter_instructions_ += done;
    if (options_.limits.instructions != 0) { // a limit keeps seeing every instruction
        for (active_run& run : running_) {
            if (run.budget != nullptr && run.budget->sticky == sticky_stop::kNone) {
                run.budget->instructions += done;
            }
        }
    }
    if (profiler_) {
        profiler_->pending += done;
    }
}

run_meter sandbox_impl::meter() {
    credit_hook_progress(state_);
    for (const auto& [id, req] : requests_) {
        if (req->thread != nullptr && !req->running) {
            credit_hook_progress(req->thread);
        }
    }
    run_meter m;
    m.instructions = meter_instructions_;
    m.active = std::chrono::duration_cast<std::chrono::nanoseconds>(meter_active_);
    if (metering_ && !running_.empty()) {
        m.active += std::chrono::duration_cast<std::chrono::nanoseconds>(steady::now() - meter_run_started_);
    }
    m.allocations = allocations_;
    m.frees = frees_;
    m.bytes_allocated = bytes_allocated_;
    m.memory = memory_used_;
    m.peak = std::max(peak_, memory_used_);
    m.objects = objects_;
    return m;
}

result<void> sandbox_impl::collect_garbage() {
    return protect(state_, [this] {
        lua_gc(state_, LUA_GCCOLLECT);
        lua_gc(state_, LUA_GCCOLLECT);
    });
}

result<void> sandbox_impl::set_gc_mode(gc_mode mode) {
    return protect(state_, [this, mode] { (void)lua_gc(state_, mode == gc_mode::kGenerational ? LUA_GCGEN : LUA_GCINC); });
}

// ---- coverage --------------------------------------------------------------------------------------

bool sandbox_impl::wants_line_events() const noexcept {
    return coverage_ != nullptr || (debugger_ && debugger_->wants_lines());
}

result<void> sandbox_impl::start_coverage() {
    if (coverage_) {
        return fail(errc::kAlreadyLoaded, "coverage is being recorded", "coverage");
    }
    coverage_ = std::make_unique<coverage_state>();
    rearm_all();
    return {};
}

coverage_report sandbox_impl::coverage() const {
    coverage_report out;
    if (!coverage_) {
        return out;
    }
    out.chunks.reserve(coverage_->chunks.size());
    for (const coverage_state::chunk_hits& c : coverage_->chunks) {
        coverage_chunk chunk{c.name, c.lines, c.hits, {}};
        for (const auto& [line, hits] : c.extra) {
            chunk.extra.push_back(line);
        }
        out.chunks.push_back(std::move(chunk));
    }
    std::ranges::sort(out.chunks, {}, &coverage_chunk::chunk);
    return out;
}

coverage_report sandbox_impl::stop_coverage() {
    coverage_report out = coverage();
    coverage_.reset();
    rearm_all();
    return out;
}

void sandbox_impl::coverage_compiled(lua_State* L, std::string_view chunk) noexcept {
    try {
        coverage_state& c = *coverage_;
        std::vector<const void*> protos;
        const std::vector<std::uint32_t> lines = internals::executable_lines(internals::proto_on_top(L), protos);
        const std::uint32_t index = c.chunk(chunk);
        c.add_lines(index, lines);
        for (const void* p : protos) {
            c.by_proto.insert_or_assign(p, index);
        }
        c.last_proto = nullptr;
    } catch (...) { // out of memory: this chunk's lines are learned as they run instead
    }
}

void sandbox_impl::coverage_line(lua_State* /*L*/, lua_Debug* ar) noexcept {
    coverage_state& c = *coverage_;
    const void* proto = internals::proto_of(ar);
    if (proto == nullptr || ar->currentline <= 0) {
        return;
    }
    try {
        std::uint32_t index = 0;
        if (proto == c.last_proto) {
            index = c.last_chunk;
        } else {
            // A prototype seen before maps to its chunk; one that wasn't compiled while recording (or
            // whose address a newer function reuses) is found by its source name.
            std::string_view source = internals::proto_source(proto);
            if (!source.empty() && (source.front() == '@' || source.front() == '=')) {
                source.remove_prefix(1);
            }
            const auto it = c.by_proto.find(proto);
            if (it != c.by_proto.end() && c.chunks[it->second].name == source) {
                index = it->second;
            } else {
                index = c.chunk(source);
                c.by_proto.insert_or_assign(proto, index);
            }
            c.last_proto = proto;
            c.last_chunk = index;
        }
        c.hit(index, static_cast<std::uint32_t>(ar->currentline));
    } catch (...) { // out of memory: this line isn't recorded
    }
}

// ---- the bridge ------------------------------------------------------------------------------------

result<void> sandbox_impl::enable_testing(testing_options options) {
    if (testing_on_) {
        return fail(errc::kAlreadyLoaded, "testing is already enabled", "enable_testing");
    }
    testing_ = std::move(options);
    testing_started_ = script_now();
    auto installed = protect(state_, [this] {
        lua_State* L = state_;
        struct entry {
            const char* name;
            lua_CFunction fn;
        };
        constexpr entry functions[] = {
            {"kind", &bridge_kind},
            {"members", &bridge_members},
            {"swap", &bridge_swap},
            {"swap_var", &bridge_swap_var},
            {"meter", &bridge_meter},
            {"reset_peak", &bridge_reset_peak},
            {"gc", &bridge_gc},
            {"gc_mode", &bridge_gc_mode},
            {"next_due", &bridge_next_due},
            {"now", &bridge_now},
            {"host", &bridge_host},
            {"fire", &bridge_fire},
            {"call_point", &bridge_call_point},
            {"coverage", &bridge_coverage},
        };
        lua_createtable(L, 0, static_cast<int>(std::size(functions)));
        for (const auto& [name, fn] : functions) {
            lua_pushcfunction(L, fn);
            lua_setfield(L, -2, name);
        }
        lua_rawgeti(L, LUA_REGISTRYINDEX, record(scratch_)->live.env_ref);
        lua_insert(L, -2);
        lua_setfield(L, -2, kBridgeName); // the scratch module's own global: modules can't see it
        lua_pop(L, 1);

        if (testing_.fake_os_epoch) {
            lua_getglobal(L, "os");
            lua_getfield(L, -1, "time");
            lua_pushinteger(L, static_cast<lua_Integer>(*testing_.fake_os_epoch));
            lua_pushcclosure(L, &fake_os_time, 2);
            lua_setfield(L, -2, "time");
            lua_pushcfunction(L, &fake_os_clock);
            lua_setfield(L, -2, "clock");
            lua_pop(L, 1);
        }
    });
    if (!installed) {
        return installed;
    }
    testing_on_ = true;
    return {};
}

std::optional<steady::time_point> sandbox_impl::next_due() const {
    std::optional<steady::time_point> due;
    const auto consider = [&due](steady::time_point t) {
        if (!due || t < *due) {
            due = t;
        }
    };
    for (const auto& [key, entry] : schedule_) {
        if (entry.kind == schedule_kind::kTimer && !entry.paused) {
            consider(entry.due);
        }
    }
    for (const auto& [id, req] : requests_) {
        if (req->wake_time && req->waiting != wait_kind::kDebug) {
            consider(*req->wake_time);
        }
    }
    return due;
}

result<value_list> sandbox_impl::call_point(std::string_view id, std::span<const value> args) {
    auto point = find_point(id);
    if (!point) {
        return std::unexpected{std::move(point).error()};
    }
    if ((*point)->invoke == nullptr) {
        return fail(errc::kTypeMismatch, "its parameters or result aren't value types: call it from C++", std::string{id});
    }
    try {
        return (*point)->invoke(args);
    } catch (const Rhp::exception& e) {
        return std::unexpected{e.err()};
    } catch (const std::exception& e) {
        return fail(errc::kRuntime, e.what(), std::string{id});
    }
}

result<void> sandbox_impl::fire_event(std::string_view name, std::span<const value> args) {
    auto event = find_event(name);
    if (!event) {
        return std::unexpected{std::move(event).error()};
    }
    if (args.size() != (*event)->arity) {
        return fail(errc::kInvalidArgument, std::format("expected {} arguments, got {}", (*event)->arity, args.size()), std::string{name});
    }
    struct value_args {
        std::span<const value> values;
    } data{args};
    const auto push = [](stack& s, const void* d) {
        const auto& a = *static_cast<const value_args*>(d);
        for (const value& v : a.values) {
            s.push_value(v);
        }
        return static_cast<int>(a.values.size());
    };
    const auto own = [](const void* d) -> std::function<int(stack&)> {
        std::vector<value> copy{static_cast<const value_args*>(d)->values.begin(), static_cast<const value_args*>(d)->values.end()};
        return [copy = std::move(copy)](stack& s) {
            for (const value& v : copy) {
                s.push_value(v);
            }
            return static_cast<int>(copy.size());
        };
    };
    const auto values = [](const void* d) {
        const auto& a = *static_cast<const value_args*>(d);
        return std::vector<value>{a.values.begin(), a.values.end()};
    };
    try {
        (*event)->state->fire(name, event_args{&data, +push, +own, +values});
    } catch (const Rhp::exception& e) {
        return std::unexpected{e.err()};
    } catch (const std::exception& e) {
        return fail(errc::kRuntime, e.what(), std::string{name});
    }
    return {};
}

void sandbox_impl::swap_member(lua_State* L, int target, int key) {
    const stack s{L};
    const int value_index = lua_gettop(L);
    target = lua_absindex(L, target);
    key = lua_absindex(L, key);
    const target_kind kind = kind_of(L, target);
    std::optional<error> failure;
    // Pushes the table that holds `key` for this target, or sets `failure`.
    switch (kind) {
    case target_kind::kLib: {
        push_lib_accessors(L, target, false);
        lua_pushvalue(L, key);
        const bool variable = lua_rawget(L, -2) != LUA_TNIL;
        lua_pop(L, 2);
        if (variable) {
            failure = make_error(errc::kInvalidArgument, "a lib variable: swap its getter and setter (swap_var)");
        } else {
            push_lib_members(L, target);
        }
        break;
    }
    case target_kind::kModule: {
        const module_record* mod = module_of_proxy(L, target);
        if (mod == nullptr || mod->live.exports_ref == kNoRef) {
            failure = make_error(errc::kUnloaded, "the module has no exports (unloaded or not loaded yet)");
        } else {
            lua_rawgeti(L, LUA_REGISTRYINDEX, mod->live.exports_ref);
        }
        break;
    }
    case target_kind::kHandle: {
        // A property's getter if `key` is one, else the methods table (a new key becomes a method).
        push_handle_table(L, target, kGettersField);
        bool property = false;
        if (lua_istable(L, -1)) {
            lua_pushvalue(L, key);
            property = lua_rawget(L, -2) != LUA_TNIL;
            lua_pop(L, 1);
        }
        if (!property) {
            lua_pop(L, 1);
            push_handle_table(L, target, kMethodsField);
            if (!lua_istable(L, -1)) {
                lua_pop(L, 1);
                failure = make_error(errc::kNotFound, "this handle type has no members");
            }
        }
        break;
    }
    case target_kind::kTable: lua_pushvalue(L, target); break;
    case target_kind::kOther: failure = make_error(errc::kTypeMismatch, std::format("can't swap a member of a {}", s.type_name(target))); break;
    }
    if (failure) {
        failure->where = "__rhp_test.swap";
        s.raise(*failure);
    }
    const int table = lua_gettop(L);
    // The original, then the effect that puts it back, then the swap.
    lua_pushvalue(L, key);
    lua_rawget(L, table);
    const int original = lua_gettop(L);
    std::vector<slot_swap_effect::slot> slots(1);
    lua_pushvalue(L, table);
    slots[0].table = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_pushvalue(L, key);
    slots[0].key = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_pushvalue(L, original);
    slots[0].original = luaL_ref(L, LUA_REGISTRYINDEX);
    std::string label = std::format("test swap {}", s.to_string(key).value_or("?"));
    (void)record_effect(std::move(label), std::make_unique<slot_swap_effect>(state_, std::move(slots)));
    lua_pushvalue(L, key);
    lua_pushvalue(L, value_index);
    lua_rawset(L, table);
    lua_replace(L, value_index); // the original takes the value's slot
    lua_settop(L, value_index);
}

void sandbox_impl::swap_variable(lua_State* L, int target, int key, int getter, int setter) {
    const stack s{L};
    target = lua_absindex(L, target);
    key = lua_absindex(L, key);
    getter = lua_absindex(L, getter);
    setter = lua_absindex(L, setter);
    if (kind_of(L, target) != target_kind::kLib) {
        s.raise(make_error(errc::kTypeMismatch, std::format("expected a lib, got {}", s.type_name(target)), "__rhp_test.swap_var"));
    }
    push_lib_accessors(L, target, false);
    const int getters = lua_gettop(L);
    push_lib_accessors(L, target, true);
    const int setters = lua_gettop(L);
    lua_pushvalue(L, key);
    if (lua_rawget(L, getters) == LUA_TNIL) {
        s.raise(make_error(errc::kNotFound, std::format("no variable '{}'", s.to_string(key).value_or("?")), "__rhp_test.swap_var"));
    }
    const int original_getter = lua_gettop(L);
    lua_pushvalue(L, key);
    lua_rawget(L, setters);
    const int original_setter = lua_gettop(L);
    std::vector<slot_swap_effect::slot> slots(2);
    for (std::size_t i = 0; i < 2; ++i) {
        lua_pushvalue(L, i == 0 ? getters : setters);
        slots[i].table = luaL_ref(L, LUA_REGISTRYINDEX);
        lua_pushvalue(L, key);
        slots[i].key = luaL_ref(L, LUA_REGISTRYINDEX);
        lua_pushvalue(L, i == 0 ? original_getter : original_setter);
        slots[i].original = luaL_ref(L, LUA_REGISTRYINDEX);
    }
    std::string label = std::format("test swap_var {}", s.to_string(key).value_or("?"));
    (void)record_effect(std::move(label), std::make_unique<slot_swap_effect>(state_, std::move(slots)));
    lua_pushvalue(L, key);
    lua_pushvalue(L, getter);
    lua_rawset(L, getters);
    lua_pushvalue(L, key);
    lua_pushvalue(L, setter);
    lua_rawset(L, setters);
    lua_pushvalue(L, original_getter);
    lua_pushvalue(L, original_setter);
}

} // namespace Rhp::script::detail

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <lauxlib.h>
#include <lua.h>

#include <rhp/script/detail/context.hpp>
#include <rhp/script/puc_lua/keys.hpp>
#include <rhp/script/puc_lua/sandbox_impl.hpp>
#include <rhp/script/puc_lua/views_impl.hpp>
#include <rhp/script/stack.hpp>

namespace Rhp::script {

namespace {

constexpr int kMaxValueDepth = 64;

int handle_newindex(lua_State* L); // __newindex of every handle: members are read-only

std::string to_std_string(lua_State* L, int index) {
    std::size_t len = 0;
    const char* s = lua_tolstring(L, index, &len);
    return s != nullptr ? std::string{s, len} : std::string{};
}

// Finds the "[code]" token RHP puts in front of its own errors.
std::optional<errc> parse_code(std::string_view text) {
    for (std::size_t open = text.find('['); open != std::string_view::npos; open = text.find('[', open + 1)) {
        const std::size_t close = text.find(']', open);
        if (close == std::string_view::npos) {
            return std::nullopt;
        }
        if (const std::optional<errc> code = parse_errc(text.substr(open + 1, close - open - 1))) {
            return code;
        }
    }
    return std::nullopt;
}

result<value> read_value(lua_State* L, int index, int depth);

result<value> read_table(lua_State* L, int index, int depth) {
    if (depth > kMaxValueDepth) {
        return fail(errc::kOutOfRange, "table nesting is too deep (or cyclic) to convert");
    }
    // Each level holds a key and a value on the stack (found by fuzzing: a deep table outgrew the
    // C function's guaranteed LUA_MINSTACK slots).
    if (lua_checkstack(L, 4) == 0) {
        return fail(errc::kOutOfRange, "no Lua stack left to convert the table");
    }
    index = lua_absindex(L, index);
    // An array is a table whose keys are exactly 1..n.
    const lua_Unsigned length = lua_rawlen(L, index);
    std::size_t count = 0;
    bool array = true;
    lua_pushnil(L);
    while (lua_next(L, index) != 0) {
        ++count;
        if (array) {
            lua_Integer k = 0;
            int is_integer = 0;
            k = lua_tointegerx(L, -2, &is_integer);
            array = lua_type(L, -2) == LUA_TNUMBER && is_integer != 0 && k >= 1 && static_cast<lua_Unsigned>(k) <= length;
        }
        lua_pop(L, 1);
    }
    if (array && count == length) {
        value::array items;
        items.reserve(count);
        for (lua_Integer i = 1; i <= static_cast<lua_Integer>(length); ++i) {
            lua_rawgeti(L, index, i);
            auto item = read_value(L, -1, depth + 1);
            lua_pop(L, 1);
            if (!item) {
                return item;
            }
            items.push_back(std::move(*item));
        }
        return value{std::move(items)};
    }
    value::map entries;
    entries.reserve(count);
    lua_pushnil(L);
    while (lua_next(L, index) != 0) {
        auto k = read_value(L, -2, depth + 1);
        auto v = k ? read_value(L, -1, depth + 1) : result<value>{};
        lua_pop(L, 1);
        if (!k || !v) {
            lua_pop(L, 1);
            return !k ? k : v;
        }
        entries.emplace_back(std::move(*k), std::move(*v));
    }
    return value{std::move(entries)};
}

result<value> read_value(lua_State* L, int index, int depth) {
    switch (lua_type(L, index)) {
    case LUA_TNONE:
    case LUA_TNIL: return value{};
    case LUA_TBOOLEAN: return value{lua_toboolean(L, index) != 0};
    case LUA_TNUMBER:
        if (lua_isinteger(L, index) != 0) {
            return value{static_cast<std::int64_t>(lua_tointeger(L, index))};
        }
        return value{static_cast<double>(lua_tonumber(L, index))};
    case LUA_TSTRING: return value{to_std_string(L, index)};
    case LUA_TTABLE: return read_table(L, index, depth);
    default: return fail(errc::kTypeMismatch, std::format("cannot convert a {} to a value", luaL_typename(L, index)));
    }
}

} // namespace

// ---- context -------------------------------------------------------------------------------------

detail::context& stack::context() const noexcept {
    return **static_cast<detail::context**>(lua_getextraspace(state_));
}

// ---- size ----------------------------------------------------------------------------------------

int stack::top() const noexcept {
    return lua_gettop(state_);
}

void stack::set_top(int index) const {
    lua_settop(state_, index);
}

void stack::pop(int count) const {
    lua_pop(state_, count);
}

int stack::abs_index(int index) const noexcept {
    return lua_absindex(state_, index);
}

type_kind stack::type(int index) const noexcept {
    return static_cast<type_kind>(lua_type(state_, index));
}

bool stack::is_none_or_nil(int index) const noexcept {
    return lua_isnoneornil(state_, index);
}

std::string_view stack::type_name(int index) const noexcept {
    if (lua_type(state_, index) == LUA_TUSERDATA && luaL_getmetafield(state_, index, "__name") == LUA_TSTRING) {
        std::size_t len = 0;
        const char* name = lua_tolstring(state_, -1, &len);
        lua_pop(state_, 1);
        return {name, len}; // anchored by the metatable, which outlives this call
    }
    return luaL_typename(state_, index);
}

// ---- push ----------------------------------------------------------------------------------------

void stack::push_nil() const {
    lua_pushnil(state_);
}

void stack::push_bool(bool b) const {
    lua_pushboolean(state_, b ? 1 : 0);
}

void stack::push_integer(std::int64_t i) const {
    lua_pushinteger(state_, static_cast<lua_Integer>(i));
}

void stack::push_number(double d) const {
    lua_pushnumber(state_, static_cast<lua_Number>(d));
}

void stack::push_string(std::string_view s) const {
    lua_pushlstring(state_, s.data(), s.size());
}

void stack::push_value(const value& v) const {
    luaL_checkstack(state_, 3, "rhp: value too deep");
    switch (v.type()) {
    case value::kind::kNil:
    case value::kind::kBool:
    case value::kind::kInteger:
    case value::kind::kNumber: detail::push_scalar(state_, v); break;
    case value::kind::kString: push_string(*v.get_if<std::string>()); break;
    case value::kind::kBytes: {
        const auto& b = *v.get_if<value::bytes>();
        lua_pushlstring(state_, reinterpret_cast<const char*>(b.data()), b.size());
        break;
    }
    case value::kind::kArray: {
        const auto& items = *v.get_if<value::array>();
        lua_createtable(state_, static_cast<int>(items.size()), 0);
        lua_Integer i = 1;
        for (const auto& item : items) {
            push_value(item);
            lua_rawseti(state_, -2, i++);
        }
        break;
    }
    case value::kind::kMap: {
        const auto& entries = *v.get_if<value::map>();
        lua_createtable(state_, 0, static_cast<int>(entries.size()));
        for (const auto& [k, item] : entries) {
            if (k.is_nil()) {
                continue; // nil can't be a Lua key
            }
            push_value(k);
            push_value(item);
            lua_rawset(state_, -3);
        }
        break;
    }
    }
}

void stack::push_copy(int index) const {
    lua_pushvalue(state_, index);
}

void stack::push_function(c_function fn, int upvalues) const {
    lua_pushcclosure(state_, fn, upvalues);
}

void stack::new_table(int array_hint, int record_hint) const {
    lua_createtable(state_, array_hint, record_hint);
}

// ---- tables --------------------------------------------------------------------------------------

void stack::set_field(int table, std::string_view key) const {
    table = lua_absindex(state_, table);
    lua_pushlstring(state_, key.data(), key.size());
    lua_insert(state_, -2);
    lua_rawset(state_, table);
}

void stack::raw_get_field(int table, std::string_view key) const {
    table = lua_absindex(state_, table);
    lua_pushlstring(state_, key.data(), key.size());
    lua_rawget(state_, table);
}

// ---- read ----------------------------------------------------------------------------------------

std::optional<bool> stack::to_bool(int index) const noexcept {
    if (lua_type(state_, index) != LUA_TBOOLEAN) {
        return std::nullopt;
    }
    return lua_toboolean(state_, index) != 0;
}

std::optional<std::int64_t> stack::to_integer(int index) const noexcept {
    if (lua_type(state_, index) != LUA_TNUMBER) {
        return std::nullopt;
    }
    int ok = 0;
    const lua_Integer i = lua_tointegerx(state_, index, &ok); // integral floats convert, 1.5 doesn't
    if (ok == 0) {
        return std::nullopt;
    }
    return static_cast<std::int64_t>(i);
}

std::optional<double> stack::to_number(int index) const noexcept {
    if (lua_type(state_, index) != LUA_TNUMBER) {
        return std::nullopt;
    }
    return static_cast<double>(lua_tonumber(state_, index));
}

std::optional<std::string_view> stack::to_string(int index) const noexcept {
    if (lua_type(state_, index) != LUA_TSTRING) {
        return std::nullopt;
    }
    std::size_t len = 0;
    const char* s = lua_tolstring(state_, index, &len);
    return std::string_view{s, len};
}

bool stack::read_args(const arg_kind* kinds, arg_slot* out, int count) const noexcept {
    for (int i = 0; i < count; ++i) {
        const int index = i + 1;
        switch (kinds[i]) {
        case arg_kind::kBool:
            if (lua_type(state_, index) != LUA_TBOOLEAN) {
                return false;
            }
            out[i].boolean = lua_toboolean(state_, index) != 0;
            break;
        case arg_kind::kInteger: {
            if (lua_type(state_, index) != LUA_TNUMBER) {
                return false;
            }
            int ok = 0;
            out[i].integer = static_cast<std::int64_t>(lua_tointegerx(state_, index, &ok)); // 1.5 doesn't convert
            if (ok == 0) {
                return false;
            }
            break;
        }
        case arg_kind::kNumber:
            if (lua_type(state_, index) != LUA_TNUMBER) {
                return false;
            }
            out[i].number = static_cast<double>(lua_tonumberx(state_, index, nullptr));
            break;
        case arg_kind::kString:
            if (lua_type(state_, index) != LUA_TSTRING) {
                return false;
            }
            out[i].string.data = lua_tolstring(state_, index, &out[i].string.size);
            break;
        case arg_kind::kSpan:
            if (!detail::read_span_arg(state_, index, out[i])) {
                return false;
            }
            break;
        case arg_kind::kOther: break;
        }
    }
    return true;
}

result<value> stack::to_value(int index) const {
    luaL_checkstack(state_, 4, "rhp: value too deep");
    return read_value(state_, index, 0);
}

// ---- upvalues ------------------------------------------------------------------------------------

std::string_view stack::upvalue_string(int n) const noexcept {
    std::size_t len = 0;
    const char* s = lua_tolstring(state_, lua_upvalueindex(n), &len);
    return s != nullptr ? std::string_view{s, len} : std::string_view{};
}

int stack::upvalue_index(int n) noexcept {
    return lua_upvalueindex(n);
}

// ---- typed userdata --------------------------------------------------------------------------------

result<void> stack::define_userdata_type(std::string_view key, std::string_view display_name, const void* type_tag, c_function eq,
                                         c_function tostring) const {
    const std::string k{key};
    if (luaL_getmetatable(state_, k.c_str()) != LUA_TNIL) {
        lua_getfield(state_, -1, detail::kTypeTagField);
        const bool same = lua_touserdata(state_, -1) == type_tag;
        lua_pop(state_, 2);
        if (!same) {
            return fail(errc::kAlreadyLoaded, std::format("handle type '{}' is already defined for a different C++ type", display_name));
        }
        return {};
    }
    lua_pop(state_, 1);
    luaL_newmetatable(state_, k.c_str());
    push_string(display_name);
    lua_setfield(state_, -2, "__name");
    lua_pushlightuserdata(state_, const_cast<void*>(type_tag));
    lua_setfield(state_, -2, detail::kTypeTagField);
    lua_pushcfunction(state_, eq);
    lua_setfield(state_, -2, "__eq");
    lua_pushcfunction(state_, tostring);
    lua_setfield(state_, -2, "__tostring");
    lua_pushliteral(state_, "locked");
    lua_setfield(state_, -2, "__metatable");
    // Members (add_handle_member) live in this table; without any, every key reads as nil.
    lua_createtable(state_, 0, 4);
    lua_pushvalue(state_, -1);
    lua_setfield(state_, -3, detail::kMethodsField);
    lua_setfield(state_, -2, "__index");
    lua_pushcfunction(state_, &handle_newindex);
    lua_setfield(state_, -2, "__newindex");
    lua_pop(state_, 1);

    if (lua_getfield(state_, LUA_REGISTRYINDEX, detail::kHandleTagsKey) != LUA_TTABLE) {
        lua_pop(state_, 1);
        lua_newtable(state_);
        lua_pushvalue(state_, -1);
        lua_setfield(state_, LUA_REGISTRYINDEX, detail::kHandleTagsKey);
    }
    // The first handle name declared for a C++ type stays the one handles of that type are pushed
    // as (events, other libs); a second name for the same type keeps its own metatable for its lib.
    lua_pushlightuserdata(state_, const_cast<void*>(type_tag));
    if (lua_rawget(state_, -2) == LUA_TNIL) {
        lua_pop(state_, 1);
        lua_pushlightuserdata(state_, const_cast<void*>(type_tag));
        push_string(key);
        lua_rawset(state_, -3);
    } else {
        lua_pop(state_, 1);
    }
    lua_pop(state_, 1);
    return {};
}

// ---- methods and properties ------------------------------------------------------------------------

namespace {

// __index of a handle with properties: upvalue 1 = methods, upvalue 2 = getters.
int handle_index(lua_State* L) {
    lua_settop(L, 2);
    lua_pushvalue(L, 2);
    if (lua_rawget(L, lua_upvalueindex(1)) != LUA_TNIL) {
        return 1;
    }
    lua_pop(L, 1);
    lua_pushvalue(L, 2);
    if (lua_rawget(L, lua_upvalueindex(2)) != LUA_TNIL) {
        // RHP's property getters are C functions without upvalues (get_property): one runs in this
        // frame, reading the handle at index 1. Anything else (a test's swap) is called with the handle.
        if (const lua_CFunction get = lua_tocfunction(L, -1); get != nullptr && lua_getupvalue(L, -1, 1) == nullptr) {
            return get(L);
        }
        lua_settop(L, 3); // drops the upvalue a C closure pushed above
        lua_pushvalue(L, 1);
        lua_call(L, 1, 1);
        return 1;
    }
    return 1; // nil
}

int handle_newindex(lua_State* L) {
    const stack s{L};
    const std::optional<std::string_view> key = s.to_string(2);
    s.raise(make_error(errc::kInvalidArgument,
                       std::format("{}.{} is read-only (a handle's members are set in C++)", s.type_name(1), key.value_or("?"))));
}

// Pushes the table `field` of the metatable at `mt` (created when missing).
void push_member_table(lua_State* L, int mt, const char* field) {
    if (lua_getfield(L, mt, field) != LUA_TTABLE) {
        lua_pop(L, 1);
        lua_createtable(L, 0, 4);
        lua_pushvalue(L, -1);
        lua_setfield(L, mt, field);
    }
}

} // namespace

result<void> stack::handle_member_free(std::string_view key, std::string_view name) const {
    const std::string k{key};
    if (luaL_getmetatable(state_, k.c_str()) != LUA_TTABLE) {
        lua_pop(state_, 1);
        return fail(errc::kNotFound, std::format("handle type '{}' is not defined", key));
    }
    bool taken = false;
    for (const char* field : {detail::kMethodsField, detail::kGettersField}) {
        if (lua_getfield(state_, -1, field) == LUA_TTABLE) {
            push_string(name);
            taken = taken || lua_rawget(state_, -2) != LUA_TNIL;
            lua_pop(state_, 1);
        }
        lua_pop(state_, 1);
    }
    lua_getfield(state_, -1, "__name");
    const std::string handle = to_std_string(state_, -1);
    lua_pop(state_, 2);
    if (taken) {
        return fail(errc::kAlreadyLoaded, std::format("handle type '{}' already has a member named '{}'", handle, name));
    }
    return {};
}

void stack::add_handle_member(std::string_view key, std::string_view name, bool property) const {
    const int fn = lua_gettop(state_);
    const std::string k{key};
    luaL_getmetatable(state_, k.c_str());
    const int mt = fn + 1;
    push_member_table(state_, mt, detail::kMethodsField);
    const int methods = fn + 2;
    if (!property) {
        push_string(name);
        lua_pushvalue(state_, fn);
        lua_rawset(state_, methods);
    }
    lua_getfield(state_, mt, detail::kGettersField);
    const bool has_getters = lua_istable(state_, -1);
    lua_pop(state_, 1);
    if (property || has_getters) {
        push_member_table(state_, mt, detail::kGettersField);
        if (property) {
            push_string(name);
            lua_pushvalue(state_, fn);
            lua_rawset(state_, fn + 3);
        }
        lua_pushcclosure(state_, &handle_index, 2); // __index = handle_index(methods, getters)
    }
    // Methods only: __index is the methods table itself (the VM's fastest lookup).
    lua_setfield(state_, mt, "__index");
    lua_pushcfunction(state_, &handle_newindex);
    lua_setfield(state_, mt, "__newindex");
    lua_settop(state_, fn - 1); // the metatable and the function
}

bool stack::push_handle(const void* type_tag, const void* data, std::size_t size) const {
    if (lua_getfield(state_, LUA_REGISTRYINDEX, detail::kHandleTagsKey) != LUA_TTABLE) {
        lua_pop(state_, 1);
        return false;
    }
    lua_pushlightuserdata(state_, const_cast<void*>(type_tag));
    if (lua_rawget(state_, -2) != LUA_TSTRING) {
        lua_pop(state_, 2);
        return false;
    }
    void* memory = lua_newuserdatauv(state_, size, 0);
    std::memcpy(memory, data, size); // handle types are trivially copyable
    lua_insert(state_, -3);          // userdata, tags, key
    luaL_getmetatable(state_, lua_tostring(state_, -1));
    lua_setmetatable(state_, -4);
    lua_pop(state_, 2);
    return true;
}

void* stack::push_userdata(std::size_t size, std::string_view key) const {
    void* memory = lua_newuserdatauv(state_, size, 0);
    // luaL_setmetatable needs a C string; keys are short literals, so a small buffer avoids allocation.
    char buffer[96];
    if (key.size() < sizeof(buffer)) {
        std::memcpy(buffer, key.data(), key.size());
        buffer[key.size()] = '\0';
        luaL_setmetatable(state_, buffer);
    } else {
        const std::string k{key};
        luaL_setmetatable(state_, k.c_str());
    }
    return memory;
}

void* stack::to_userdata(int index, std::string_view key) const noexcept {
    // By name, not by a light-userdata key: the registry hashes a pointer with a modulo by its size,
    // which measured slower than Lua's string cache and a short-string lookup.
    // luaL_testudata needs a C string; keys are short literals, so a small buffer avoids allocation.
    char buffer[96];
    if (key.size() >= sizeof(buffer)) {
        return nullptr;
    }
    std::memcpy(buffer, key.data(), key.size());
    buffer[key.size()] = '\0';
    return luaL_testudata(state_, index, buffer);
}

// ---- registry references ---------------------------------------------------------------------------

int stack::ref() const {
    return luaL_ref(state_, LUA_REGISTRYINDEX);
}

void stack::unref(int reference) const {
    luaL_unref(state_, LUA_REGISTRYINDEX, reference);
}

void stack::push_ref(int reference) const {
    lua_rawgeti(state_, LUA_REGISTRYINDEX, reference);
}

// ---- calls ---------------------------------------------------------------------------------------

result<void> stack::call(int nargs, int nresults) const {
    const int base = lua_gettop(state_) - nargs; // the function
    lua_pushcfunction(state_, &detail::traceback_handler);
    lua_insert(state_, base);
    const int status = lua_pcall(state_, nargs, nresults, base);
    if (status != LUA_OK) {
        error err = detail::take_lua_error(state_, status);
        lua_remove(state_, base);
        return std::unexpected{std::move(err)};
    }
    lua_remove(state_, base);
    return {};
}

void stack::call_unprotected(int nargs, int nresults) const {
    lua_call(state_, nargs, nresults);
}

result<void> stack::run_protected(c_function fn, void* data) const {
    const int top = lua_gettop(state_);
    if (lua_checkstack(state_, 3) == 0) {
        return fail(errc::kMemoryExceeded, "Lua stack overflow");
    }
    lua_pushcfunction(state_, &detail::traceback_handler);
    lua_pushcfunction(state_, fn);
    lua_pushlightuserdata(state_, data);
    const int status = lua_pcall(state_, 1, 0, top + 1);
    if (status != LUA_OK) {
        error err = detail::take_lua_error(state_, status);
        lua_settop(state_, top);
        return std::unexpected{std::move(err)};
    }
    lua_settop(state_, top);
    return {};
}

void* stack::to_light_userdata(int index) const noexcept {
    return lua_touserdata(state_, index);
}

// ---- errors --------------------------------------------------------------------------------------

void stack::raise(const error& err) const {
    auto& impl = detail::impl_of(state_);
    std::string text = std::format("{}", err);
    lua_pushlstring(state_, text.data(), text.size());
    impl.last_raised = detail::sandbox_impl::raised_error{std::move(text), err};
    lua_error(state_);
    std::unreachable();
}

// ---- asynchronous bindings ---------------------------------------------------------------------

namespace {

// Where a binding that yielded through yield_async() continues once its request resumes. Upvalue
// 1 of the binding's closure is still its label.
int continue_async(lua_State* L, int /*status*/, lua_KContext /*ctx*/) {
    stack s{L};
    detail::context& ctx = s.context();
    const std::shared_ptr<detail::async_wait> op = ctx.take_async(L);
    if (!op) {
        s.raise(make_error(errc::kTimeout, "the asynchronous call took longer than limits.async_ms", std::string{s.upvalue_string(1)}));
    }
    return op->finish(s, ctx);
}

} // namespace

} // namespace Rhp::script

namespace Rhp::script::detail {

void yield_async(lua_State* L) {
    (void)lua_yieldk(L, 0, 0, &continue_async);
    // A yield from a C function never returns here: it unwinds (or jumps) back into lua_resume.
    std::unreachable();
}

} // namespace Rhp::script::detail

namespace Rhp::script {

namespace detail {

error take_lua_error(lua_State* L, int status) {
    auto& impl = impl_of(L);
    std::string text;
    if (lua_type(L, -1) == LUA_TSTRING) {
        text = to_std_string(L, -1);
    } else if (luaL_callmeta(L, -1, "__tostring") != 0 && lua_type(L, -1) == LUA_TSTRING) {
        text = to_std_string(L, -1);
        lua_pop(L, 1);
    } else {
        text = std::format("(error object is a {} value)", luaL_typename(L, -1));
    }
    lua_pop(L, 1);

    error err;
    if (impl.last_raised && text.find(impl.last_raised->text) != std::string::npos) {
        err = std::move(impl.last_raised->err);
    } else if (status == LUA_ERRSYNTAX) {
        err = make_error(errc::kCompile, std::move(text));
    } else if (status == LUA_ERRMEM) {
        err = make_error(errc::kMemoryExceeded, std::move(text));
    } else {
        err = make_error(parse_code(text).value_or(errc::kRuntime), std::move(text));
    }
    impl.last_raised.reset();
    err.traceback = std::move(impl.pending_traceback);
    impl.pending_traceback.clear();
    return err;
}

void push_scalar(lua_State* L, const value& v) noexcept {
    switch (v.type()) {
    case value::kind::kBool: lua_pushboolean(L, *v.get_if<bool>() ? 1 : 0); break;
    case value::kind::kInteger: lua_pushinteger(L, static_cast<lua_Integer>(*v.get_if<std::int64_t>())); break;
    case value::kind::kNumber: lua_pushnumber(L, static_cast<lua_Number>(*v.get_if<double>())); break;
    default: lua_pushnil(L); break;
    }
}

bool append_scalar(value_list& out, lua_State* L, int index) {
    switch (lua_type(L, index)) {
    case LUA_TNIL: out.emplace_back(); return true;
    case LUA_TBOOLEAN: out.emplace_back(lua_toboolean(L, index) != 0); return true;
    case LUA_TNUMBER:
        if (lua_isinteger(L, index) != 0) {
            out.emplace_back(static_cast<std::int64_t>(lua_tointeger(L, index)));
        } else {
            out.emplace_back(static_cast<double>(lua_tonumber(L, index)));
        }
        return true;
    default: return false;
    }
}

int traceback_handler(lua_State* L) {
    auto& impl = impl_of(L);
    luaL_traceback(L, L, nullptr, 1);
    impl.pending_traceback = to_std_string(L, -1);
    lua_pop(L, 1);
    lua_settop(L, 1);
    return 1;
}

} // namespace detail

} // namespace Rhp::script

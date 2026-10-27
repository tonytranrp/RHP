#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/views.hpp>

// The Lua state type, forward-declared so no RHP header ever includes lua.h. Lua is compiled as
// C++ (cmake/lua/lua_cxx.cpp), so this matches upstream's declaration with C++ linkage.
struct lua_State;

namespace Rhp::script {

namespace detail {
class context;
} // namespace detail

// A Lua C function. Binding trampolines are generated as these.
using c_function = int (*)(lua_State*);

enum class type_kind : std::int8_t {
    kNone = -1,
    kNil = 0,
    kBoolean,
    kLightUserdata,
    kNumber,
    kString,
    kTable,
    kFunction,
    kUserdata,
    kThread
};

// How stack::read_args reads one argument of a plain binding (plain_arg, detail/lib_traits.hpp).
enum class arg_kind : std::uint8_t {
    kBool,    // a boolean
    kInteger, // a number with an integer value (2.0 too)
    kNumber,  // any number
    kString,  // a string (its bytes stay in Lua)
    kSpan,    // a typed view or byte buffer (its memory found now), or a string's bytes
    kOther    // not read here (the caller reads it another way: a handle)
};

// One argument read by stack::read_args: the member its arg_kind names.
union arg_slot {
    struct text {
        const char* data;
        std::size_t size;
    };
    struct bytes {
        const void* data;
        std::size_t size;  // bytes
        std::uint8_t elem; // an elem_kind
        bool string;       // a Lua string (elem is meaningless)
    };
    bool boolean;
    std::int64_t integer;
    double number;
    text string;
    bytes view;
};

// Non-owning view of a Lua stack: the single wall between RHP's templates and the Lua C API.
// Every member is defined out of line in puc_lua/stack.cpp, so binding code instantiated in user
// translation units never needs lua.h.
//
// Indices follow Lua: positive from the bottom (1 = first argument), negative from the top.
// Readers (to_*) never raise Lua errors; they return nullopt / an Rhp::error instead. Pushers may
// raise a Lua memory error, which unwinds as a C++ exception through RAII-safe frames.
class stack {
public:
    explicit stack(lua_State* state) noexcept : state_(state) {}

    [[nodiscard]] lua_State* state() const noexcept { return state_; }

    // The sandbox that owns this state (set when the state is created).
    [[nodiscard]] detail::context& context() const noexcept;

    // ---- size ------------------------------------------------------------------------------
    [[nodiscard]] int top() const noexcept;
    void set_top(int index) const;
    void pop(int count = 1) const;
    [[nodiscard]] int abs_index(int index) const noexcept;
    [[nodiscard]] type_kind type(int index) const noexcept;
    [[nodiscard]] bool is_none_or_nil(int index) const noexcept;
    // "number", "string", ... or the __name of a userdata's metatable ("entity").
    [[nodiscard]] std::string_view type_name(int index) const noexcept;

    // ---- push ------------------------------------------------------------------------------
    void push_nil() const;
    void push_bool(bool b) const;
    void push_integer(std::int64_t i) const;
    void push_number(double d) const;
    void push_string(std::string_view s) const;
    void push_value(const value& v) const;
    void push_copy(int index) const;
    // A C closure; the top `upvalues` values become its upvalues 1..n and are popped.
    void push_function(c_function fn, int upvalues = 0) const;
    void new_table(int array_hint = 0, int record_hint = 0) const;

    // ---- tables ----------------------------------------------------------------------------
    // t[key] = top value (popped). t is at `table`.
    void set_field(int table, std::string_view key) const;
    // Pushes t[key] (raw access, no metamethods).
    void raw_get_field(int table, std::string_view key) const;

    // ---- read (never raises) ---------------------------------------------------------------
    [[nodiscard]] std::optional<bool> to_bool(int index) const noexcept;               // booleans only
    [[nodiscard]] std::optional<std::int64_t> to_integer(int index) const noexcept;    // integers and integral floats
    [[nodiscard]] std::optional<double> to_number(int index) const noexcept;           // numbers only
    [[nodiscard]] std::optional<std::string_view> to_string(int index) const noexcept; // strings only, no coercion
    // nil, booleans, numbers, strings and (acyclic, <= 64 deep) tables. Functions etc. fail.
    [[nodiscard]] result<value> to_value(int index) const;
    // Arguments 1..count, read as `kinds` says into `out` in one call (the plain binding
    // trampoline's reader): by type only, exactly as to_bool / to_integer / to_number / to_string
    // read them. False at the first one that doesn't fit (`out` is then partly written).
    [[nodiscard]] bool read_args(const arg_kind* kinds, arg_slot* out, int count) const noexcept;

    // ---- upvalues of the running C closure ---------------------------------------------------
    [[nodiscard]] std::string_view upvalue_string(int n) const noexcept;
    [[nodiscard]] static int upvalue_index(int n) noexcept;

    // ---- typed userdata (opaque handles) -------------------------------------------------------
    // Creates (once per state) the metatable registered under `key` for one C++ handle type.
    // `type_tag` identifies the C++ type; reusing a key with a different tag fails with kAlreadyLoaded.
    // eq / tostring become __eq / __tostring. __name is set to `display_name`.
    [[nodiscard]] result<void> define_userdata_type(std::string_view key, std::string_view display_name, const void* type_tag,
                                                    c_function eq, c_function tostring) const;
    // Pushes a new userdata of `size` bytes with the metatable registered under `key`.
    [[nodiscard]] void* push_userdata(std::size_t size, std::string_view key) const;
    // The userdata's memory if the value at `index` carries the metatable registered under `key`.
    [[nodiscard]] void* to_userdata(int index, std::string_view key) const noexcept;
    // Methods and properties of the handle type registered under `key` (defined first). The
    // function on top (popped) becomes method `name` (h:name(...)) or property `name` (h.name,
    // read-only: called with the handle; a C function without upvalues runs in __index's own frame,
    // the handle at index 1). handle_member_free fails with kAlreadyLoaded when the
    // handle already has a member of that name.
    [[nodiscard]] result<void> handle_member_free(std::string_view key, std::string_view name) const;
    void add_handle_member(std::string_view key, std::string_view name, bool property) const;
    // Pushes a copy of `size` bytes as a userdata of the handle type defined with `type_tag`.
    // Returns false and pushes nothing when no lib in this state defined that type.
    [[nodiscard]] bool push_handle(const void* type_tag, const void* data, std::size_t size) const;

    // ---- typed views and struct views (views.hpp; puc_lua/views.cpp) ----------------------------
    // Pushes a host view (a span or struct view a binding returned) and returns where its
    // view_source goes (init.source_size bytes); attach_view_source(source) on the view on top then
    // owns it (destroyed with the view), resolves it once and raises the binding's error, or
    // replaces the view with nil when a struct view's binding returned null.
    [[nodiscard]] void* push_host_view(const detail::host_view_init& init) const;
    void attach_view_source(detail::view_source* source) const;
    // The memory of the span argument at `index` for one call: a typed view, a byte buffer or a Lua
    // string (request.bytes), or a table of numbers copied into a temporary left on the stack
    // (request.tables). A writable request journals a host view's range first (needs kPatch).
    [[nodiscard]] result<detail::span_arg> to_span(int index, const detail::span_request& request) const;
    // The object a struct view of the type registered under `key` stands for (nil: nullptr when
    // `nil_ok`).
    [[nodiscard]] result<void*> to_object(int index, std::string_view key, std::string_view name, bool nil_ok) const;
    // Creates (once per state) the metatable of a struct view type and adds its fields; a type
    // another lib defined gets the fields it lacks (one defined differently: kAlreadyLoaded), a
    // name taken by another C++ type fails with kAlreadyLoaded.
    [[nodiscard]] result<void> define_view_type(const detail::view_type_info& type, const detail::field_desc* fields, std::size_t count) const;

    // ---- registry references -----------------------------------------------------------------
    [[nodiscard]] int ref() const; // pops the top value, returns a reference to it
    void unref(int reference) const;
    void push_ref(int reference) const;

    // ---- calls ---------------------------------------------------------------------------------
    // Protected call of the function below `nargs` arguments on top. On success leaves `nresults`
    // results (-1 = all); on failure pops the error and returns it with a traceback.
    [[nodiscard]] result<void> call(int nargs, int nresults) const;
    // Unprotected call: errors propagate as a Lua error. Only valid inside a protected context
    // (a binding trampoline, or a function run by run_protected).
    void call_unprotected(int nargs, int nresults) const;
    // Runs fn(L) in protected mode with `data` as its only argument (a light userdata, read with
    // to_light_userdata(1)). Any Lua error - including out-of-memory while pushing - comes back as
    // an Rhp::error with a traceback instead of reaching Lua's panic handler. The stack is restored.
    [[nodiscard]] result<void> run_protected(c_function fn, void* data) const;
    [[nodiscard]] void* to_light_userdata(int index) const noexcept;

    // ---- errors --------------------------------------------------------------------------------
    // Raises a Lua error carrying `err` (formatted "[code] where: message"). Never returns; unwinds
    // as a C++ exception. Must not be called inside a try block that catches (...).
    [[noreturn]] void raise(const error& err) const;

private:
    lua_State* state_;
};

} // namespace Rhp::script

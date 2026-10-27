#pragma once

// Private to Src/rhp/script/puc_lua: the userdata behind typed views, struct views and byte
// buffers (views.cpp, buffer.cpp), and the journal of writes to host memory (view_journal.cpp).
//
// Every one is a view_node at the start of a userdata (its payload after it: a buffer's bytes, or
// a host view's view_source). A node finds its memory on every access (locate): a buffer's bytes,
// what its host source resolves to now, or a part of its parent node (a slice, a typed view of a
// buffer, a struct view's array or nested struct field), the parent kept alive by uservalue 1.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/puc_lua/keys.hpp> // kSpanKey, kBufferKey
#include <rhp/script/stack.hpp>
#include <rhp/script/views.hpp>

struct lua_State;

namespace Rhp::script::detail {

class context;

enum class node_shape : std::uint8_t {
    kBytes, // a byte buffer (elem kU8)
    kSpan,  // a typed view
    kObject // a struct view
};

enum class node_origin : std::uint8_t {
    kInline, // a buffer: the bytes follow the node
    kHost,   // C++ memory: `source` (in the payload) finds it
    kParent  // a part of `parent`
};

// The journal layer a node wrote through last, valid while no layer anywhere went away (epoch)
// and the same code runs (owner, context).
struct journal_cache {
    void* layer = nullptr;
    std::uint64_t epoch = 0;
    const context* ctx = nullptr;
    effect_owner owner{};
};

struct view_node {
    node_shape shape = node_shape::kSpan;
    node_origin origin = node_origin::kInline;
    elem_kind elem = elem_kind::kU8;
    bool writable = false;
    bool source_live = false; // kHost: `source` was constructed (__gc destroys it)
    std::size_t offset = 0;   // kParent: bytes into the parent
    std::size_t count = 0;    // kBytes / kSpan of a buffer or a parent: elements (kHost: what resolve finds)
    std::byte* data = nullptr;
    view_source* source = nullptr;
    view_node* parent = nullptr;
    const view_type_info* type = nullptr; // kObject
    std::string_view label{};             // errors and journal entries ("game.samples")
    journal_cache cache{};
};

// Where a node's memory is right now.
struct place {
    std::byte* data = nullptr;
    std::size_t size = 0;            // bytes
    const view_node* root = nullptr; // the host node whose source finds the memory (nullptr: a buffer, never journaled)
    std::byte* root_data = nullptr;
    std::size_t root_size = 0;
};

// ---- views.cpp ---------------------------------------------------------------------------------

// stack::raise of `err`, or of an error made of `code`, `message` and `where`.
[[noreturn]] void raise(lua_State* L, error err);
[[noreturn]] void raise(lua_State* L, errc code, std::string message, std::string_view where);
// The node a span view or buffer at `index` is, or nullptr.
[[nodiscard]] view_node* to_span_node(lua_State* L, int index) noexcept;
// Where `node` is now, or why it isn't (the caller labels the error).
[[nodiscard]] result<place> locate(const view_node& node);
// The same on every access: false (no error made) when locate would fail.
[[nodiscard]] bool find_place(const view_node& node, place& out) noexcept;
// locate, raising its error (where = the node's label).
place locate_or_raise(lua_State* L, const view_node& node);
// Before bytes [offset, offset + len) of `p` (relative to p.data) change: checks the caller may
// write host memory (kPatch) and journals them. False when nothing may be written (the sandbox is
// closing). Script-owned memory (p.root == nullptr) needs nothing. Errors are labelled with the
// field ("transform.x") or the node's label.
bool before_write(lua_State* L, view_node& writer, const place& p, std::size_t offset, std::size_t len, const field_desc* field = nullptr);
// Pushes the element of kind `k` at `p`.
void push_elem(lua_State* L, elem_kind k, const std::byte* p);

// Why a Lua value doesn't fit an element.
enum class elem_error : std::uint8_t {
    kNone,
    kType,       // not a number (not a boolean, for a bool)
    kNotInteger, // 1.5 for an integer element
    kRange       // outside the element type
};

// Converts the Lua value at `index` to an element of kind `k` into `out` (elem_size(k) bytes).
[[nodiscard]] elem_error to_elem(lua_State* L, int index, elem_kind k, std::byte* out) noexcept;
// Raises the error to_elem reported, labelled `where`.
[[noreturn]] void raise_elem(lua_State* L, int index, elem_kind k, elem_error e, std::string where);
// A new node (a userdata with `payload` bytes after the node and one uservalue) carrying the
// metatable registered under `key`; left on top of the stack.
view_node* new_node(lua_State* L, std::size_t payload, const char* key);
// The payload after a node.
[[nodiscard]] std::byte* node_payload(view_node* node) noexcept;
// Pushes a part of the node at `index`: `count` elements of kind `elem` from byte `offset` (already
// checked to fit), a buffer (kBytes) or a typed view (kSpan); writable when the parent is.
void push_part(lua_State* L, int index, std::size_t offset, std::size_t count, node_shape shape, elem_kind elem);
// Reads a span argument for stack::read_args (no error): false when it isn't one.
[[nodiscard]] bool read_span_arg(lua_State* L, int index, arg_slot& out) noexcept;
// Sets the metamethods of the span or buffer metatable at `mt` and adds the shared methods (slice,
// fill, copy) to `methods`. A span's __index is a C function (integers are elements, names are
// methods: get, set, totable, kind, writable too), with __newindex, __pairs and __gc; a buffer's
// __index is `methods` itself and b[i] = v raises. Both get __len, __eq and a locked metatable.
void set_sequence_metamethods(lua_State* L, int mt, int methods, bool buffer);
// Creates the span metatable.
void define_span_type(lua_State* L);
// Parses optional element range arguments i, j (1-based, inclusive, as string.sub without negative
// indices) at `i_index` against `count`: returns [first, last) 0-based. Raises when they don't fit.
std::pair<std::size_t, std::size_t> range_args(lua_State* L, int i_index, std::size_t count, std::string_view where);

// ---- view_journal.cpp ------------------------------------------------------------------------------

// Makes sure the running code's layer of p.root holds the originals of bytes [offset, offset + len)
// of the root region (offset counted from p.root_data), copying the ones it doesn't have yet. False:
// nothing may be written (the sandbox is closing). Throws std::bad_alloc.
bool journal_touch(context& ctx, journal_cache& cache, const place& p, std::size_t offset, std::size_t len);
// Journal layers alive in this process (all sandboxes): tests check undone layers go away.
[[nodiscard]] std::size_t journal_layers() noexcept;

} // namespace Rhp::script::detail

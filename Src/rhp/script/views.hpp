#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <type_traits>

#include <rhp/core/result.hpp>

// Typed buffers and struct views: C++ memory a script reads and writes in place (no copy into Lua
// tables), every write journaled so a revert puts the bytes back.
//
//   std::span<float> samples();                     // a binding returning a span: a typed view
//   transform* transform_of(entity_id e);           // a pointer (or reference) to a declared view type
//
//   using game_lib = Rhp::lib<"game">
//       ::fn<"samples", &samples>                   // game.samples()[1] = 0.5  (journaled)
//       ::view<"transform", transform>              // a struct view type (standard layout)
//       ::field<"x", &transform::x>                 // t.x, t.x = 3            (journaled)
//       ::ro_field<"id", &transform::id>            // read-only
//       ::method<"transform", &transform_of>;       // e:transform() -> view (nil when null)
//
// A view keeps no pointer: every access calls its binding again with the arguments it was made
// with (handles checked with their is_alive first), so a view kept across frames finds the memory
// where it is now, or raises (kStaleHandle) when it is gone. See Docs/guide/views-and-buffers.md.

namespace Rhp::script {

// The element types a span crosses as: every arithmetic type but bool, and std::byte.
template <class T>
concept span_element = std::same_as<T, std::remove_cv_t<T>> &&
                       ((std::is_arithmetic_v<T> && !std::same_as<T, bool> && (!std::is_floating_point_v<T> || sizeof(T) == 4 || sizeof(T) == 8) &&
                         sizeof(T) <= 8) ||
                        std::same_as<T, std::byte>);

// How one element (or one struct field) is stored, as views read and write it.
enum class elem_kind : std::uint8_t {
    kI8,
    kU8,
    kI16,
    kU16,
    kI32,
    kU32,
    kI64,
    kU64,
    kF32,
    kF64,
    kByte, // std::byte: an integer 0..255
    kBool  // struct fields only
};

[[nodiscard]] constexpr std::size_t elem_size(elem_kind k) noexcept {
    switch (k) {
    case elem_kind::kI8:
    case elem_kind::kU8:
    case elem_kind::kByte:
    case elem_kind::kBool: return 1;
    case elem_kind::kI16:
    case elem_kind::kU16: return 2;
    case elem_kind::kI32:
    case elem_kind::kU32:
    case elem_kind::kF32: return 4;
    case elem_kind::kI64:
    case elem_kind::kU64:
    case elem_kind::kF64: return 8;
    }
    return 1;
}

// The name scripts use ("f32", buf:view("f32")).
[[nodiscard]] constexpr std::string_view elem_name(elem_kind k) noexcept {
    switch (k) {
    case elem_kind::kI8: return "i8";
    case elem_kind::kU8: return "u8";
    case elem_kind::kI16: return "i16";
    case elem_kind::kU16: return "u16";
    case elem_kind::kI32: return "i32";
    case elem_kind::kU32: return "u32";
    case elem_kind::kI64: return "i64";
    case elem_kind::kU64: return "u64";
    case elem_kind::kF32: return "f32";
    case elem_kind::kF64: return "f64";
    case elem_kind::kByte: return "byte";
    case elem_kind::kBool: return "bool";
    }
    return "?";
}

[[nodiscard]] constexpr bool is_float_kind(elem_kind k) noexcept {
    return k == elem_kind::kF32 || k == elem_kind::kF64;
}

// An element of one byte that byte-oriented parameters take (std::span<const std::byte>, char, ...).
[[nodiscard]] constexpr bool is_byte_kind(elem_kind k) noexcept {
    return k == elem_kind::kI8 || k == elem_kind::kU8 || k == elem_kind::kByte;
}

namespace detail {

template <class T>
consteval elem_kind integer_kind() {
    if constexpr (sizeof(T) == 1) {
        return std::is_signed_v<T> ? elem_kind::kI8 : elem_kind::kU8;
    } else if constexpr (sizeof(T) == 2) {
        return std::is_signed_v<T> ? elem_kind::kI16 : elem_kind::kU16;
    } else if constexpr (sizeof(T) == 4) {
        return std::is_signed_v<T> ? elem_kind::kI32 : elem_kind::kU32;
    } else {
        static_assert(sizeof(T) == 8, "integers of 1, 2, 4 or 8 bytes");
        return std::is_signed_v<T> ? elem_kind::kI64 : elem_kind::kU64;
    }
}

} // namespace detail

// The elem_kind of a span element, a struct field's arithmetic type, bool or enum (its underlying type).
template <class T>
consteval elem_kind elem_kind_of() {
    using U = std::remove_cv_t<T>;
    if constexpr (std::same_as<U, std::byte>) {
        return elem_kind::kByte;
    } else if constexpr (std::same_as<U, bool>) {
        return elem_kind::kBool;
    } else if constexpr (std::is_enum_v<U>) {
        return detail::integer_kind<std::underlying_type_t<U>>();
    } else if constexpr (std::is_floating_point_v<U>) {
        return sizeof(U) == 4 ? elem_kind::kF32 : elem_kind::kF64;
    } else {
        return detail::integer_kind<U>();
    }
}

// A one-byte element type a byte buffer or a Lua string can stand in for.
template <class T>
concept byte_element = span_element<std::remove_cv_t<T>> && sizeof(T) == 1 && !std::is_floating_point_v<std::remove_cv_t<T>>;

namespace detail {

// Bytes a view covers right now.
struct region {
    std::byte* data = nullptr;
    std::size_t size = 0; // bytes
};

// Where a host view's memory is: made by the binding trampoline that returned the view (its
// binding and the arguments it was called with), asked again on every access and when a journaled
// write is undone. Never holds a pointer into the memory itself.
class view_source {
public:
    virtual ~view_source() = default;
    view_source& operator=(const view_source&) = delete;

    // The memory now, or why there is none (kStaleHandle: a handle argument is dead, or the binding
    // returned a null pointer; the binding's own error otherwise). Never throws.
    [[nodiscard]] virtual result<region> resolve() const noexcept = 0;
    // The same without saying why not (every access: no error is made when there is memory).
    [[nodiscard]] virtual bool find(region& out) const noexcept = 0;
    // A copy kept by the journal (it outlives the Lua view).
    [[nodiscard]] virtual std::unique_ptr<view_source> clone() const = 0;
    // Same binding, same arguments: the same memory (the journal stacks their writes together).
    [[nodiscard]] virtual bool same(const view_source& other) const noexcept = 0;
    // Identifies the binding (one address per binding).
    [[nodiscard]] virtual const void* binding() const noexcept = 0;

protected:
    view_source() = default;
    view_source(const view_source&) = default; // clone()
};

struct view_type_info;

// One field of a struct view type, made at compile time from a ::field<> entry.
enum class field_shape : std::uint8_t {
    kValue, // a number, bool or enum
    kArray, // a C array or std::array of span elements: read as a span view
    kObject // a struct of another declared view type: read as a struct view
};

struct field_desc {
    std::string_view name;
    field_shape shape = field_shape::kValue;
    elem_kind elem = elem_kind::kU8; // kValue: the value; kArray: an element
    bool writable = false;
    std::size_t count = 0;                                // kArray: elements
    void* (*address)(void* object) noexcept = nullptr;    // the field inside an object of its type
    const view_type_info* (*nested)() noexcept = nullptr; // kObject: the field's view type
    bool ranged = false;                                  // writes must lie in [min, max] (Rhp::range)
    double min = 0;
    double max = 0;
};

// A struct view type (::view<"name", T>): its Lua name, registry key and size. Its fields are given
// to stack::define_view_type and live in its metatable.
struct view_type_info {
    std::string_view name; // "transform"
    std::string_view key;  // "rhp.view.transform"
    const void* type_tag = nullptr;
    std::size_t size = 0;
};

// What a binding trampoline asks for when it pushes a host view (stack::push_host_view).
enum class view_shape : std::uint8_t {
    kSpan,
    kObject
};

struct host_view_init {
    view_shape shape = view_shape::kSpan;
    elem_kind elem = elem_kind::kU8; // kSpan
    bool writable = false;
    std::size_t source_size = 0;          // bytes for the view_source made in place (8-byte aligned: call_view checks it needs no more)
    std::string_view label{};             // "game.samples": errors and journal entries
    const view_type_info* type = nullptr; // kObject
};

// A span argument read by stack::to_span: what the binding gets for std::span<T> / std::span<const T>.
struct span_request {
    elem_kind elem = elem_kind::kU8;
    bool writable = false; // std::span<T>: C++ may write (a host view's range is journaled first)
    bool bytes = false;    // a one-byte element: byte buffers, byte views and Lua strings fit too
    bool tables = false;   // a table of numbers fits (copied for the call; read-only spans only)
};

struct span_arg {
    void* data = nullptr;
    std::size_t count = 0; // elements
};

} // namespace detail

} // namespace Rhp::script

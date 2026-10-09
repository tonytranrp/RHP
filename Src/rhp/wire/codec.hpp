#pragma once

#include <concepts>
#include <cstddef>
#include <string_view>

#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace Rhp::wire {

// Bounds a decoder enforces on untrusted input (the frame length already bounds the total size).
struct decode_limits {
    std::size_t max_depth = 100;         // nested arrays / maps
    std::size_t max_elements = 1u << 20; // values in total (array items, map keys and values)
};

// Payload codec policy for Rhp::config<>::codec<...>: Rhp::value <-> bytes.
//   encode appends to `out`; decode must consume all of `in` and reject anything else.
template <class C>
concept codec = requires(const value& v, utils::byte_buffer& out, utils::bytes_view in, const decode_limits& limits) {
    { C::name } -> std::convertible_to<std::string_view>;
    { C::encode(v, out) } -> std::same_as<result<void>>;
    { C::decode(in, limits) } -> std::same_as<result<value>>;
};

// A codec as two function pointers, so the session layer stays out of templates.
struct codec_ops {
    std::string_view name;
    result<void> (*encode)(const value& v, utils::byte_buffer& out) = nullptr;
    result<value> (*decode)(utils::bytes_view in, const decode_limits& limits) = nullptr;
};

template <codec C>
inline constexpr codec_ops codec_ops_for{C::name, &C::encode, &C::decode};

} // namespace Rhp::wire

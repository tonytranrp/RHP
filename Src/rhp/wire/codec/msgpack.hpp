#pragma once

#include <string_view>

#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/wire/codec.hpp>

namespace Rhp::wire {

// MessagePack for Rhp::value (RHP's own codec, no dependency). Every value kind maps 1:1:
//   nil, bool, integer (smallest int/uint form), number (float64), string (str), bytes (bin),
//   array, map (any key type, insertion order kept).
// Decoding accepts every non-ext MessagePack form: float32 widens to a number, a uint64 above
// INT64_MAX becomes a number, ext types and the never-used 0xc1 are rejected (kProtocol).
// Element counts are checked against the bytes left before anything is reserved.
struct msgpack {
    static constexpr std::string_view name = "msgpack";

    static result<void> encode(const value& v, utils::byte_buffer& out);
    static result<value> decode(utils::bytes_view in, const decode_limits& limits = {});
};

static_assert(codec<msgpack>);

} // namespace Rhp::wire

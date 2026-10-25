#pragma once

// JSON for rhp-cli's Debug Adapter Protocol bridge, over Rhp::value: objects are maps with string
// keys (in order), arrays are arrays, integers stay integers, null is nil.

#include <optional>
#include <string>
#include <string_view>

#include <rhp/core/value.hpp>

namespace rhp_cli {

// One JSON document (surrounding whitespace allowed); nullopt if it isn't valid JSON or nests
// deeper than 64.
[[nodiscard]] std::optional<Rhp::value> parse_json(std::string_view text);

// Compact JSON. Bytes become arrays of numbers; non-string map keys become their JSON text.
[[nodiscard]] std::string to_json(const Rhp::value& v);

} // namespace rhp_cli

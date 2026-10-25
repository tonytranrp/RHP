#pragma once

// JSON over Rhp::value: objects are maps with string keys (in order), arrays are arrays, integers
// stay integers, null is nil. Test reports, API descriptions and rhp-cli's Debug Adapter Protocol
// bridge use it.

#include <optional>
#include <string>
#include <string_view>

#include <rhp/core/value.hpp>

namespace Rhp::json {

// One JSON document (surrounding whitespace allowed); nullopt if it isn't valid JSON or nests
// deeper than 64.
[[nodiscard]] std::optional<value> parse(std::string_view text);

// JSON text: compact (indent < 0), or one item per line indented by `indent` spaces per level.
// Bytes become arrays of numbers; non-string map keys become their JSON text; NaN and infinities null.
[[nodiscard]] std::string to_text(const value& v, int indent = -1);

} // namespace Rhp::json

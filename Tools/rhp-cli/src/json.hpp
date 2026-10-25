#pragma once

// rhp-cli's names for the library's JSON codec (rhp/core/json.hpp).

#include <optional>
#include <string>
#include <string_view>

#include <rhp/core/json.hpp>
#include <rhp/core/value.hpp>

namespace rhp_cli {

[[nodiscard]] inline std::optional<Rhp::value> parse_json(std::string_view text) {
    return Rhp::json::parse(text);
}

[[nodiscard]] inline std::string to_json(const Rhp::value& v) {
    return Rhp::json::to_text(v);
}

} // namespace rhp_cli

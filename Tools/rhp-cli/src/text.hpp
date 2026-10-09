#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/net/endpoint.hpp>

namespace rhp_cli {

// "127.0.0.1:7777", "localhost:7777", "[::1]:7777". `listen` makes a listening endpoint (reverse
// mode), `insecure_lan` allows a non-loopback address without TLS.
[[nodiscard]] Rhp::result<Rhp::endpoint> parse_endpoint(std::string_view text, bool listen, bool insecure_lan);

// True when `chunk` looks like unfinished Lua (an open block, bracket, string or comment), so the
// REPL keeps reading lines. A heuristic: the host's compiler has the last word.
[[nodiscard]] bool lua_incomplete(std::string_view chunk);

// A value as Lua-ish text: 1, 2.5, "text", true, nil, {1, 2, x = 3}, <12 bytes>.
[[nodiscard]] std::string format_value(const Rhp::value& v);
[[nodiscard]] std::string format_values(const std::vector<Rhp::value>& values);

// Splits a command line into words; "double quotes" group words (\" is a quote inside them; other
// backslashes are kept, so Windows paths work).
// With `keep_quotes` a quoted word keeps its quotes (so `call` can tell "42" from 42).
[[nodiscard]] std::vector<std::string> split_words(std::string_view line, bool keep_quotes = false);

// A call argument: 42, -1.5, "text", 'text', true, false, nil; anything else is a string.
[[nodiscard]] Rhp::value parse_literal(std::string_view text);

// Words to complete from LuaLS stubs: lib names, `lib.function`, `lib.variable`.
[[nodiscard]] std::vector<std::string> names_from_stubs(std::string_view stubs);

// A module name for a script file: its stem, lowercased ("Low_Grav.lua" → "low_grav").
[[nodiscard]] std::string module_name_for(std::string_view path);

} // namespace rhp_cli

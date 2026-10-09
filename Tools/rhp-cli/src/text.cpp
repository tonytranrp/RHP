#include "text.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <format>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/net/endpoint.hpp>

namespace rhp_cli {

namespace {

[[nodiscard]] bool ident_start(char c) noexcept {
    return std::isalpha(static_cast<unsigned char>(c)) != 0 || c == '_';
}

[[nodiscard]] bool ident_char(char c) noexcept {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
}

[[nodiscard]] std::string_view trim(std::string_view text) noexcept {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())) != 0) {
        text.remove_prefix(1);
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())) != 0) {
        text.remove_suffix(1);
    }
    return text;
}

// The level of a long bracket opening at `at` ("[[" → 0, "[==[" → 2), or -1 if there is none.
[[nodiscard]] int long_bracket(std::string_view s, std::size_t at) noexcept {
    if (at >= s.size() || s[at] != '[') {
        return -1;
    }
    std::size_t i = at + 1;
    int level = 0;
    while (i < s.size() && s[i] == '=') {
        ++level;
        ++i;
    }
    return i < s.size() && s[i] == '[' ? level : -1;
}

// Index just past the long bracket closing at `level` from `from`, or npos.
[[nodiscard]] std::size_t close_long(std::string_view s, std::size_t from, int level) {
    const std::string closer = "]" + std::string(static_cast<std::size_t>(level), '=') + "]";
    const auto at = s.find(closer, from);
    return at == std::string_view::npos ? std::string_view::npos : at + closer.size();
}

void quote(std::string& out, std::string_view text) {
    out += '"';
    for (const char c : text) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: out += c;
        }
    }
    out += '"';
}

[[nodiscard]] bool is_identifier(std::string_view s) noexcept {
    return !s.empty() && ident_start(s.front()) && std::all_of(s.begin(), s.end(), ident_char);
}

void format_into(std::string& out, const Rhp::value& v, int depth) {
    using kind = Rhp::value::kind;
    if (depth > 16) {
        out += "{...}";
        return;
    }
    switch (v.type()) {
    case kind::kNil: out += "nil"; return;
    case kind::kBool: out += *v.get_if<bool>() ? "true" : "false"; return;
    case kind::kInteger: out += std::format("{}", *v.get_if<std::int64_t>()); return;
    case kind::kNumber: out += std::format("{}", *v.get_if<double>()); return;
    case kind::kString: quote(out, *v.get_if<std::string>()); return;
    case kind::kBytes: out += std::format("<{} bytes>", v.get_if<Rhp::value::bytes>()->size()); return;
    case kind::kArray: {
        out += '{';
        bool first = true;
        for (const Rhp::value& item : *v.get_if<Rhp::value::array>()) {
            out += first ? "" : ", ";
            first = false;
            format_into(out, item, depth + 1);
        }
        out += '}';
        return;
    }
    case kind::kMap: {
        out += '{';
        bool first = true;
        for (const auto& [k, item] : *v.get_if<Rhp::value::map>()) {
            out += first ? "" : ", ";
            first = false;
            if (const auto* name = k.get_if<std::string>(); name != nullptr && is_identifier(*name)) {
                out += *name;
            } else {
                out += '[';
                format_into(out, k, depth + 1);
                out += ']';
            }
            out += " = ";
            format_into(out, item, depth + 1);
        }
        out += '}';
        return;
    }
    }
}

} // namespace

Rhp::result<Rhp::endpoint> parse_endpoint(std::string_view text, bool listen, bool insecure_lan) {
    text = trim(text);
    const auto colon = text.rfind(':');
    if (colon == std::string_view::npos || colon == 0 || colon + 1 == text.size()) {
        return Rhp::fail(Rhp::errc::kInvalidArgument, std::format("'{}' is not host:port", text), "rhp-cli");
    }
    std::string_view host = text.substr(0, colon);
    const std::string_view port_text = text.substr(colon + 1);
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    } else if (host.find(':') != std::string_view::npos) {
        return Rhp::fail(Rhp::errc::kInvalidArgument, "write IPv6 addresses in brackets: [::1]:7777", "rhp-cli");
    }
    std::uint16_t port = 0;
    const auto [end, ec] = std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
    if (ec != std::errc{} || end != port_text.data() + port_text.size()) {
        return Rhp::fail(Rhp::errc::kInvalidArgument, std::format("bad port '{}'", port_text), "rhp-cli");
    }
    if (listen) {
        return insecure_lan ? Rhp::endpoint::listen(host, port, Rhp::net::insecure_lan) : Rhp::endpoint::listen(host, port);
    }
    return insecure_lan ? Rhp::endpoint::dial(host, port, Rhp::net::insecure_lan) : Rhp::endpoint::dial(host, port);
}

bool lua_incomplete(std::string_view s) {
    int blocks = 0;
    int brackets = 0;
    std::size_t i = 0;
    while (i < s.size()) {
        const char c = s[i];
        if (c == '-' && i + 1 < s.size() && s[i + 1] == '-') {
            const int level = long_bracket(s, i + 2);
            if (level >= 0) {
                const auto end = close_long(s, i + 2, level);
                if (end == std::string_view::npos) {
                    return true; // open long comment
                }
                i = end;
            } else {
                const auto nl = s.find('\n', i);
                i = nl == std::string_view::npos ? s.size() : nl + 1;
            }
            continue;
        }
        if (c == '"' || c == '\'') {
            std::size_t j = i + 1;
            while (j < s.size() && s[j] != c) {
                if (s[j] == '\\') {
                    ++j;
                } else if (s[j] == '\n') {
                    break; // an unfinished short string is an error, not more input
                }
                ++j;
            }
            if (j >= s.size()) {
                return true;
            }
            i = j + 1;
            continue;
        }
        if (c == '[') {
            const int level = long_bracket(s, i);
            if (level >= 0) {
                const auto end = close_long(s, i, level);
                if (end == std::string_view::npos) {
                    return true; // open long string
                }
                i = end;
                continue;
            }
        }
        if (ident_start(c)) {
            std::size_t j = i;
            while (j < s.size() && ident_char(s[j])) {
                ++j;
            }
            const std::string_view word = s.substr(i, j - i);
            const bool field = i > 0 && (s[i - 1] == '.' || s[i - 1] == ':');
            if (!field) {
                if (word == "function" || word == "do" || word == "if" || word == "repeat") {
                    ++blocks;
                } else if (word == "end" || word == "until") {
                    --blocks;
                }
            }
            i = j;
            continue;
        }
        if (c == '(' || c == '[' || c == '{') {
            ++brackets;
        } else if (c == ')' || c == ']' || c == '}') {
            --brackets;
        }
        ++i;
    }
    return blocks > 0 || brackets > 0;
}

std::string format_value(const Rhp::value& v) {
    std::string out;
    format_into(out, v, 0);
    return out;
}

std::string format_values(const std::vector<Rhp::value>& values) {
    std::string out;
    for (const Rhp::value& v : values) {
        if (!out.empty()) {
            out += "\t";
        }
        format_into(out, v, 0);
    }
    return out;
}

std::vector<std::string> split_words(std::string_view line) {
    std::vector<std::string> words;
    std::size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i])) != 0) {
            ++i;
        }
        if (i >= line.size()) {
            break;
        }
        std::string word;
        if (line[i] == '"') {
            ++i;
            while (i < line.size() && line[i] != '"') {
                // Only \" is an escape: Windows paths keep their backslashes.
                if (line[i] == '\\' && i + 1 < line.size() && line[i + 1] == '"') {
                    ++i;
                }
                word += line[i++];
            }
            ++i; // closing quote
        } else {
            while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i])) == 0) {
                word += line[i++];
            }
        }
        words.push_back(std::move(word));
    }
    return words;
}

Rhp::value parse_literal(std::string_view text) {
    text = trim(text);
    if (text == "nil") {
        return Rhp::value{};
    }
    if (text == "true" || text == "false") {
        return Rhp::value{text == "true"};
    }
    if (text.size() >= 2 && (text.front() == '"' || text.front() == '\'') && text.back() == text.front()) {
        return Rhp::value{std::string{text.substr(1, text.size() - 2)}};
    }
    std::int64_t i = 0;
    if (const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), i); ec == std::errc{} && end == text.data() + text.size()) {
        return Rhp::value{i};
    }
    double d = 0;
    if (const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), d); ec == std::errc{} && end == text.data() + text.size()) {
        return Rhp::value{d};
    }
    return Rhp::value{std::string{text}};
}

std::vector<std::string> names_from_stubs(std::string_view stubs) {
    std::set<std::string> names;
    std::string current;
    while (!stubs.empty()) {
        const auto nl = stubs.find('\n');
        std::string_view line = trim(stubs.substr(0, nl));
        stubs = nl == std::string_view::npos ? std::string_view{} : stubs.substr(nl + 1);
        constexpr std::string_view kClass = "---@class ";
        constexpr std::string_view kField = "---@field ";
        constexpr std::string_view kFunction = "function ";
        if (line.starts_with(kClass)) {
            line.remove_prefix(kClass.size());
            current = std::string{line.substr(0, line.find_first_of(" :"))};
            if (current.find('.') == std::string::npos && current.find('_') != 0) {
                names.insert(current);
            }
        } else if (line.starts_with(kField) && !current.empty()) {
            line.remove_prefix(kField.size());
            names.insert(current + "." + std::string{line.substr(0, line.find(' '))});
        } else if (line.starts_with(kFunction)) {
            line.remove_prefix(kFunction.size());
            names.insert(std::string{line.substr(0, line.find('('))});
        }
    }
    return {names.begin(), names.end()};
}

std::string module_name_for(std::string_view path) {
    const auto slash = path.find_last_of("/\\");
    std::string_view file = slash == std::string_view::npos ? path : path.substr(slash + 1);
    if (const auto dot = file.rfind('.'); dot != std::string_view::npos && dot > 0) {
        file = file.substr(0, dot);
    }
    std::string name;
    for (const char c : file) {
        name += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return name;
}

} // namespace rhp_cli

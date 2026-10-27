#pragma once

#include <cctype>
#include <cstddef>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace Rhp::security::detail {

[[nodiscard]] inline std::string_view trim(std::string_view text) noexcept {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())) != 0) {
        text.remove_prefix(1);
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())) != 0) {
        text.remove_suffix(1);
    }
    return text;
}

// One line of a key file: its 1-based number and its text without the comment (from '#') and
// surrounding whitespace. Blank lines are skipped.
struct text_line {
    std::size_t number = 0;
    std::string_view text;
};

[[nodiscard]] inline std::vector<text_line> content_lines(std::string_view text) {
    std::vector<text_line> lines;
    std::size_t number = 0;
    while (!text.empty()) {
        const auto end = text.find('\n');
        std::string_view line = text.substr(0, end);
        text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
        ++number;
        if (const auto hash = line.find('#'); hash != std::string_view::npos) {
            line = line.substr(0, hash);
        }
        line = trim(line);
        if (!line.empty()) {
            lines.push_back({number, line});
        }
    }
    return lines;
}

// Whitespace-separated fields.
[[nodiscard]] inline std::vector<std::string_view> fields(std::string_view line) {
    std::vector<std::string_view> out;
    while (true) {
        line = trim(line);
        if (line.empty()) {
            return out;
        }
        std::size_t end = 0;
        while (end < line.size() && std::isspace(static_cast<unsigned char>(line[end])) == 0) {
            ++end;
        }
        out.push_back(line.substr(0, end));
        line.remove_prefix(end);
    }
}

// The whole file in one allocation of its size when the size can be read, so a key file's text
// leaves no reallocated copies behind (the caller wipes the one it gets).
[[nodiscard]] inline std::optional<std::string> read_file(const std::string& path) {
    std::ifstream in{path, std::ios::binary | std::ios::ate};
    if (!in) {
        return std::nullopt;
    }
    if (const auto size = in.tellg(); size >= 0 && in.seekg(0)) {
        std::string text(static_cast<std::size_t>(size), '\0');
        if (in.read(text.data(), static_cast<std::streamsize>(size)) || in.eof()) {
            text.resize(static_cast<std::size_t>(in.gcount()));
            return text;
        }
        return std::nullopt;
    }
    in.clear();
    in.seekg(0);
    return std::string{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
}

} // namespace Rhp::security::detail

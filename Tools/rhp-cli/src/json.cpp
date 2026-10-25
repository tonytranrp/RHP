#include "json.hpp"

#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <format>
#include <iterator>
#include <locale>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <rhp/core/value.hpp>

namespace rhp_cli {

namespace {

constexpr int kMaxDepth = 64;

class reader {
public:
    explicit reader(std::string_view text) : s_(text) {}

    std::optional<Rhp::value> document() {
        auto v = value(0);
        skip();
        if (!v || i_ != s_.size()) {
            return std::nullopt;
        }
        return v;
    }

private:
    void skip() {
        while (i_ < s_.size() && (s_[i_] == ' ' || s_[i_] == '\t' || s_[i_] == '\n' || s_[i_] == '\r')) {
            ++i_;
        }
    }

    bool literal(std::string_view word) {
        if (s_.substr(i_, word.size()) != word) {
            return false;
        }
        i_ += word.size();
        return true;
    }

    std::optional<Rhp::value> value(int depth) {
        if (depth > kMaxDepth) {
            return std::nullopt;
        }
        skip();
        if (i_ >= s_.size()) {
            return std::nullopt;
        }
        switch (s_[i_]) {
        case '{': return object(depth);
        case '[': return array(depth);
        case '"': {
            auto text = string();
            return text ? std::optional<Rhp::value>{Rhp::value{std::move(*text)}} : std::nullopt;
        }
        case 't': return literal("true") ? std::optional<Rhp::value>{Rhp::value{true}} : std::nullopt;
        case 'f': return literal("false") ? std::optional<Rhp::value>{Rhp::value{false}} : std::nullopt;
        case 'n': return literal("null") ? std::optional<Rhp::value>{Rhp::value{}} : std::nullopt;
        default: return number();
        }
    }

    std::optional<Rhp::value> object(int depth) {
        ++i_; // {
        Rhp::value::map out;
        skip();
        if (i_ < s_.size() && s_[i_] == '}') {
            ++i_;
            return Rhp::value{std::move(out)};
        }
        while (true) {
            skip();
            if (i_ >= s_.size() || s_[i_] != '"') {
                return std::nullopt;
            }
            auto key = string();
            skip();
            if (!key || i_ >= s_.size() || s_[i_] != ':') {
                return std::nullopt;
            }
            ++i_;
            auto v = value(depth + 1);
            if (!v) {
                return std::nullopt;
            }
            out.emplace_back(Rhp::value{std::move(*key)}, std::move(*v));
            skip();
            if (i_ < s_.size() && s_[i_] == ',') {
                ++i_;
                continue;
            }
            if (i_ < s_.size() && s_[i_] == '}') {
                ++i_;
                return Rhp::value{std::move(out)};
            }
            return std::nullopt;
        }
    }

    std::optional<Rhp::value> array(int depth) {
        ++i_; // [
        Rhp::value::array out;
        skip();
        if (i_ < s_.size() && s_[i_] == ']') {
            ++i_;
            return Rhp::value{std::move(out)};
        }
        while (true) {
            auto v = value(depth + 1);
            if (!v) {
                return std::nullopt;
            }
            out.push_back(std::move(*v));
            skip();
            if (i_ < s_.size() && s_[i_] == ',') {
                ++i_;
                continue;
            }
            if (i_ < s_.size() && s_[i_] == ']') {
                ++i_;
                return Rhp::value{std::move(out)};
            }
            return std::nullopt;
        }
    }

    static void utf8(std::string& out, std::uint32_t cp) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }

    std::optional<std::uint32_t> hex4() {
        if (i_ + 4 > s_.size()) {
            return std::nullopt;
        }
        std::uint32_t cp = 0;
        const auto [end, ec] = std::from_chars(s_.data() + i_, s_.data() + i_ + 4, cp, 16);
        if (ec != std::errc{} || end != s_.data() + i_ + 4) {
            return std::nullopt;
        }
        i_ += 4;
        return cp;
    }

    std::optional<std::string> string() {
        ++i_; // "
        std::string out;
        while (i_ < s_.size()) {
            const char c = s_[i_++];
            if (c == '"') {
                return out;
            }
            if (static_cast<unsigned char>(c) < 0x20) {
                return std::nullopt;
            }
            if (c != '\\') {
                out += c;
                continue;
            }
            if (i_ >= s_.size()) {
                return std::nullopt;
            }
            const char e = s_[i_++];
            switch (e) {
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case '/': out += '/'; break;
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case 'u': {
                auto cp = hex4();
                if (!cp) {
                    return std::nullopt;
                }
                if (*cp >= 0xDC00 && *cp < 0xE000) {
                    return std::nullopt; // a low surrogate on its own
                }
                if (*cp >= 0xD800 && *cp < 0xDC00) { // a surrogate pair, or a lone high surrogate
                    if (!literal("\\u")) {
                        return std::nullopt;
                    }
                    auto low = hex4();
                    if (!low || *low < 0xDC00 || *low >= 0xE000) {
                        return std::nullopt;
                    }
                    *cp = 0x10000 + ((*cp - 0xD800) << 10) + (*low - 0xDC00);
                }
                utf8(out, *cp);
                break;
            }
            default: return std::nullopt;
            }
        }
        return std::nullopt;
    }

    std::optional<Rhp::value> number() {
        const std::size_t start = i_;
        if (i_ < s_.size() && s_[i_] == '-') {
            ++i_;
        }
        bool integral = true;
        while (i_ < s_.size()) {
            const char c = s_[i_];
            if (c >= '0' && c <= '9') {
                ++i_;
            } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                integral = false;
                ++i_;
            } else {
                break;
            }
        }
        const std::string_view text = s_.substr(start, i_ - start);
        if (text.empty() || text == "-") {
            return std::nullopt;
        }
        if (integral) {
            std::int64_t n = 0;
            const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), n);
            if (ec == std::errc{} && end == text.data() + text.size()) {
                return Rhp::value{n};
            }
        }
        // Not std::from_chars: Apple's libc++ only has the floating-point overload from macOS 26.
        double d = 0;
        std::istringstream in{std::string{text}};
        in.imbue(std::locale::classic());
        if (!(in >> std::noskipws >> d) || in.peek() != std::char_traits<char>::eof() || !std::isfinite(d)) {
            return std::nullopt;
        }
        return Rhp::value{d};
    }

    std::string_view s_;
    std::size_t i_ = 0;
};

void write_string(std::string& out, std::string_view s) {
    out += '"';
    for (const char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                std::format_to(std::back_inserter(out), "\\u{:04x}", static_cast<unsigned char>(c));
            } else {
                out += c;
            }
        }
    }
    out += '"';
}

void write(std::string& out, const Rhp::value& v) {
    if (v.is_nil()) {
        out += "null";
    } else if (const auto* b = v.get_if<bool>()) {
        out += *b ? "true" : "false";
    } else if (const auto* i = v.get_if<std::int64_t>()) {
        out += std::format("{}", *i);
    } else if (const auto* d = v.get_if<double>()) {
        if (!std::isfinite(*d)) {
            out += "null";
        } else {
            std::string text = std::format("{}", *d);
            if (text.find_first_of(".e") == std::string::npos) {
                text += ".0"; // stays a float when read back
            }
            out += text;
        }
    } else if (const auto* s = v.get_if<std::string>()) {
        write_string(out, *s);
    } else if (const auto* bytes = v.get_if<Rhp::value::bytes>()) {
        out += '[';
        for (std::size_t k = 0; k < bytes->size(); ++k) {
            out += std::format("{}{}", k == 0 ? "" : ",", std::to_integer<unsigned>((*bytes)[k]));
        }
        out += ']';
    } else if (const auto* a = v.get_if<Rhp::value::array>()) {
        out += '[';
        for (std::size_t k = 0; k < a->size(); ++k) {
            if (k != 0) {
                out += ',';
            }
            write(out, (*a)[k]);
        }
        out += ']';
    } else if (const auto* m = v.get_if<Rhp::value::map>()) {
        out += '{';
        bool first = true;
        for (const auto& [key, item] : *m) {
            if (!first) {
                out += ',';
            }
            first = false;
            if (const auto* k = key.get_if<std::string>()) {
                write_string(out, *k);
            } else {
                write_string(out, to_json(key));
            }
            out += ':';
            write(out, item);
        }
        out += '}';
    }
}

} // namespace

std::optional<Rhp::value> parse_json(std::string_view text) {
    return reader{text}.document();
}

std::string to_json(const Rhp::value& v) {
    std::string out;
    write(out, v);
    return out;
}

} // namespace rhp_cli

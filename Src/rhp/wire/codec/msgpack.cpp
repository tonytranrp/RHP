#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <string>
#include <utility>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/wire/codec.hpp>
#include <rhp/wire/codec/msgpack.hpp>

namespace Rhp::wire {

namespace {

// MessagePack integers and lengths are big-endian.
template <std::unsigned_integral T>
void put_be(utils::byte_buffer& out, T v) {
    std::byte bytes[sizeof(T)];
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        bytes[i] = static_cast<std::byte>(v >> (8 * (sizeof(T) - 1 - i)));
    }
    out.append(utils::bytes_view{bytes, sizeof(T)});
}

void put_tag(utils::byte_buffer& out, std::uint8_t tag) {
    const std::byte b{tag};
    out.append(utils::bytes_view{&b, 1});
}

void put_int(utils::byte_buffer& out, std::int64_t i) {
    if (i >= 0) {
        const auto u = static_cast<std::uint64_t>(i);
        if (u <= 0x7f) {
            put_tag(out, static_cast<std::uint8_t>(u));
        } else if (u <= 0xff) {
            put_tag(out, 0xcc);
            put_be(out, static_cast<std::uint8_t>(u));
        } else if (u <= 0xffff) {
            put_tag(out, 0xcd);
            put_be(out, static_cast<std::uint16_t>(u));
        } else if (u <= 0xffff'ffff) {
            put_tag(out, 0xce);
            put_be(out, static_cast<std::uint32_t>(u));
        } else {
            put_tag(out, 0xcf);
            put_be(out, u);
        }
        return;
    }
    if (i >= -32) {
        put_tag(out, static_cast<std::uint8_t>(static_cast<std::int8_t>(i)));
    } else if (i >= std::numeric_limits<std::int8_t>::min()) {
        put_tag(out, 0xd0);
        put_be(out, static_cast<std::uint8_t>(static_cast<std::int8_t>(i)));
    } else if (i >= std::numeric_limits<std::int16_t>::min()) {
        put_tag(out, 0xd1);
        put_be(out, static_cast<std::uint16_t>(static_cast<std::int16_t>(i)));
    } else if (i >= std::numeric_limits<std::int32_t>::min()) {
        put_tag(out, 0xd2);
        put_be(out, static_cast<std::uint32_t>(static_cast<std::int32_t>(i)));
    } else {
        put_tag(out, 0xd3);
        put_be(out, static_cast<std::uint64_t>(i));
    }
}

// fixed-size header (`fix_base` | n when n < fix_limit), else 8/16/32-bit length forms.
result<void> put_length(utils::byte_buffer& out, std::size_t n, std::uint8_t fix_base, std::size_t fix_limit, std::uint8_t tag8, std::uint8_t tag16,
                        std::uint8_t tag32) {
    if (n < fix_limit) {
        put_tag(out, static_cast<std::uint8_t>(fix_base | n));
    } else if (tag8 != 0 && n <= 0xff) {
        put_tag(out, tag8);
        put_be(out, static_cast<std::uint8_t>(n));
    } else if (n <= 0xffff) {
        put_tag(out, tag16);
        put_be(out, static_cast<std::uint16_t>(n));
    } else if (n <= 0xffff'ffffu) {
        put_tag(out, tag32);
        put_be(out, static_cast<std::uint32_t>(n));
    } else {
        return fail(errc::kLimitExceeded, std::format("{} elements or bytes exceed MessagePack's 32-bit length", n), "msgpack");
    }
    return {};
}

result<void> encode_value(const value& v, utils::byte_buffer& out, std::size_t depth) {
    if (depth > decode_limits{}.max_depth) {
        return fail(errc::kLimitExceeded, std::format("value nested deeper than {} levels", decode_limits{}.max_depth), "msgpack");
    }
    switch (v.type()) {
    case value::kind::kNil: put_tag(out, 0xc0); return {};
    case value::kind::kBool: put_tag(out, *v.get_if<bool>() ? std::uint8_t{0xc3} : std::uint8_t{0xc2}); return {};
    case value::kind::kInteger: put_int(out, *v.get_if<std::int64_t>()); return {};
    case value::kind::kNumber:
        put_tag(out, 0xcb);
        put_be(out, std::bit_cast<std::uint64_t>(*v.get_if<double>()));
        return {};
    case value::kind::kString: {
        const std::string& s = *v.get_if<std::string>();
        if (auto ok = put_length(out, s.size(), 0xa0, 32, 0xd9, 0xda, 0xdb); !ok) {
            return ok;
        }
        out.append(std::string_view{s});
        return {};
    }
    case value::kind::kBytes: {
        const value::bytes& b = *v.get_if<value::bytes>();
        if (auto ok = put_length(out, b.size(), 0, 0, 0xc4, 0xc5, 0xc6); !ok) {
            return ok;
        }
        out.append(utils::bytes_view{b});
        return {};
    }
    case value::kind::kArray: {
        const value::array& a = *v.get_if<value::array>();
        if (auto ok = put_length(out, a.size(), 0x90, 16, 0, 0xdc, 0xdd); !ok) {
            return ok;
        }
        for (const value& item : a) {
            if (auto ok = encode_value(item, out, depth + 1); !ok) {
                return ok;
            }
        }
        return {};
    }
    case value::kind::kMap: {
        const value::map& m = *v.get_if<value::map>();
        if (auto ok = put_length(out, m.size(), 0x80, 16, 0, 0xde, 0xdf); !ok) {
            return ok;
        }
        for (const auto& [key, item] : m) {
            if (auto ok = encode_value(key, out, depth + 1); !ok) {
                return ok;
            }
            if (auto ok = encode_value(item, out, depth + 1); !ok) {
                return ok;
            }
        }
        return {};
    }
    }
    return fail(errc::kInvalidArgument, "unknown value kind", "msgpack");
}

class reader {
public:
    reader(utils::bytes_view in, const decode_limits& limits) noexcept : in_(in), limits_(limits) {}

    result<value> read(std::size_t depth) {
        if (depth > limits_.max_depth) {
            return fail(errc::kLimitExceeded, std::format("value nested deeper than {} levels", limits_.max_depth), where());
        }
        if (++elements_ > limits_.max_elements) {
            return fail(errc::kLimitExceeded, std::format("more than {} values", limits_.max_elements), where());
        }
        auto tag = byte();
        if (!tag) {
            return std::unexpected{std::move(tag).error()};
        }
        const std::uint8_t t = *tag;
        if (t <= 0x7f) {
            return value{static_cast<std::int64_t>(t)};
        }
        if (t >= 0xe0) {
            return value{static_cast<std::int64_t>(static_cast<std::int8_t>(t))};
        }
        if ((t & 0xf0) == 0x80) {
            return map(t & 0x0fu, depth);
        }
        if ((t & 0xf0) == 0x90) {
            return array(t & 0x0fu, depth);
        }
        if ((t & 0xe0) == 0xa0) {
            return string(t & 0x1fu);
        }
        switch (t) {
        case 0xc0: return value{};
        case 0xc2: return value{false};
        case 0xc3: return value{true};
        case 0xc4: return sized<std::uint8_t>([this](std::size_t n) { return bytes(n); });
        case 0xc5: return sized<std::uint16_t>([this](std::size_t n) { return bytes(n); });
        case 0xc6: return sized<std::uint32_t>([this](std::size_t n) { return bytes(n); });
        case 0xca: {
            auto bits = be<std::uint32_t>();
            if (!bits) {
                return std::unexpected{std::move(bits).error()};
            }
            return value{static_cast<double>(std::bit_cast<float>(*bits))};
        }
        case 0xcb: {
            auto bits = be<std::uint64_t>();
            if (!bits) {
                return std::unexpected{std::move(bits).error()};
            }
            return value{std::bit_cast<double>(*bits)};
        }
        case 0xcc: return unsigned_int<std::uint8_t>();
        case 0xcd: return unsigned_int<std::uint16_t>();
        case 0xce: return unsigned_int<std::uint32_t>();
        case 0xcf: return unsigned_int<std::uint64_t>();
        case 0xd0: return signed_int<std::uint8_t, std::int8_t>();
        case 0xd1: return signed_int<std::uint16_t, std::int16_t>();
        case 0xd2: return signed_int<std::uint32_t, std::int32_t>();
        case 0xd3: return signed_int<std::uint64_t, std::int64_t>();
        case 0xd9: return sized<std::uint8_t>([this](std::size_t n) { return string(n); });
        case 0xda: return sized<std::uint16_t>([this](std::size_t n) { return string(n); });
        case 0xdb: return sized<std::uint32_t>([this](std::size_t n) { return string(n); });
        case 0xdc: return sized<std::uint16_t>([this, depth](std::size_t n) { return array(n, depth); });
        case 0xdd: return sized<std::uint32_t>([this, depth](std::size_t n) { return array(n, depth); });
        case 0xde: return sized<std::uint16_t>([this, depth](std::size_t n) { return map(n, depth); });
        case 0xdf: return sized<std::uint32_t>([this, depth](std::size_t n) { return map(n, depth); });
        default: break;
        }
        if ((t >= 0xc7 && t <= 0xc9) || (t >= 0xd4 && t <= 0xd8)) {
            return fail(errc::kProtocol, std::format("MessagePack ext type (0x{:02x}) is not supported", t), where());
        }
        return fail(errc::kProtocol, std::format("invalid MessagePack byte 0x{:02x}", t), where());
    }

    [[nodiscard]] bool done() const noexcept { return at_ == in_.size(); }
    [[nodiscard]] std::size_t left() const noexcept { return in_.size() - at_; }
    [[nodiscard]] std::string where() const { return std::format("msgpack at byte {}", at_); }

private:
    result<std::uint8_t> byte() {
        if (left() < 1) {
            return truncated();
        }
        return static_cast<std::uint8_t>(in_[at_++]);
    }

    template <std::unsigned_integral T>
    result<T> be() {
        if (left() < sizeof(T)) {
            return truncated();
        }
        T v = 0;
        for (std::size_t i = 0; i < sizeof(T); ++i) {
            v = static_cast<T>((v << 8) | static_cast<T>(in_[at_ + i]));
        }
        at_ += sizeof(T);
        return v;
    }

    template <std::unsigned_integral T, std::invocable<std::size_t> F>
    result<value> sized(F&& then) {
        auto n = be<T>();
        if (!n) {
            return std::unexpected{std::move(n).error()};
        }
        return then(static_cast<std::size_t>(*n));
    }

    template <std::unsigned_integral T>
    result<value> unsigned_int() {
        auto u = be<T>();
        if (!u) {
            return std::unexpected{std::move(u).error()};
        }
        if constexpr (sizeof(T) == sizeof(std::uint64_t)) {
            if (*u > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
                // Doesn't fit a Lua integer: a number, like Rhp::convert does.
                return value{static_cast<double>(*u)};
            }
        }
        return value{static_cast<std::int64_t>(*u)};
    }

    template <std::unsigned_integral U, std::signed_integral S>
    result<value> signed_int() {
        auto u = be<U>();
        if (!u) {
            return std::unexpected{std::move(u).error()};
        }
        return value{static_cast<std::int64_t>(std::bit_cast<S>(*u))};
    }

    result<value> string(std::size_t n) {
        if (left() < n) {
            return truncated();
        }
        std::string s(reinterpret_cast<const char*>(in_.data() + at_), n);
        at_ += n;
        return value{std::move(s)};
    }

    result<value> bytes(std::size_t n) {
        if (left() < n) {
            return truncated();
        }
        value::bytes b(in_.begin() + static_cast<std::ptrdiff_t>(at_), in_.begin() + static_cast<std::ptrdiff_t>(at_ + n));
        at_ += n;
        return value{std::move(b)};
    }

    result<value> array(std::size_t n, std::size_t depth) {
        // Every element takes at least one byte: a count above what's left is a lie.
        if (n > left()) {
            return truncated();
        }
        value::array a;
        // Reserve only a little up front: counts are claims, and every nesting level would
        // otherwise reserve against the same remaining bytes.
        a.reserve(n < kReserveCap ? n : kReserveCap);
        for (std::size_t i = 0; i < n; ++i) {
            auto item = read(depth + 1);
            if (!item) {
                return item;
            }
            a.push_back(std::move(*item));
        }
        return value{std::move(a)};
    }

    result<value> map(std::size_t n, std::size_t depth) {
        if (n > left() / 2) {
            return truncated();
        }
        value::map m;
        m.reserve(n < kReserveCap ? n : kReserveCap);
        for (std::size_t i = 0; i < n; ++i) {
            auto key = read(depth + 1);
            if (!key) {
                return key;
            }
            auto item = read(depth + 1);
            if (!item) {
                return item;
            }
            m.emplace_back(std::move(*key), std::move(*item));
        }
        return value{std::move(m)};
    }

    [[nodiscard]] std::unexpected<error> truncated() const { return fail(errc::kProtocol, "truncated MessagePack data", where()); }

    static constexpr std::size_t kReserveCap = 256;

    utils::bytes_view in_;
    const decode_limits& limits_;
    std::size_t at_ = 0;
    std::size_t elements_ = 0;
};

} // namespace

result<void> msgpack::encode(const value& v, utils::byte_buffer& out) {
    const std::size_t start = out.size();
    auto ok = encode_value(v, out, 0);
    if (!ok) {
        out.resize(start); // leave `out` as it was
    }
    return ok;
}

result<value> msgpack::decode(utils::bytes_view in, const decode_limits& limits) {
    reader r{in, limits};
    auto v = r.read(0);
    if (!v) {
        return v;
    }
    if (!r.done()) {
        return fail(errc::kProtocol, std::format("{} trailing bytes after the MessagePack value", r.left()), r.where());
    }
    return v;
}

} // namespace Rhp::wire

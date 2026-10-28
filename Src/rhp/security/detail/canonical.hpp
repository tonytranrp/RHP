#pragma once

// Private to security's .cpp files (not installed): canonical MessagePack documents with fixed
// field order, as operator certificates and script claims use them (the release manifest's
// encoding: wire::msgpack over an Rhp::value map, keys in a fixed order).

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/wire/codec/msgpack.hpp>

namespace Rhp::security::detail {

[[nodiscard]] inline result<std::vector<std::byte>> encode_canonical(const value& v) {
    utils::byte_buffer out;
    if (auto ok = wire::msgpack::encode(v, out); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    const auto bytes = out.view();
    return std::vector<std::byte>(bytes.begin(), bytes.end());
}

[[nodiscard]] inline result<value> decode_canonical(std::span<const std::byte> bytes) {
    return wire::msgpack::decode(utils::bytes_view{bytes.data(), bytes.size()});
}

// Sorted, without duplicates: how lists are signed.
[[nodiscard]] inline std::vector<std::string> canonical_set(std::vector<std::string> items) {
    std::ranges::sort(items);
    const auto dup = std::ranges::unique(items);
    items.erase(dup.begin(), dup.end());
    return items;
}

[[nodiscard]] inline value strings_value(const std::vector<std::string>& items) {
    value::array out;
    out.reserve(items.size());
    for (const std::string& s : items) {
        out.emplace_back(s);
    }
    return value{std::move(out)};
}

// A map read field by field at fixed positions; every error is kProtocol at `where`.
class fixed_map {
public:
    [[nodiscard]] static result<fixed_map> of(const value& v, std::size_t fields, std::string_view what, std::string_view where) {
        const auto* m = v.get_if<value::map>();
        if (m == nullptr || m->size() != fields) {
            return std::unexpected{make_error(errc::kProtocol, std::format("{} must be a map of {} fields", what, fields), std::string{where})};
        }
        return fixed_map{*m, where};
    }

    [[nodiscard]] result<const value*> at(std::size_t index, std::string_view key) const {
        const auto* name = (*m_)[index].first.get_if<std::string>();
        if (name == nullptr || *name != key) {
            return std::unexpected{bad(std::format("expected field '{}' at position {}", key, index + 1))};
        }
        return &(*m_)[index].second;
    }

    [[nodiscard]] result<std::string> text(std::size_t index, std::string_view key, std::size_t max) const {
        auto v = at(index, key);
        if (!v) {
            return std::unexpected{std::move(v).error()};
        }
        const auto* s = (*v)->get_if<std::string>();
        if (s == nullptr || s->size() > max) {
            return std::unexpected{bad(std::format("'{}' must be a string of at most {} bytes", key, max))};
        }
        return *s;
    }

    [[nodiscard]] result<std::uint64_t> count(std::size_t index, std::string_view key) const {
        auto v = at(index, key);
        if (!v) {
            return std::unexpected{std::move(v).error()};
        }
        const auto* i = (*v)->get_if<std::int64_t>();
        if (i == nullptr || *i < 0) {
            return std::unexpected{bad(std::format("'{}' must be a non-negative integer", key))};
        }
        return static_cast<std::uint64_t>(*i);
    }

    // `size` 0: any length up to `max`.
    [[nodiscard]] result<const value::bytes*> bytes(std::size_t index, std::string_view key, std::size_t size, std::size_t max = 0) const {
        auto v = at(index, key);
        if (!v) {
            return std::unexpected{std::move(v).error()};
        }
        const auto* b = (*v)->get_if<value::bytes>();
        if (b == nullptr || (size != 0 && b->size() != size) || (max != 0 && b->size() > max)) {
            return std::unexpected{bad(size != 0 ? std::format("'{}' must be {} bytes", key, size) : std::format("'{}' must be at most {} bytes", key, max))};
        }
        return b;
    }

    [[nodiscard]] result<std::vector<std::string>> texts(std::size_t index, std::string_view key, std::size_t max_entries, std::size_t max_text) const {
        auto v = at(index, key);
        if (!v) {
            return std::unexpected{std::move(v).error()};
        }
        const auto* a = (*v)->get_if<value::array>();
        if (a == nullptr || a->size() > max_entries) {
            return std::unexpected{bad(std::format("'{}' must be an array of at most {} strings", key, max_entries))};
        }
        std::vector<std::string> out;
        out.reserve(a->size());
        for (const value& item : *a) {
            const auto* s = item.get_if<std::string>();
            if (s == nullptr || s->size() > max_text) {
                return std::unexpected{bad(std::format("'{}' must hold strings of at most {} bytes", key, max_text))};
            }
            out.push_back(*s);
        }
        return out;
    }

    [[nodiscard]] error bad(std::string message) const { return make_error(errc::kProtocol, std::move(message), std::string{where_}); }

private:
    fixed_map(const value::map& m, std::string_view where) : m_(&m), where_(where) {}

    const value::map* m_;
    std::string_view where_;
};

} // namespace Rhp::security::detail

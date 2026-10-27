#pragma once

// Private to Src/rhp/release: strict MessagePack reading shared by the manifest, envelope,
// revocation and state codecs, the store's key prefixes and what a signature covers. Everything
// here is implemented in manifest.cpp, which every configuration builds.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/security/hash.hpp>

namespace Rhp::release::detail {

// Store keys: "releases/<hex id>" holds an envelope, "bytecode/<hex id>" its compiled-chunk cache entry.
inline constexpr std::string_view kReleasesPrefix = "releases/";
inline constexpr std::string_view kBytecodePrefix = "bytecode/";

// domain || body: what a release or revocation list signature covers.
[[nodiscard]] std::vector<std::byte> signed_message(std::string_view domain, std::span<const std::byte> body);

[[nodiscard]] error bad_body(std::string message);

// Sorted, without duplicates: lists that are sets encode one way only.
[[nodiscard]] std::vector<std::string> canonical_set(std::vector<std::string> items);
[[nodiscard]] value string_array(const std::vector<std::string>& items);
[[nodiscard]] value digest_value(const security::digest256& d);

[[nodiscard]] result<std::vector<std::byte>> encode(const value& v);
[[nodiscard]] result<value> decode(std::span<const std::byte> bytes);

// Readers: kProtocol naming the field when the shape is wrong.
[[nodiscard]] result<const value::map*> fields(const value& v, std::string_view what);
// The field at `index`, which must be named `key` (canonical order).
[[nodiscard]] result<const value*> field(const value::map& m, std::size_t index, std::string_view key);
[[nodiscard]] result<std::string> text(const value& v, std::string_view key);
[[nodiscard]] result<std::uint64_t> count(const value& v, std::string_view key);
[[nodiscard]] result<std::vector<std::string>> texts(const value& v, std::string_view key);
[[nodiscard]] result<security::digest256> digest(const value& v, std::string_view key);
[[nodiscard]] result<void> exact_size(const value::map& m, std::size_t n, std::string_view what);

// Fits the int64 MessagePack integers RHP writes.
[[nodiscard]] bool fits(std::uint64_t n);
// Dotted lowercase words of a-z 0-9 _ - ("game.balance"), at most kMaxChannelName bytes.
[[nodiscard]] bool valid_channel(std::string_view name);

} // namespace Rhp::release::detail

// The device allow-list: text and files only (built with RHP_ENABLE=OFF too). The handshake is
// device_handshake.cpp.
#include <algorithm>
#include <format>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/scopes.hpp>
#include <rhp/security/detail/text.hpp>
#include <rhp/security/device_keys.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/key_handle.hpp>

namespace Rhp::security {

namespace {

constexpr const char* kWhere = "security.device_allow_list";
constexpr const char* kFormat = "`name role alg base64-public-key [scopes] [env=dev|prod]`";

} // namespace

result<void> device_allow_list::add(device_entry entry) {
    if (entry.name.empty()) {
        return fail(errc::kInvalidArgument, "a device needs a name", kWhere);
    }
    const std::size_t size = key_handle::public_key_size(entry.alg);
    if (entry.public_key.size() != size || (entry.alg == key_algorithm::kP256 && entry.public_key.front() != std::byte{0x04})) {
        return fail(errc::kInvalidArgument, std::format("device '{}': a {} public key is {} bytes{}", entry.name, to_string(entry.alg), size, entry.alg == key_algorithm::kP256 ? ", uncompressed (0x04 first)" : ""),
                    kWhere);
    }
    if (find(entry.name) != nullptr) {
        return fail(errc::kAlreadyLoaded, std::format("device '{}' is already on the allow-list", entry.name), kWhere);
    }
    if (const device_entry* same = find(entry.alg, entry.public_key); same != nullptr) {
        return fail(errc::kAlreadyLoaded, std::format("device '{}' has the key of '{}'", entry.name, same->name), kWhere);
    }
    entries_.push_back(std::move(entry));
    return {};
}

result<device_allow_list> device_allow_list::parse(std::string_view text) {
    device_allow_list out;
    for (const detail::text_line& line : detail::content_lines(text)) {
        const auto f = detail::fields(line.text);
        if (f.size() < 4) {
            return fail(errc::kInvalidArgument, std::format("line {}: expected {}", line.number, kFormat), kWhere);
        }
        const auto granted = parse_role(f[1]);
        if (!granted) {
            return fail(errc::kInvalidArgument, std::format("line {}: unknown role '{}' (observe, patch or admin)", line.number, f[1]), kWhere);
        }
        const auto alg = parse_key_algorithm(f[2]);
        if (!alg) {
            return fail(errc::kInvalidArgument, std::format("line {}: unknown algorithm '{}' (ed25519 or p256)", line.number, f[2]), kWhere);
        }
        auto pub = base64_decode(f[3]);
        if (!pub) {
            return fail(errc::kInvalidArgument, std::format("line {}: {}", line.number, pub.error().message), kWhere);
        }
        // After the key: at most one scopes field and at most one env= tag, in either order (as the keyring).
        device_entry entry{std::string{f[0]}, *granted, *alg, std::move(*pub), scope_set{}, std::nullopt};
        bool have_scopes = false;
        for (const std::string_view extra : std::span{f}.subspan(4)) {
            auto tag = parse_env_field(extra);
            if (!tag) {
                return fail(errc::kInvalidArgument, std::format("line {}: {}", line.number, tag.error().message), kWhere);
            }
            if (*tag && !entry.env) {
                entry.env = **tag;
                continue;
            }
            if (*tag || have_scopes) {
                return fail(errc::kInvalidArgument, std::format("line {}: unexpected '{}' (expected {})", line.number, extra, kFormat), kWhere);
            }
            auto scopes = scope_set::parse(extra);
            if (!scopes) {
                return fail(errc::kInvalidArgument, std::format("line {}: {}", line.number, scopes.error().message), kWhere);
            }
            entry.scopes = std::move(*scopes);
            have_scopes = true;
        }
        if (auto added = out.add(std::move(entry)); !added) {
            return fail(added.error().code, std::format("line {}: {}", line.number, added.error().message), kWhere);
        }
    }
    return out;
}

result<device_allow_list> device_allow_list::from_file(const std::string& path) {
    const auto text = detail::read_file(path);
    if (!text) {
        return fail(errc::kNotFound, std::format("can't read device allow-list {}", path), kWhere);
    }
    auto list = parse(*text);
    if (auto warning = list ? detail::exposure_warning(path) : std::nullopt) {
        list->warnings_.push_back(std::move(*warning));
    }
    return list;
}

std::string device_allow_list::to_text() const {
    std::string out;
    for (const device_entry& e : entries_) {
        out += std::format("{} {} {} {}", e.name, e.granted, to_string(e.alg), base64_encode(e.public_key));
        if (!e.scopes.unrestricted()) {
            out += std::format(" {}", e.scopes.to_string());
        }
        if (e.env) {
            out += std::format(" env={}", to_string(*e.env));
        }
        out += '\n';
    }
    return out;
}

const device_entry* device_allow_list::find(std::string_view name) const noexcept {
    const auto it = std::ranges::find(entries_, name, &device_entry::name);
    return it != entries_.end() ? &*it : nullptr;
}

const device_entry* device_allow_list::find(key_algorithm alg, std::span<const std::byte> public_key) const noexcept {
    const auto it = std::ranges::find_if(entries_, [&](const device_entry& e) { return e.alg == alg && std::ranges::equal(e.public_key, public_key); });
    return it != entries_.end() ? &*it : nullptr;
}

std::optional<key_env> device_allow_list::env_of(std::string_view name) const noexcept {
    const device_entry* e = find(name);
    return e != nullptr ? e->env : std::nullopt;
}

device_allow_list device_allow_list::without(key_env env) const {
    device_allow_list out;
    std::ranges::copy_if(entries_, std::back_inserter(out.entries_), [env](const device_entry& e) { return e.env != env; });
    out.warnings_ = warnings_;
    return out;
}

} // namespace Rhp::security

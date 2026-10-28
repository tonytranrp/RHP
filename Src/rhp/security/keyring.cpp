#include <format>
#include <initializer_list>
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
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>

namespace Rhp::security {

keyring::keyring(std::initializer_list<keyring_entry> entries) {
    for (const keyring_entry& e : entries) {
        if (auto added = add(e); !added) {
            throw Rhp::exception{std::move(added).error()};
        }
    }
}

result<void> keyring::add(keyring_entry entry) {
    if (entry.name.empty()) {
        return fail(errc::kInvalidArgument, "a key needs a name", "security.keyring");
    }
    if (entry.secret.empty()) {
        return fail(errc::kInvalidArgument, std::format("key '{}' has no secret", entry.name), "security.keyring");
    }
    if (find(entry.name) != nullptr) {
        return fail(errc::kAlreadyLoaded, std::format("key '{}' is already in the keyring", entry.name), "security.keyring");
    }
    entries_.push_back(std::move(entry));
    return {};
}

result<keyring> keyring::parse(std::string_view text) {
    keyring out;
    for (const detail::text_line& line : detail::content_lines(text)) {
        const auto f = detail::fields(line.text);
        if (f.size() < 3) {
            return fail(errc::kInvalidArgument, std::format("line {}: expected `name role base64-key [scopes] [env=dev|prod]`", line.number), "security.keyring");
        }
        const auto granted = parse_role(f[1]);
        if (!granted) {
            return fail(errc::kInvalidArgument, std::format("line {}: unknown role '{}' (observe, patch or admin)", line.number, f[1]), "security.keyring");
        }
        auto secret = key::from_base64(f[2]);
        if (!secret) {
            return fail(errc::kInvalidArgument, std::format("line {}: {}", line.number, secret.error().message), "security.keyring");
        }
        // After the key: at most one scopes field and at most one env= tag, in either order.
        std::optional<key_env> env;
        std::optional<scope_set> scopes;
        for (const std::string_view extra : std::span{f}.subspan(3)) {
            auto tag = parse_env_field(extra);
            if (!tag) {
                return fail(errc::kInvalidArgument, std::format("line {}: {}", line.number, tag.error().message), "security.keyring");
            }
            if (*tag && !env) {
                env = **tag;
                continue;
            }
            if (*tag || scopes) {
                return fail(errc::kInvalidArgument, std::format("line {}: unexpected '{}'", line.number, extra), "security.keyring");
            }
            auto parsed = scope_set::parse(extra);
            if (!parsed) {
                return fail(errc::kInvalidArgument, std::format("line {}: {}", line.number, parsed.error().message), "security.keyring");
            }
            scopes = std::move(*parsed);
        }
        if (auto added = out.add({std::string{f[0]}, std::move(*secret), *granted, scopes ? std::move(*scopes) : scope_set{}}); !added) {
            return fail(added.error().code, std::format("line {}: {}", line.number, added.error().message), "security.keyring");
        }
        if (env) {
            (void)out.set_env(f[0], *env);
        }
    }
    return out;
}

result<keyring> keyring::from_file(const std::string& path) {
    auto text = detail::read_file(path);
    if (!text) {
        return fail(errc::kNotFound, std::format("can't read keyring file {}", path), "security.keyring");
    }
    auto ring = parse(*text);
    secure_wipe(text->data(), text->size());
    if (auto warning = ring ? detail::exposure_warning(path) : std::nullopt) {
        ring->warnings_.push_back(std::move(*warning));
    }
    return ring;
}

const keyring_entry* keyring::find(std::string_view name) const noexcept {
    for (const keyring_entry& e : entries_) {
        if (e.name == name) {
            return &e;
        }
    }
    return nullptr;
}

std::optional<key_env> keyring::env_of(std::string_view name) const noexcept {
    for (const auto& [n, env] : envs_) {
        if (n == name) {
            return env;
        }
    }
    return std::nullopt;
}

result<void> keyring::set_env(std::string_view name, key_env env) {
    if (find(name) == nullptr) {
        return fail(errc::kNotFound, std::format("key '{}' is not in the keyring", name), "security.keyring");
    }
    for (auto& [n, e] : envs_) {
        if (n == name) {
            e = env;
            return {};
        }
    }
    envs_.emplace_back(std::string{name}, env);
    return {};
}

} // namespace Rhp::security

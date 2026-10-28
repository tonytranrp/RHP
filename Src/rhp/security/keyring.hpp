#pragma once

#include <cstddef>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/scopes.hpp>
#include <rhp/security/key.hpp>

namespace Rhp::security {

// One key the host accepts: its name is the identity (one lua_State per identity), its role what
// that identity may do, its scopes what it may reach (decision AL13; default everything).
struct keyring_entry {
    std::string name;
    key secret;
    role granted = role::kObserve;
    scope_set scopes{};
};

// The host's keys. Names are unique; add() fails with kAlreadyLoaded on a duplicate.
class keyring {
public:
    keyring() = default;
    // Throws Rhp::exception on an invalid entry (a duplicate name, an empty key); use add() to get
    // the error instead.
    keyring(std::initializer_list<keyring_entry> entries);

    result<void> add(keyring_entry entry);

    // Text with one `name role base64-key [scopes] [env=dev|prod]` per line (role: observe, patch or
    // admin; scopes: comma-separated scope patterns, Rhp::scope_set, everything when left out; '#'
    // starts a comment), e.g. what `rhp-cli keygen` prints for the host.
    [[nodiscard]] static result<keyring> parse(std::string_view text);
    [[nodiscard]] static result<keyring> from_file(const std::string& path);
    [[nodiscard]] const keyring_entry* find(std::string_view name) const noexcept;
    // The `env=` tag of a key (decision AL11); nullopt for an untagged or unknown key.
    [[nodiscard]] std::optional<key_env> env_of(std::string_view name) const noexcept;
    // Tags a key that is in the ring (kNotFound otherwise).
    result<void> set_env(std::string_view name, key_env env);
    // A copy without the keys tagged `env` (Rhp::host leaves out dev keys at production hardening).
    [[nodiscard]] keyring without(key_env env) const;
    [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
    // What from_file noticed that isn't fatal: a file other users can read. Callers show them (the
    // headless server example prints "warning: ..."), as identity_file::warnings.
    [[nodiscard]] const std::vector<std::string>& warnings() const noexcept { return warnings_; }

private:
    std::vector<keyring_entry> entries_;
    std::vector<std::pair<std::string, key_env>> envs_;
    std::vector<std::string> warnings_;
};

} // namespace Rhp::security

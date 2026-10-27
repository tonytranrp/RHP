#pragma once

#include <cstddef>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/security/key.hpp>

namespace Rhp::security {

// One key the host accepts: its name is the identity (one lua_State per identity), its role what
// that identity may do.
struct keyring_entry {
    std::string name;
    key secret;
    role granted = role::kObserve;
};

// The host's keys. Names are unique; add() fails with kAlreadyLoaded on a duplicate.
class keyring {
public:
    keyring() = default;
    // Throws Rhp::exception on an invalid entry (a duplicate name, an empty key); use add() to get
    // the error instead.
    keyring(std::initializer_list<keyring_entry> entries);

    result<void> add(keyring_entry entry);

    // Text with one `name role base64-key` per line (role: observe, patch or admin; '#' starts a
    // comment), e.g. what `rhp-cli keygen` prints for the host.
    [[nodiscard]] static result<keyring> parse(std::string_view text);
    [[nodiscard]] static result<keyring> from_file(const std::string& path);
    [[nodiscard]] const keyring_entry* find(std::string_view name) const noexcept;
    [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
    // What from_file noticed that isn't fatal: a file other users can read. Callers show them (the
    // headless server example prints "warning: ..."), as identity_file::warnings.
    [[nodiscard]] const std::vector<std::string>& warnings() const noexcept { return warnings_; }

private:
    std::vector<keyring_entry> entries_;
    std::vector<std::string> warnings_;
};

} // namespace Rhp::security

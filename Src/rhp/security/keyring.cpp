#include <format>
#include <initializer_list>
#include <string_view>
#include <utility>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
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

const keyring_entry* keyring::find(std::string_view name) const noexcept {
    for (const keyring_entry& e : entries_) {
        if (e.name == name) {
            return &e;
        }
    }
    return nullptr;
}

} // namespace Rhp::security

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/security/ed25519.hpp>
#include <rhp/security/identity_revocations.hpp>

namespace Rhp::security {

namespace {

bool has_key(const std::vector<public_key_ref>& keys, std::span<const std::byte> pub, std::string_view alg) {
    return std::ranges::any_of(keys, [&](const public_key_ref& k) { return k.alg == alg && std::ranges::equal(k.pub, pub); });
}

} // namespace

public_key_ref key_ref(const ed25519_public_key& k) {
    return public_key_ref{"ed25519", std::vector<std::byte>(k.bytes().begin(), k.bytes().end())};
}

bool revoked_identities::is_revoked_serial(std::string_view serial) const {
    const std::shared_lock lock{mutex_};
    return std::ranges::find(all_.cert_serials, serial) != all_.cert_serials.end();
}

bool revoked_identities::is_revoked_signer(std::span<const std::byte> pub, std::string_view alg) const {
    const std::shared_lock lock{mutex_};
    return has_key(all_.signer_keys, pub, alg);
}

bool revoked_identities::is_revoked_device(std::span<const std::byte> pub, std::string_view alg) const {
    const std::shared_lock lock{mutex_};
    return has_key(all_.device_keys, pub, alg);
}

std::uint64_t revoked_identities::seq() const {
    const std::shared_lock lock{mutex_};
    return all_.seq;
}

identity_revocation_list revoked_identities::snapshot() const {
    const std::shared_lock lock{mutex_};
    return all_;
}

void revoked_identities::merge_into(identity_revocation_list& into, const identity_revocation_list& list) {
    into.seq = std::max(into.seq, list.seq);
    for (const std::string& s : list.cert_serials) {
        if (std::ranges::find(into.cert_serials, s) == into.cert_serials.end()) {
            into.cert_serials.push_back(s);
        }
    }
    for (const public_key_ref& k : list.signer_keys) {
        if (!has_key(into.signer_keys, k.pub, k.alg)) {
            into.signer_keys.push_back(k);
        }
    }
    for (const public_key_ref& k : list.device_keys) {
        if (!has_key(into.device_keys, k.pub, k.alg)) {
            into.device_keys.push_back(k);
        }
    }
}

void revoked_identities::merge(const identity_revocation_list& list) {
    const std::unique_lock lock{mutex_};
    merge_into(all_, list);
}

void revoked_identities::replace(std::span<const identity_revocation_list> lists) {
    identity_revocation_list next;
    for (const identity_revocation_list& l : lists) {
        merge_into(next, l);
    }
    const std::unique_lock lock{mutex_};
    all_ = std::move(next);
}

} // namespace Rhp::security

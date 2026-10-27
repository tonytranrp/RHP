#pragma once

// Private to Src/rhp/release: what a manager keeps of its channels and of the revocation lists it
// applied (the store's "state"), and that document's codec.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/release/release.hpp>
#include <rhp/security/ed25519.hpp>

namespace Rhp::release::detail {

inline constexpr std::size_t kQuarantineKept = 16; // newest quarantined ids a channel remembers

// Everything every revocation list applied so far withdrew: lists only ever add to it, so a newer
// list can't forgive what an older one revoked (not even one signed by a key that older list revoked).
struct revoked_set {
    std::uint64_t seq = 0; // the newest list applied
    std::vector<release_id> releases;
    std::vector<security::ed25519_public_key> keys;
    std::vector<seq_floor> floors; // per channel: releases at or below it are revoked

    void merge(const revocation_list& l) { merge(l.seq, l.releases, l.keys, l.floors); }
    void merge(const revoked_set& o) { merge(o.seq, o.releases, o.keys, o.floors); }

    [[nodiscard]] bool revokes(const release_id& id) const;
    [[nodiscard]] std::uint64_t floor_of(std::string_view channel) const;

private:
    void merge(std::uint64_t list_seq, std::span<const release_id> ids, std::span<const security::ed25519_public_key> revoked_keys,
               std::span<const seq_floor> revoked_floors);
};

// What persists of one channel.
struct channel_state {
    std::string name;
    std::uint64_t floor = 0;
    std::optional<release_id> active;
    std::optional<release_id> previous;
    std::optional<release_id> candidate;
    confirm_mode confirm = confirm_mode::kNow;
    std::uint32_t attempts = 0;
    bool held = false;
    std::vector<release_id> quarantined;
};

struct decoded_state {
    std::vector<channel_state> channels;
    revoked_set revoked;
};

// The state document: BLAKE2b-256(body) || body. The checksum notices a torn or corrupted file, not
// a deliberate edit: whoever can write the store can lower floors (signatures are still checked on
// every restore, so only signed releases ever run).
[[nodiscard]] result<std::vector<std::byte>> encode_state(const std::vector<channel_state>& channels, const revoked_set& revoked);
[[nodiscard]] result<decoded_state> decode_state(std::span<const std::byte> bytes);

} // namespace Rhp::release::detail

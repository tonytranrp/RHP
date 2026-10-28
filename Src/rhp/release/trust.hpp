#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/release/release.hpp>
#include <rhp/security/ed25519.hpp>

namespace Rhp::release {

// The keys a host trusts to sign releases and revocation lists. Each key is limited to channel
// patterns ("game.balance", "game.*", "*"); a revocation list needs keys trusted for "*".
// `threshold` distinct keys must sign (default 1).
//
// Text form (rhp_release_signers.pub), one key per line, '#' starts a comment:
//   name base64-public-key [pattern,pattern,...] [env=dev|prod]     (no patterns: "*")
//
// These keys are separate from the script signers (security::trusted_signers): a key that may
// sign a one-off exec need not be able to ship a release, and the other way round.
class trust {
public:
    struct entry {
        std::string name;
        security::ed25519_public_key key;
        std::vector<std::string> channels;
    };

    trust() = default;

    result<void> add(std::string name, security::ed25519_public_key key, std::vector<std::string> channels = {"*"});
    [[nodiscard]] static result<trust> parse(std::string_view text);
    [[nodiscard]] static result<trust> from_file(const std::string& path);

    result<void> set_threshold(std::size_t n);
    [[nodiscard]] std::size_t threshold() const noexcept { return threshold_; }
    [[nodiscard]] std::span<const entry> entries() const noexcept { return entries_; }
    [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }

    // The names of the trusted keys whose signatures over `domain || body` hold, for `channel`
    // ("*": a revocation list), skipping `revoked` keys. kBadSignature unless at least `threshold`
    // distinct keys signed.
    [[nodiscard]] result<std::vector<std::string>> verify(std::string_view domain, std::span<const std::byte> body, std::span<const signature> sigs,
                                                          std::string_view channel, std::span<const security::ed25519_public_key> revoked = {}) const;

    [[nodiscard]] result<std::vector<std::string>> verify(const release& r, std::span<const security::ed25519_public_key> revoked = {}) const;
    [[nodiscard]] result<std::vector<std::string>> verify(const signed_revocations& r, std::span<const security::ed25519_public_key> revoked = {}) const;

private:
    std::vector<entry> entries_;
    std::size_t threshold_ = 1;
};

// True if `channel` matches `pattern`: "*", the exact name, or "prefix.*" (any channel below prefix).
[[nodiscard]] bool channel_matches(std::string_view pattern, std::string_view channel) noexcept;

} // namespace Rhp::release

#include <algorithm>
#include <cstddef>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/release/detail/codec.hpp>
#include <rhp/release/release.hpp>
#include <rhp/release/trust.hpp>
#include <rhp/security/detail/text.hpp>
#include <rhp/security/ed25519.hpp>

namespace Rhp::release {

namespace {

error bad_trust(std::string message) {
    return make_error(errc::kInvalidArgument, std::move(message), "release.trust");
}

error bad_signature(std::string message) {
    return make_error(errc::kBadSignature, std::move(message), "release.signature");
}

bool valid_pattern(std::string_view pattern) {
    if (pattern == "*") {
        return true;
    }
    if (pattern.ends_with(".*")) {
        pattern.remove_suffix(2);
    }
    return detail::valid_channel(pattern);
}

std::vector<std::string> split_patterns(std::string_view text) {
    std::vector<std::string> out;
    while (!text.empty()) {
        const auto comma = text.find(',');
        out.emplace_back(security::detail::trim(text.substr(0, comma)));
        text = comma == std::string_view::npos ? std::string_view{} : text.substr(comma + 1);
    }
    return out;
}

} // namespace

bool channel_matches(std::string_view pattern, std::string_view channel) noexcept {
    if (pattern == "*" || pattern == channel) {
        return true;
    }
    if (pattern.ends_with(".*")) {
        pattern.remove_suffix(1); // keep the dot: "game." matches "game.balance", not "gameplay"
        return channel.starts_with(pattern) && channel.size() > pattern.size();
    }
    return false;
}

result<void> trust::add(std::string name, security::ed25519_public_key key, std::vector<std::string> channels) {
    if (name.empty()) {
        return std::unexpected{bad_trust("a release signer needs a name")};
    }
    if (std::ranges::any_of(entries_, [&](const entry& e) { return e.name == name; })) {
        return fail(errc::kAlreadyLoaded, std::format("release signer '{}' is already trusted", name), "release.trust");
    }
    if (channels.empty()) {
        channels.emplace_back("*");
    }
    for (const std::string& p : channels) {
        if (!valid_pattern(p)) {
            return std::unexpected{bad_trust(std::format("'{}' is not a channel pattern (\"*\", \"game.balance\" or \"game.*\")", p))};
        }
    }
    entries_.push_back(entry{std::move(name), key, std::move(channels)});
    return {};
}

result<trust> trust::parse(std::string_view text) {
    trust out;
    for (const security::detail::text_line& line : security::detail::content_lines(text)) {
        const auto f = security::detail::fields(line.text);
        if (f.size() != 2 && f.size() != 3) {
            return std::unexpected{bad_trust(std::format("line {}: expected `name base64-public-key [pattern,pattern,...]`", line.number))};
        }
        auto key = security::ed25519_public_key::from_base64(f[1]);
        if (!key) {
            return std::unexpected{bad_trust(std::format("line {}: {}", line.number, key.error().message))};
        }
        auto added = out.add(std::string{f[0]}, *key, f.size() == 3 ? split_patterns(f[2]) : std::vector<std::string>{});
        if (!added) {
            return fail(added.error().code, std::format("line {}: {}", line.number, added.error().message), "release.trust");
        }
    }
    return out;
}

result<trust> trust::from_file(const std::string& path) {
    const auto text = security::detail::read_file(path);
    if (!text) {
        return fail(errc::kNotFound, std::format("can't read release signers file {}", path), "release.trust");
    }
    return parse(*text);
}

result<void> trust::set_threshold(std::size_t n) {
    if (n == 0 || n > kMaxSignatures) {
        return std::unexpected{bad_trust(std::format("a threshold is 1 to {}", kMaxSignatures))};
    }
    threshold_ = n;
    return {};
}

result<std::vector<std::string>> trust::verify(std::string_view domain, std::span<const std::byte> body, std::span<const signature> sigs,
                                               std::string_view channel, std::span<const security::ed25519_public_key> revoked) const {
    const std::vector<std::byte> message = detail::signed_message(domain, body);
    std::vector<std::string> signers;
    std::vector<const security::ed25519_public_key*> used;
    std::string why; // every reason a signature didn't count, "; "-separated
    const auto reject = [&why](std::string reason) {
        why += (why.empty() ? "" : "; ") + std::move(reason);
    };
    for (const signature& s : sigs) {
        const auto it = std::ranges::find(entries_, s.signer, &entry::name);
        if (it == entries_.end()) {
            reject(std::format("'{}' is not a trusted release signer", s.signer));
            continue;
        }
        if (std::ranges::find(revoked, it->key) != revoked.end()) {
            reject(std::format("the key of '{}' is revoked", s.signer));
            continue;
        }
        const bool allowed = channel == "*" ? std::ranges::find(it->channels, "*") != it->channels.end()
                                            : std::ranges::any_of(it->channels, [&](const std::string& p) { return channel_matches(p, channel); });
        if (!allowed) {
            reject(std::format("'{}' may not sign for channel '{}'", s.signer, channel));
            continue;
        }
        if (!security::ed25519_check(it->key, s.bytes, message)) {
            reject(std::format("the signature by '{}' doesn't match", s.signer));
            continue;
        }
        // Distinct keys: two names for one key count once.
        if (std::ranges::any_of(used, [&](const security::ed25519_public_key* k) { return *k == it->key; })) {
            continue;
        }
        used.push_back(&it->key);
        signers.push_back(s.signer);
    }
    if (signers.size() < threshold_) {
        if (sigs.empty()) {
            why = "it is not signed";
        }
        return std::unexpected{bad_signature(std::format("{} of {} required signatures hold{}{}", signers.size(), threshold_, why.empty() ? "" : ": ", why))};
    }
    return signers;
}

result<std::vector<std::string>> trust::verify(const release& r, std::span<const security::ed25519_public_key> revoked) const {
    return verify(kReleaseSignatureDomain, r.body_bytes, r.signatures, r.body.channel, revoked);
}

result<std::vector<std::string>> trust::verify(const signed_revocations& r, std::span<const security::ed25519_public_key> revoked) const {
    return verify(kRevocationSignatureDomain, r.body_bytes, r.signatures, "*", revoked);
}

} // namespace Rhp::release

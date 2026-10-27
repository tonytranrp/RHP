// The replay cache and the signature header need no cryptography, so they build with RHP_ENABLE=OFF too.
#include <rhp/security/http_auth.hpp>
#include <rhp/utils/base64.hpp>
#include <rhp/wire/codec/msgpack.hpp>

namespace Rhp::security {

result<std::string> http_signature_header(const value& signature) {
    utils::byte_buffer bytes;
    if (auto ok = wire::msgpack::encode(signature, bytes); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    return utils::base64_encode(bytes.view());
}

result<value> read_http_signature(std::string_view header) {
    if (header.empty()) {
        return value{};
    }
    if (const auto bytes = utils::base64_decode(header)) {
        if (auto signature = wire::msgpack::decode(*bytes)) {
            return signature;
        }
    }
    return fail(errc::kBadSignature, "X-RHP-Signature is not a MessagePack signature value", "security.http");
}

result<void> http_replay_guard::admit(const http_grant& grant, std::chrono::system_clock::time_point now) {
    prune(now);
    entry key{grant.identity, grant.nonce};
    if (seen_.contains(key)) {
        return fail(errc::kAuth, "HTTP proof was already used", "security.http");
    }
    auto& count = counts_[grant.identity];
    if (count >= per_identity_) {
        return fail(errc::kLimitExceeded, "too many HTTP requests from this key in the replay window", "security.http");
    }
    ++count;
    seen_.insert(key);
    by_expiry_.emplace(grant.expires, std::move(key));
    return {};
}

std::optional<std::chrono::system_clock::time_point> http_replay_guard::next_expiry() const {
    return by_expiry_.empty() ? std::nullopt : std::optional{by_expiry_.begin()->first};
}

void http_replay_guard::prune(std::chrono::system_clock::time_point now) {
    while (!by_expiry_.empty() && by_expiry_.begin()->first <= now) {
        const auto& expired = by_expiry_.begin()->second;
        seen_.erase(expired);
        if (const auto count = counts_.find(expired.first); count != counts_.end() && --count->second == 0) {
            counts_.erase(count);
        }
        by_expiry_.erase(by_expiry_.begin());
    }
}

} // namespace Rhp::security

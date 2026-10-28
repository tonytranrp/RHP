// The device-key handshake (security::device_keys, decision AL10). The allow-list is device_keys.cpp.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/security/authenticator.hpp>
#include <rhp/security/detail/frame_keys.hpp>
#include <rhp/security/device_keys.hpp>
#include <rhp/security/identity_revocations.hpp>
#include <rhp/security/key_handle.hpp>
#include <rhp/security/known_hosts.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace Rhp::security {

namespace {

constexpr std::size_t kNonceSize = 32;
constexpr std::string_view kScheme = "device";
constexpr std::string_view kHostDomain{"rhp/device/host\0", 16};
constexpr std::string_view kClientDomain{"rhp/device/client\0", 18};
constexpr const char* kWhere = "device handshake";

using nonce = std::array<std::byte, kNonceSize>;

// One side's key as it travels: its algorithm and public key.
struct offered_key {
    key_algorithm alg = key_algorithm::kEd25519;
    std::vector<std::byte> pub;
};

[[nodiscard]] std::unexpected<error> auth_failed() {
    return fail(errc::kAuth, "authentication failed", kWhere);
}

[[nodiscard]] std::unexpected<error> needs_tls() {
    return fail(errc::kAuth, "device keys need TLS", kWhere);
}

[[nodiscard]] const value::bytes* bytes_field(const value& map, std::string_view field) {
    const value* v = map.find(field);
    return v != nullptr ? v->get_if<value::bytes>() : nullptr;
}

[[nodiscard]] std::optional<nonce> read_nonce(const value& map) {
    const auto* b = bytes_field(map, "nonce");
    if (b == nullptr || b->size() != kNonceSize) {
        return std::nullopt;
    }
    nonce n{};
    std::ranges::copy(*b, n.begin());
    return n;
}

// {alg, pub} with a known algorithm and a public key of its size.
[[nodiscard]] std::optional<offered_key> read_key(const value& map) {
    const value* name = map.find("alg");
    const auto* text = name != nullptr ? name->get_if<std::string>() : nullptr;
    const auto alg = text != nullptr ? parse_key_algorithm(*text) : std::nullopt;
    const auto* pub = bytes_field(map, "pub");
    if (!alg || pub == nullptr || pub->size() != key_handle::public_key_size(*alg)) {
        return std::nullopt;
    }
    return offered_key{*alg, *pub};
}

[[nodiscard]] value bytes_value(std::span<const std::byte> b) {
    return value{value::bytes(b.begin(), b.end())};
}

void append_field(utils::byte_buffer& t, std::span<const std::byte> field) {
    t.append_le(static_cast<std::uint32_t>(field.size()));
    t.append(field);
}

// T: every field length-prefixed, so no two different handshakes share a transcript.
[[nodiscard]] utils::byte_buffer transcript(const offered_key& client, const nonce& nc, const nonce& nh, const offered_key& host, std::span<const std::byte> binding) {
    utils::byte_buffer t;
    append_field(t, std::as_bytes(std::span{to_string(client.alg)}));
    append_field(t, client.pub);
    append_field(t, nc);
    append_field(t, nh);
    append_field(t, std::as_bytes(std::span{to_string(host.alg)}));
    append_field(t, host.pub);
    append_field(t, binding);
    return t;
}

[[nodiscard]] std::vector<std::byte> signed_message(std::string_view domain, const utils::byte_buffer& t) {
    std::vector<std::byte> m;
    m.reserve(domain.size() + t.size());
    const auto d = std::as_bytes(std::span{domain});
    m.insert(m.end(), d.begin(), d.end());
    const auto body = t.view();
    m.insert(m.end(), body.begin(), body.end());
    return m;
}

// ---- host side ---------------------------------------------------------------------------------------

class device_host_handshake final : public host_handshake {
public:
    device_host_handshake(std::shared_ptr<const device_allow_list> allowed, key_handle host, std::shared_ptr<const revoked_identities> revoked)
        : allowed_(std::move(allowed)), host_(std::move(host)), revoked_(std::move(revoked)) {}

    void bind_channel(std::span<const std::byte> binding) override { binding_.assign(binding.begin(), binding.end()); }

    result<value> challenge(const value& hello) override {
        const value* scheme = hello.find("scheme");
        const auto* scheme_name = scheme != nullptr ? scheme->get_if<std::string>() : nullptr;
        auto client = read_key(hello);
        const auto nc = read_nonce(hello);
        if (scheme_name == nullptr || *scheme_name != kScheme || !client || !nc || stage_ != stage::kHello) {
            return fail(errc::kProtocol, "malformed device-key hello (a device-key host needs a device-key client)", kWhere);
        }
        stage_ = stage::kDone; // until the challenge is out
        if (binding_.empty()) {
            return needs_tls();
        }
        if (host_.empty()) {
            return fail(errc::kAuth, "this host has no device key", kWhere);
        }
        auto nh = platform::random_array<kNonceSize>();
        if (!nh) {
            return std::unexpected{std::move(nh).error()};
        }
        const offered_key mine{host_.alg(), std::vector<std::byte>(host_.public_key().begin(), host_.public_key().end())};
        transcript_ = transcript(*client, *nc, *nh, mine, binding_);
        auto sig = host_.sign(signed_message(kHostDomain, transcript_));
        if (!sig) {
            return std::unexpected{std::move(sig).error()};
        }
        // Looked up for every key, listed or not: an unlisted one is answered the same way and fails at verify.
        entry_ = allowed_->find(client->alg, client->pub);
        if (entry_ != nullptr && revoked_ != nullptr && revoked_->is_revoked_device(client->pub, to_string(client->alg))) {
            entry_ = nullptr;
        }
        client_ = std::move(*client);
        stage_ = stage::kChallenged;
        value::map out;
        out.emplace_back("nonce", bytes_value(*nh));
        out.emplace_back("alg", value{std::string{to_string(mine.alg)}});
        out.emplace_back("pub", bytes_value(mine.pub));
        out.emplace_back("sig", bytes_value(*sig));
        return value{std::move(out)};
    }

    result<auth_grant> verify(const value& response) override {
        if (stage_ != stage::kChallenged) {
            return fail(errc::kProtocol, "device-key response before the challenge", kWhere);
        }
        stage_ = stage::kDone;
        const auto* sig = bytes_field(response, "sig");
        if (sig == nullptr || entry_ == nullptr || !security::verify(client_.alg, client_.pub, signed_message(kClientDomain, transcript_), *sig)) {
            return auth_failed();
        }
        auth_grant grant = detail::frame_keys(binding_, transcript_.view(), true);
        grant.identity = entry_->name;
        grant.granted = entry_->granted;
        grant.scopes = entry_->scopes;
        grant.host_key = host_.fingerprint();
        return grant;
    }

private:
    enum class stage : std::uint8_t {
        kHello,
        kChallenged,
        kDone
    };

    std::shared_ptr<const device_allow_list> allowed_;
    key_handle host_;
    std::shared_ptr<const revoked_identities> revoked_;
    const device_entry* entry_ = nullptr;
    offered_key client_;
    utils::byte_buffer transcript_;
    std::vector<std::byte> binding_;
    stage stage_ = stage::kHello;
};

// ---- client side -------------------------------------------------------------------------------------

class device_client_handshake final : public client_handshake {
public:
    explicit device_client_handshake(const device_credential& c) : cred_(c) {}

    result<value> hello() override {
        if (cred_.key.empty()) {
            return fail(errc::kInvalidArgument, "the device credential has no key", kWhere);
        }
        auto n = platform::random_array<kNonceSize>();
        if (!n) {
            return std::unexpected{std::move(n).error()};
        }
        nc_ = *n;
        value::map out;
        out.emplace_back("scheme", value{std::string{kScheme}});
        out.emplace_back("alg", value{std::string{to_string(cred_.key.alg())}});
        out.emplace_back("pub", bytes_value(cred_.key.public_key()));
        out.emplace_back("nonce", bytes_value(nc_));
        return value{std::move(out)};
    }

    void bind_channel(std::span<const std::byte> binding) override { binding_.assign(binding.begin(), binding.end()); }

    result<value> respond(const value& challenge) override {
        if (binding_.empty()) {
            return needs_tls();
        }
        const auto nh = read_nonce(challenge);
        auto host = read_key(challenge);
        const auto* sig = bytes_field(challenge, "sig");
        if (!nh || !host || sig == nullptr) {
            return fail(errc::kProtocol, "malformed device-key challenge", kWhere);
        }
        const offered_key mine{cred_.key.alg(), std::vector<std::byte>(cred_.key.public_key().begin(), cred_.key.public_key().end())};
        auto t = transcript(mine, nc_, *nh, *host, binding_);
        if (!security::verify(host->alg, host->pub, signed_message(kHostDomain, t), *sig)) {
            return fail(errc::kAuth, "the host's device-key signature doesn't verify", kWhere);
        }
        // The host holds this key; is it the one this client trusts for the endpoint?
        std::string fingerprint = key_fingerprint(host->alg, host->pub);
        switch (cred_.pins.check(cred_.endpoint, host->alg, host->pub)) {
        case known_hosts::match::kPinned: break;
        case known_hosts::match::kChanged:
            return fail(errc::kAuth,
                        std::format("the host key of {} changed: it is {} now, not one pinned in known_hosts (another host, or the host's key was replaced: "
                                    "remove the old line to trust the new one)",
                                    cred_.endpoint, fingerprint),
                        kWhere);
        case known_hosts::match::kUnknown:
            if (!cred_.trust_new || !cred_.trust_new(cred_.endpoint, fingerprint)) {
                return fail(errc::kAuth, std::format("the host key {} of {} is not in known_hosts", fingerprint, cred_.endpoint), kWhere);
            }
            // Pinned in memory even if the file can't be written.
            (void)cred_.pins.add({cred_.endpoint, host->alg, std::move(host->pub)});
            break;
        }
        auto mine_sig = cred_.key.sign(signed_message(kClientDomain, t));
        if (!mine_sig) {
            return std::unexpected{std::move(mine_sig).error()};
        }
        transcript_ = std::move(t);
        host_key_ = std::move(fingerprint);
        value::map out;
        out.emplace_back("sig", bytes_value(*mine_sig));
        return value{std::move(out)};
    }

    result<auth_grant> finish() override {
        if (transcript_.empty()) {
            return fail(errc::kProtocol, "device-key handshake not finished", kWhere);
        }
        auth_grant grant = detail::frame_keys(binding_, transcript_.view(), false);
        grant.host_key = host_key_;
        return grant;
    }

private:
    device_credential cred_;
    nonce nc_{};
    utils::byte_buffer transcript_;
    std::vector<std::byte> binding_;
    std::string host_key_;
};

} // namespace

std::unique_ptr<client_handshake> device_credential::begin() const {
    return std::make_unique<device_client_handshake>(*this);
}

std::unique_ptr<host_handshake> device_keys::begin() const {
    return std::make_unique<device_host_handshake>(allowed_, host_, revoked_);
}

} // namespace Rhp::security

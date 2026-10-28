#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <monocypher.h>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/security/authenticator.hpp>
#include <rhp/security/detail/bytes.hpp>
#include <rhp/security/detail/frame_keys.hpp>
#include <rhp/security/hash.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/psk_keyring.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/utils/scope_guard.hpp>
#include <rhp/wire/frame.hpp>

namespace Rhp::security {

using detail::u8;

namespace {

constexpr std::size_t kNonceSize = 32;
constexpr std::size_t kMacSize = 32;

using nonce = std::array<std::byte, kNonceSize>;

// Every MAC below is keyed_blake2b_256(psk, label, T): the PSK (a `key`, 16..64 bytes) is used whole.
static_assert(key::kMaxSize <= 64 && sizeof(digest256) == kMacSize && wire::kMacSize == kMacSize);

// T = len(name) ‖ name ‖ Nc ‖ Nh [‖ channel binding]: binds both nonces, the key name and (under
// TLS) the TLS connection into every proof and key.
[[nodiscard]] utils::byte_buffer transcript(std::string_view name, const nonce& client, const nonce& host, std::span<const std::byte> binding) {
    utils::byte_buffer t;
    t.reserve(sizeof(std::uint32_t) + name.size() + client.size() + host.size() + binding.size());
    t.append_le(static_cast<std::uint32_t>(name.size()));
    t.append(name);
    t.append(client);
    t.append(host);
    t.append(binding);
    return t;
}

// The per-direction frame MAC: keyed BLAKE2b-256 over header + payload.
//
// Keyed BLAKE2b hashes the key, padded to a block, as its first block, and Monocypher compresses that
// block once the first message byte arrives. Every frame starts with the frame magic, so the sealer
// keeps the state after the key and the magic and copies it per frame: the same MAC, one compression
// fewer (a frame of a call is 2-3 blocks). Input that doesn't start with the magic is hashed in full.
class blake2b_sealer final : public wire::frame_sealer {
public:
    explicit blake2b_sealer(const digest256& k) noexcept : key_(k) {
        crypto_blake2b_keyed_init(&primed_, wire::kMacSize, u8(key_.data()), key_.size());
        crypto_blake2b_update(&primed_, u8(wire::kMagic.data()), wire::kMagic.size());
    }
    ~blake2b_sealer() override {
        crypto_wipe(key_.data(), key_.size());
        crypto_wipe(&primed_, sizeof primed_);
    }

    blake2b_sealer(const blake2b_sealer&) = delete;
    blake2b_sealer& operator=(const blake2b_sealer&) = delete;

    [[nodiscard]] wire::mac_bytes seal(utils::bytes_view sealed) const noexcept override {
        wire::mac_bytes out{};
        if (sealed.size() >= wire::kMagic.size() && std::ranges::equal(sealed.first(wire::kMagic.size()), wire::kMagic)) {
            crypto_blake2b_ctx ctx = primed_;
            crypto_blake2b_update(&ctx, u8(sealed.data() + wire::kMagic.size()), sealed.size() - wire::kMagic.size());
            crypto_blake2b_final(&ctx, u8(out.data())); // also wipes ctx
            return out;
        }
        crypto_blake2b_keyed(u8(out.data()), out.size(), u8(key_.data()), key_.size(), u8(sealed.data()), sealed.size());
        return out;
    }

    [[nodiscard]] bool verify(utils::bytes_view sealed, std::span<const std::byte, wire::kMacSize> mac) const noexcept override {
        const wire::mac_bytes expected = seal(sealed);
        return digests_equal(expected, mac);
    }

private:
    digest256 key_;
    crypto_blake2b_ctx primed_{}; // keyed, the magic absorbed
};

[[nodiscard]] std::unexpected<error> auth_failed() {
    return fail(errc::kAuth, "authentication failed", "psk handshake");
}

[[nodiscard]] std::optional<nonce> read_nonce(const value& map, std::string_view field) {
    const value* v = map.find(field);
    const auto* b = v != nullptr ? v->get_if<value::bytes>() : nullptr;
    if (b == nullptr || b->size() != kNonceSize) {
        return std::nullopt;
    }
    nonce n{};
    std::ranges::copy(*b, n.begin());
    return n;
}

[[nodiscard]] value bytes_value(std::span<const std::byte> b) {
    return value{value::bytes(b.begin(), b.end())};
}

// ---- host side ---------------------------------------------------------------------------------------

class psk_host_handshake final : public host_handshake {
public:
    explicit psk_host_handshake(std::shared_ptr<const keyring> keys) : keys_(std::move(keys)) {}

    ~psk_host_handshake() override {
        if (!fake_secret_.empty()) {
            crypto_wipe(fake_secret_.data(), fake_secret_.size());
        }
    }

    void bind_channel(std::span<const std::byte> binding) override { binding_.assign(binding.begin(), binding.end()); }

    result<value> challenge(const value& hello) override {
        const value* name = hello.find("key");
        const auto client_nonce = read_nonce(hello, "nonce");
        if (name == nullptr || !name->is_string() || !client_nonce || stage_ != stage::kHello) {
            return fail(errc::kProtocol, "malformed psk hello", "psk handshake");
        }
        name_ = *name->get_if<std::string>();
        auto host_nonce = platform::random_array<kNonceSize>();
        if (!host_nonce) {
            return std::unexpected{std::move(host_nonce).error()};
        }
        // Drawn for every name, so a known one takes the same path as an unknown one, which is
        // answered exactly like a known one, with a secret nobody has.
        auto fake = platform::random_array<kMacSize>();
        if (!fake) {
            return std::unexpected{std::move(fake).error()};
        }
        const utils::scope_guard wipe_fake{[&fake]() noexcept { crypto_wipe(fake->data(), fake->size()); }};
        entry_ = keys_->find(name_);
        if (entry_ == nullptr) {
            fake_secret_.assign(fake->begin(), fake->end());
        }
        transcript_ = transcript(name_, *client_nonce, *host_nonce, binding_);
        stage_ = stage::kChallenged;
        const digest256 proof = keyed_blake2b_256(secret(), "rhp/host", transcript_.view());
        value::map out;
        out.emplace_back("nonce", bytes_value(*host_nonce));
        out.emplace_back("proof", bytes_value(proof));
        return value{std::move(out)};
    }

    result<auth_grant> verify(const value& response) override {
        if (stage_ != stage::kChallenged) {
            return fail(errc::kProtocol, "psk response before the challenge", "psk handshake");
        }
        stage_ = stage::kDone;
        const auto proof = read_nonce(response, "proof");
        if (!proof || entry_ == nullptr) {
            return auth_failed();
        }
        const digest256 expected = keyed_blake2b_256(secret(), "rhp/client", transcript_.view());
        if (!digests_equal(expected, *proof)) {
            return auth_failed();
        }
        auth_grant grant = detail::frame_keys(secret(), transcript_.view(), true);
        grant.identity = entry_->name;
        grant.granted = entry_->granted;
        grant.scopes = entry_->scopes;
        return grant;
    }

private:
    enum class stage : std::uint8_t {
        kHello,
        kChallenged,
        kDone
    };

    [[nodiscard]] std::span<const std::byte> secret() const noexcept {
        return entry_ != nullptr ? entry_->secret.bytes() : std::span<const std::byte>{fake_secret_};
    }

    std::shared_ptr<const keyring> keys_;
    const keyring_entry* entry_ = nullptr;
    std::vector<std::byte> fake_secret_;
    std::string name_;
    utils::byte_buffer transcript_;
    std::vector<std::byte> binding_;
    stage stage_ = stage::kHello;
};

// ---- client side -------------------------------------------------------------------------------------

class psk_client_handshake final : public client_handshake {
public:
    explicit psk_client_handshake(const psk_identity& id) : name_(id.name), secret_(id.secret) {}

    result<value> hello() override {
        auto n = platform::random_array<kNonceSize>();
        if (!n) {
            return std::unexpected{std::move(n).error()};
        }
        client_nonce_ = *n;
        value::map out;
        out.emplace_back("key", value{name_});
        out.emplace_back("nonce", bytes_value(client_nonce_));
        return value{std::move(out)};
    }

    void bind_channel(std::span<const std::byte> binding) override { binding_.assign(binding.begin(), binding.end()); }

    result<value> respond(const value& challenge) override {
        const auto host_nonce = read_nonce(challenge, "nonce");
        const auto proof = read_nonce(challenge, "proof");
        if (!host_nonce || !proof) {
            return fail(errc::kProtocol, "malformed psk challenge", "psk handshake");
        }
        transcript_ = transcript(name_, client_nonce_, *host_nonce, binding_);
        const digest256 expected = keyed_blake2b_256(secret_.bytes(), "rhp/host", transcript_.view());
        if (!digests_equal(expected, *proof)) {
            // The host doesn't know this key (or it is someone else): don't prove ours to it.
            return auth_failed();
        }
        const digest256 mine = keyed_blake2b_256(secret_.bytes(), "rhp/client", transcript_.view());
        value::map out;
        out.emplace_back("proof", bytes_value(mine));
        return value{std::move(out)};
    }

    result<auth_grant> finish() override {
        if (transcript_.empty()) {
            return fail(errc::kProtocol, "psk handshake not finished", "psk handshake");
        }
        auth_grant grant = detail::frame_keys(secret_.bytes(), transcript_.view(), false);
        grant.identity = name_;
        return grant;
    }

private:
    std::string name_;
    key secret_;
    nonce client_nonce_{};
    utils::byte_buffer transcript_;
    std::vector<std::byte> binding_;
};

} // namespace

auth_grant detail::frame_keys(std::span<const std::byte> key, std::span<const std::byte> t, bool host_side) {
    digest256 c2h = keyed_blake2b_256(key, "rhp/c2h", t);
    digest256 h2c = keyed_blake2b_256(key, "rhp/h2c", t);
    const utils::scope_guard wipe{[&]() noexcept {
        crypto_wipe(c2h.data(), c2h.size());
        crypto_wipe(h2c.data(), h2c.size());
    }};
    auth_grant grant;
    grant.outgoing = std::make_unique<blake2b_sealer>(host_side ? h2c : c2h);
    grant.incoming = std::make_unique<blake2b_sealer>(host_side ? c2h : h2c);
    return grant;
}

std::unique_ptr<client_handshake> psk_identity::begin() const {
    return std::make_unique<psk_client_handshake>(*this);
}

std::unique_ptr<host_handshake> psk_keyring::begin() const {
    return std::make_unique<psk_host_handshake>(keys_);
}

} // namespace Rhp::security

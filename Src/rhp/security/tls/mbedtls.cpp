#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/security/tls/mbedtls.hpp>
#include <rhp/security/tls/tls.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace Rhp::security::tls {

namespace {

constexpr const char* kWhere = "tls (mbedtls)";
constexpr std::string_view kBindingLabel = "EXPORTER-Channel-Binding";
constexpr std::size_t kReadChunk = 16u * 1024u;

// Mbed TLS's PSA core (key slots, the RNG) is only thread-safe with MBEDTLS_THREADING_C, which the
// default configuration leaves off and Windows can't turn on without a custom threading layer.
// Every call into Mbed TLS takes this lock instead (recursive: a config may be freed while it is
// held); TLS on a handful of links doesn't notice.
std::recursive_mutex& lib_mutex() {
    static std::recursive_mutex m;
    return m;
}

[[nodiscard]] std::string describe(int code) {
    std::array<char, 160> buf{};
    mbedtls_strerror(code, buf.data(), buf.size());
    return std::format("{} (-0x{:04x})", buf.data(), static_cast<unsigned>(-code));
}

[[nodiscard]] std::unexpected<error> failure(errc code, std::string_view what, int ret) {
    return fail(code, std::format("{}: {}", what, describe(ret)), kWhere);
}

// psa_crypto_init() once per process (callers hold lib_mutex()).
[[nodiscard]] result<void> init_psa() {
    static const psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return fail(errc::kTransport, std::format("psa_crypto_init failed ({})", static_cast<int>(status)), kWhere);
    }
    return {};
}

// What both ends own: the configuration and its certificates. Freed only after every engine made
// from it (engines keep the context alive).
struct shared_config {
    mbedtls_ssl_config conf{};
    mbedtls_x509_crt own_cert{};
    mbedtls_pk_context own_key{};
    mbedtls_x509_crt ca{};
    std::string server_name;
    bool client = false;

    shared_config() {
        mbedtls_ssl_config_init(&conf);
        mbedtls_x509_crt_init(&own_cert);
        mbedtls_pk_init(&own_key);
        mbedtls_x509_crt_init(&ca);
    }

    ~shared_config() {
        const std::scoped_lock lock{lib_mutex()};
        mbedtls_ssl_config_free(&conf);
        mbedtls_x509_crt_free(&own_cert);
        mbedtls_pk_free(&own_key);
        mbedtls_x509_crt_free(&ca);
    }

    shared_config(const shared_config&) = delete;
    shared_config& operator=(const shared_config&) = delete;
};

// mbedtls_x509_crt_parse wants PEM with its terminating NUL counted.
[[nodiscard]] std::vector<unsigned char> pem_bytes(std::string_view pem) {
    std::vector<unsigned char> out(pem.begin(), pem.end());
    out.push_back(0);
    return out;
}

// An ephemeral self-signed P-256 certificate ("CN=rhp host"), valid for ten years.
[[nodiscard]] result<void> make_ephemeral_certificate(shared_config& c) {
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE |
                                             PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_COPY);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    if (const psa_status_t s = psa_generate_key(&attributes, &key_id); s != PSA_SUCCESS) {
        return fail(errc::kTransport, std::format("can't make a key ({})", static_cast<int>(s)), kWhere);
    }
    // A plain (non-PSA) copy, so the PSA slot can go right away.
    const int copied = mbedtls_pk_copy_from_psa(key_id, &c.own_key);
    (void)psa_destroy_key(key_id);
    if (copied != 0) {
        return failure(errc::kTransport, "can't use the new key", copied);
    }

    auto serial = platform::random_array<8>();
    if (!serial) {
        return std::unexpected{std::move(serial).error()};
    }
    (*serial)[0] &= std::byte{0x7f}; // positive

    mbedtls_x509write_cert crt;
    mbedtls_x509write_crt_init(&crt);
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt, &c.own_key);
    mbedtls_x509write_crt_set_issuer_key(&crt, &c.own_key);
    int ret = mbedtls_x509write_crt_set_serial_raw(&crt, reinterpret_cast<unsigned char*>(serial->data()), serial->size());
    if (ret == 0) {
        ret = mbedtls_x509write_crt_set_validity(&crt, "20250101000000", "20450101000000");
    }
    if (ret == 0) {
        ret = mbedtls_x509write_crt_set_subject_name(&crt, "CN=rhp host");
    }
    if (ret == 0) {
        ret = mbedtls_x509write_crt_set_issuer_name(&crt, "CN=rhp host");
    }
    std::vector<unsigned char> der(2048);
    int written = ret == 0 ? mbedtls_x509write_crt_der(&crt, der.data(), der.size()) : ret;
    mbedtls_x509write_crt_free(&crt);
    if (written < 0) {
        return failure(errc::kTransport, "can't write a self-signed certificate", written);
    }
    // The DER is written at the end of the buffer.
    ret = mbedtls_x509_crt_parse_der(&c.own_cert, der.data() + der.size() - static_cast<std::size_t>(written), static_cast<std::size_t>(written));
    if (ret != 0) {
        return failure(errc::kTransport, "can't read back the self-signed certificate", ret);
    }
    return {};
}

[[nodiscard]] result<void> load_certificate(shared_config& c, const settings& s) {
    const auto cert = pem_bytes(s.cert_pem);
    if (const int ret = mbedtls_x509_crt_parse(&c.own_cert, cert.data(), cert.size()); ret != 0) {
        return failure(errc::kInvalidArgument, "cert_pem holds no usable certificate", ret);
    }
    const auto key = pem_bytes(s.key_pem);
    if (const int ret = mbedtls_pk_parse_key(&c.own_key, key.data(), key.size(), nullptr, 0); ret != 0) {
        return failure(errc::kInvalidArgument, "key_pem holds no usable private key", ret);
    }
    if (const int ret = mbedtls_pk_check_pair(&c.own_cert.pk, &c.own_key); ret != 0) {
        return failure(errc::kInvalidArgument, "key_pem doesn't hold the certificate's private key", ret);
    }
    return {};
}

[[nodiscard]] result<std::shared_ptr<shared_config>> make_config(const settings& s, bool client) {
    auto c = std::make_shared<shared_config>();
    c->client = client;
    c->server_name = s.server_name;
    int ret = mbedtls_ssl_config_defaults(&c->conf, client ? MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        return failure(errc::kTransport, "can't set up TLS", ret);
    }
    mbedtls_ssl_conf_min_tls_version(&c->conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&c->conf, MBEDTLS_SSL_VERSION_TLS1_3);
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    mbedtls_ssl_conf_session_tickets(&c->conf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if (!client) {
        mbedtls_ssl_conf_new_session_tickets(&c->conf, 0);
    }
#endif
#endif
    if (client) {
        if (s.ca_pem.empty()) {
            mbedtls_ssl_conf_authmode(&c->conf, MBEDTLS_SSL_VERIFY_NONE);
        } else {
            const auto ca = pem_bytes(s.ca_pem);
            if (ret = mbedtls_x509_crt_parse(&c->ca, ca.data(), ca.size()); ret != 0) {
                return failure(errc::kInvalidArgument, "ca_pem holds no usable certificate", ret);
            }
            mbedtls_ssl_conf_ca_chain(&c->conf, &c->ca, nullptr);
            mbedtls_ssl_conf_authmode(&c->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        }
    } else {
        auto cert = s.cert_pem.empty() ? make_ephemeral_certificate(*c) : load_certificate(*c, s);
        if (!cert) {
            return std::unexpected{std::move(cert).error()};
        }
        if (ret = mbedtls_ssl_conf_own_cert(&c->conf, &c->own_cert, &c->own_key); ret != 0) {
            return failure(errc::kTransport, "can't use the certificate", ret);
        }
    }
    return c;
}

class mbedtls_engine final : public engine {
public:
    explicit mbedtls_engine(std::shared_ptr<shared_config> config) : config_(std::move(config)) { mbedtls_ssl_init(&ssl_); }

    ~mbedtls_engine() override {
        const std::scoped_lock lock{lib_mutex()};
        mbedtls_ssl_free(&ssl_);
    }

    mbedtls_engine(const mbedtls_engine&) = delete;
    mbedtls_engine& operator=(const mbedtls_engine&) = delete;

    // Under lib_mutex(), once, right after construction.
    [[nodiscard]] result<void> setup() {
        if (const int ret = mbedtls_ssl_setup(&ssl_, &config_->conf); ret != 0) {
            return failure(errc::kTransport, "can't start a TLS connection", ret);
        }
        if (config_->client) {
            // NULL says "no name check" on purpose (Mbed TLS refuses to verify without a decision).
            const int ret = mbedtls_ssl_set_hostname(&ssl_, config_->server_name.empty() ? nullptr : config_->server_name.c_str());
            if (ret != 0) {
                return failure(errc::kInvalidArgument, "bad server_name", ret);
            }
        }
        mbedtls_ssl_set_bio(&ssl_, this, &mbedtls_engine::bio_send, &mbedtls_engine::bio_recv, nullptr);
        return {};
    }

    result<void> start(utils::byte_buffer& to_peer) override {
        const std::scoped_lock lock{lib_mutex()};
        out_ = &to_peer;
        auto ok = config_->client ? step() : result<void>{};
        out_ = nullptr;
        return ok;
    }

    result<void> receive(utils::bytes_view from_peer, utils::byte_buffer& plain, utils::byte_buffer& to_peer) override {
        const std::scoped_lock lock{lib_mutex()};
        in_.insert(in_.end(), from_peer.begin(), from_peer.end());
        out_ = &to_peer;
        auto ok = pump(plain);
        out_ = nullptr;
        return ok;
    }

    result<void> send(utils::bytes_view plain, utils::byte_buffer& to_peer) override {
        const std::scoped_lock lock{lib_mutex()};
        if (!established_) {
            return fail(errc::kTransport, "TLS is not established", kWhere);
        }
        out_ = &to_peer;
        std::size_t done = 0;
        while (done < plain.size()) {
            const int n = mbedtls_ssl_write(&ssl_, reinterpret_cast<const unsigned char*>(plain.data() + done), plain.size() - done);
            if (n < 0) {
                out_ = nullptr;
                return failure(errc::kTransport, "TLS write failed", n);
            }
            done += static_cast<std::size_t>(n);
        }
        out_ = nullptr;
        return {};
    }

    void close(utils::byte_buffer& to_peer) noexcept override {
        const std::scoped_lock lock{lib_mutex()};
        if (established_) {
            out_ = &to_peer;
            (void)mbedtls_ssl_close_notify(&ssl_);
            out_ = nullptr;
        }
    }

    bool established() const noexcept override { return established_; }

    result<channel_binding> binding() override {
        const std::scoped_lock lock{lib_mutex()};
        channel_binding out{};
        if (!established_) {
            return fail(errc::kTransport, "no TLS channel binding before the handshake", kWhere);
        }
        const int ret = mbedtls_ssl_export_keying_material(&ssl_, reinterpret_cast<std::uint8_t*>(out.data()), out.size(), kBindingLabel.data(), kBindingLabel.size(),
                                                           nullptr, 0, 0);
        if (ret != 0) {
            return failure(errc::kTransport, "no TLS channel binding", ret);
        }
        return out;
    }

private:
    result<void> step() {
        const int ret = mbedtls_ssl_handshake(&ssl_);
        if (ret == 0) {
            established_ = true;
            return {};
        }
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            return {};
        }
        if (config_->client && mbedtls_ssl_get_verify_result(&ssl_) != 0) {
            return failure(errc::kAuth, "the host's certificate didn't verify", ret);
        }
        return failure(errc::kTransport, "TLS handshake failed", ret);
    }

    result<void> pump(utils::byte_buffer& plain) {
        if (!established_) {
            if (auto ok = step(); !ok || !established_) {
                return ok;
            }
        }
        std::array<unsigned char, kReadChunk> buf{};
        for (;;) {
            const int n = mbedtls_ssl_read(&ssl_, buf.data(), buf.size());
            if (n > 0) {
                plain.append(std::as_bytes(std::span{buf.data(), static_cast<std::size_t>(n)}));
                continue;
            }
            if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
                return {};
            }
#if defined(MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
            if (n == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
                continue;
            }
#endif
            if (n == 0 || n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                return fail(errc::kTransport, "the peer closed TLS", kWhere);
            }
            return failure(errc::kTransport, "TLS read failed", n);
        }
    }

    static int bio_send(void* self, const unsigned char* buf, std::size_t len) {
        auto* e = static_cast<mbedtls_engine*>(self);
        if (e->out_ == nullptr) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        try {
            e->out_->append(std::as_bytes(std::span{buf, len}));
        } catch (...) {
            return MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
        return static_cast<int>(len);
    }

    static int bio_recv(void* self, unsigned char* buf, std::size_t len) {
        auto* e = static_cast<mbedtls_engine*>(self);
        if (e->read_ == e->in_.size()) {
            e->in_.clear();
            e->read_ = 0;
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        const std::size_t n = std::min(len, e->in_.size() - e->read_);
        std::memcpy(buf, e->in_.data() + e->read_, n);
        e->read_ += n;
        return static_cast<int>(n);
    }

    std::shared_ptr<shared_config> config_;
    mbedtls_ssl_context ssl_{};
    std::vector<std::byte> in_;
    std::size_t read_ = 0;
    utils::byte_buffer* out_ = nullptr;
    bool established_ = false;
};

class mbedtls_context final : public context {
public:
    explicit mbedtls_context(std::shared_ptr<shared_config> config) : config_(std::move(config)) {}

    result<std::unique_ptr<engine>> make_engine() override {
        auto e = std::make_unique<mbedtls_engine>(config_);
        const std::scoped_lock lock{lib_mutex()};
        if (auto ok = e->setup(); !ok) {
            return std::unexpected{std::move(ok).error()};
        }
        return std::unique_ptr<engine>{std::move(e)};
    }

private:
    std::shared_ptr<shared_config> config_;
};

[[nodiscard]] result<std::shared_ptr<context>> make_context(const settings& s, bool client) {
    std::shared_ptr<shared_config> config;
    {
        const std::scoped_lock lock{lib_mutex()};
        if (auto ok = init_psa(); !ok) {
            return std::unexpected{std::move(ok).error()};
        }
        auto made = make_config(s, client);
        if (!made) {
            return std::unexpected{std::move(made).error()};
        }
        config = std::move(*made);
    }
    return std::make_shared<mbedtls_context>(std::move(config));
}

} // namespace

result<std::shared_ptr<context>> mbedtls::server(const settings& s) {
    return make_context(s, false);
}

result<std::shared_ptr<context>> mbedtls::client(const settings& s) {
    return make_context(s, true);
}

} // namespace Rhp::security::tls

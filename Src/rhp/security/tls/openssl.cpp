#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/security/tls/openssl.hpp>
#include <rhp/security/tls/tls.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace Rhp::security::tls {

namespace {

constexpr const char* kWhere = "tls (openssl)";
constexpr std::string_view kBindingLabel = "EXPORTER-Channel-Binding";
constexpr std::size_t kReadChunk = 16u * 1024u;

struct ctx_free {
    void operator()(SSL_CTX* p) const noexcept { SSL_CTX_free(p); }
};
struct ssl_free {
    void operator()(SSL* p) const noexcept { SSL_free(p); }
};
struct pkey_free {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
struct x509_free {
    void operator()(X509* p) const noexcept { X509_free(p); }
};
struct bio_free {
    void operator()(BIO* p) const noexcept { BIO_free(p); }
};

using ctx_ptr = std::unique_ptr<SSL_CTX, ctx_free>;
using ssl_ptr = std::unique_ptr<SSL, ssl_free>;
using pkey_ptr = std::unique_ptr<EVP_PKEY, pkey_free>;
using x509_ptr = std::unique_ptr<X509, x509_free>;
using bio_ptr = std::unique_ptr<BIO, bio_free>;

// The OpenSSL error queue as text (and emptied), or `fallback`.
[[nodiscard]] std::string drain_errors(std::string_view fallback) {
    std::string text;
    while (const unsigned long code = ERR_get_error()) {
        std::array<char, 256> buf{};
        ERR_error_string_n(code, buf.data(), buf.size());
        if (!text.empty()) {
            text += "; ";
        }
        text += buf.data();
    }
    return text.empty() ? std::string{fallback} : text;
}

[[nodiscard]] std::unexpected<error> failure(errc code, std::string_view what) {
    return fail(code, drain_errors(what), kWhere);
}

[[nodiscard]] bio_ptr memory_bio(std::string_view text) {
    return bio_ptr{BIO_new_mem_buf(text.data(), static_cast<int>(text.size()))};
}

// An ephemeral self-signed P-256 certificate ("CN=rhp host"), valid from an hour ago for ten years.
[[nodiscard]] result<void> use_ephemeral_certificate(SSL_CTX* ctx) {
    pkey_ptr key{EVP_EC_gen("P-256")};
    x509_ptr cert{X509_new()};
    if (key == nullptr || cert == nullptr) {
        return failure(errc::kTransport, "can't make a key");
    }
    auto serial = platform::random_array<8>();
    if (!serial) {
        return std::unexpected{std::move(serial).error()};
    }
    std::uint64_t n = 0;
    for (const std::byte b : *serial) {
        n = (n << 8) | std::to_integer<std::uint64_t>(b);
    }
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set_uint64(X509_get_serialNumber(cert.get()), n >> 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 10L * 365 * 24 * 3600);
    X509_set_pubkey(cert.get(), key.get());
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("rhp host"), -1, -1, 0);
    X509_set_issuer_name(cert.get(), name);
    if (X509_sign(cert.get(), key.get(), EVP_sha256()) == 0 || SSL_CTX_use_certificate(ctx, cert.get()) != 1 ||
        SSL_CTX_use_PrivateKey(ctx, key.get()) != 1) {
        return failure(errc::kTransport, "can't make a self-signed certificate");
    }
    return {};
}

[[nodiscard]] result<void> use_certificate(SSL_CTX* ctx, const settings& s) {
    bio_ptr certs = memory_bio(s.cert_pem);
    x509_ptr leaf{certs != nullptr ? PEM_read_bio_X509(certs.get(), nullptr, nullptr, nullptr) : nullptr};
    if (leaf == nullptr || SSL_CTX_use_certificate(ctx, leaf.get()) != 1) {
        return failure(errc::kInvalidArgument, "cert_pem holds no usable certificate");
    }
    while (X509* extra = PEM_read_bio_X509(certs.get(), nullptr, nullptr, nullptr)) {
        if (SSL_CTX_add0_chain_cert(ctx, extra) != 1) {
            X509_free(extra);
            return failure(errc::kInvalidArgument, "cert_pem has a bad chain certificate");
        }
    }
    ERR_clear_error(); // the loop ends on "no start line"
    bio_ptr keys = memory_bio(s.key_pem);
    pkey_ptr key{keys != nullptr ? PEM_read_bio_PrivateKey(keys.get(), nullptr, nullptr, nullptr) : nullptr};
    if (key == nullptr || SSL_CTX_use_PrivateKey(ctx, key.get()) != 1 || SSL_CTX_check_private_key(ctx) != 1) {
        return failure(errc::kInvalidArgument, "key_pem doesn't hold the certificate's private key");
    }
    return {};
}

[[nodiscard]] result<void> trust(SSL_CTX* ctx, const settings& s) {
    X509_STORE* store = SSL_CTX_get_cert_store(ctx);
    bio_ptr certs = memory_bio(s.ca_pem);
    int added = 0;
    while (const x509_ptr ca{certs != nullptr ? PEM_read_bio_X509(certs.get(), nullptr, nullptr, nullptr) : nullptr}) {
        if (X509_STORE_add_cert(store, ca.get()) != 1) { // the store takes its own reference
            return failure(errc::kInvalidArgument, "ca_pem has a bad certificate");
        }
        ++added;
    }
    ERR_clear_error();
    if (added == 0) {
        return fail(errc::kInvalidArgument, "ca_pem holds no certificate", kWhere);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    return {};
}

class openssl_engine final : public engine {
public:
    explicit openssl_engine(ssl_ptr ssl, bool client) : ssl_(std::move(ssl)), client_(client) {}

    result<void> start(utils::byte_buffer& to_peer) override {
        if (client_) {
            if (auto ok = step(); !ok) {
                return ok;
            }
        }
        drain(to_peer);
        return {};
    }

    result<void> receive(utils::bytes_view from_peer, utils::byte_buffer& plain, utils::byte_buffer& to_peer) override {
        if (!from_peer.empty() && BIO_write(SSL_get_rbio(ssl_.get()), from_peer.data(), static_cast<int>(from_peer.size())) <= 0) {
            return failure(errc::kTransport, "can't buffer TLS input");
        }
        if (!established_) {
            if (auto ok = step(); !ok) {
                drain(to_peer); // the alert, if any
                return ok;
            }
        }
        if (established_) {
            std::array<std::byte, kReadChunk> buf{};
            for (;;) {
                std::size_t got = 0;
                ERR_clear_error();
                if (SSL_read_ex(ssl_.get(), buf.data(), buf.size(), &got) == 1) {
                    plain.append(utils::bytes_view{buf.data(), got});
                    continue;
                }
                const int err = SSL_get_error(ssl_.get(), 0);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    break;
                }
                drain(to_peer);
                if (err == SSL_ERROR_ZERO_RETURN) {
                    return fail(errc::kTransport, "the peer closed TLS", kWhere);
                }
                return failure(errc::kTransport, "TLS read failed");
            }
        }
        drain(to_peer);
        return {};
    }

    result<void> send(utils::bytes_view plain, utils::byte_buffer& to_peer) override {
        if (!established_) {
            return fail(errc::kTransport, "TLS is not established", kWhere);
        }
        if (!plain.empty()) {
            std::size_t written = 0;
            ERR_clear_error();
            if (SSL_write_ex(ssl_.get(), plain.data(), plain.size(), &written) != 1 || written != plain.size()) {
                return failure(errc::kTransport, "TLS write failed");
            }
        }
        drain(to_peer);
        return {};
    }

    void close(utils::byte_buffer& to_peer) noexcept override {
        if (established_) {
            (void)SSL_shutdown(ssl_.get());
            try {
                drain(to_peer);
            } catch (...) { // out of memory: the peer misses the close_notify
            }
        }
        ERR_clear_error();
    }

    bool established() const noexcept override { return established_; }

    result<channel_binding> binding() override {
        channel_binding out{};
        if (!established_ || SSL_export_keying_material(ssl_.get(), reinterpret_cast<unsigned char*>(out.data()), out.size(), kBindingLabel.data(), kBindingLabel.size(),
                                                        nullptr, 0, 0) != 1) {
            return failure(errc::kTransport, "no TLS channel binding");
        }
        return out;
    }

private:
    result<void> step() {
        ERR_clear_error(); // SSL_get_error reads the thread's queue: start from an empty one
        const int r = SSL_do_handshake(ssl_.get());
        if (r == 1) {
            established_ = true;
            return {};
        }
        const int err = SSL_get_error(ssl_.get(), r);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return {};
        }
        if ((SSL_get_verify_mode(ssl_.get()) & SSL_VERIFY_PEER) != 0 && SSL_get_verify_result(ssl_.get()) != X509_V_OK) {
            const long v = SSL_get_verify_result(ssl_.get());
            ERR_clear_error();
            return fail(errc::kAuth, std::format("the host's certificate didn't verify: {}", X509_verify_cert_error_string(v)), kWhere);
        }
        return failure(errc::kTransport, "TLS handshake failed");
    }

    void drain(utils::byte_buffer& to_peer) {
        BIO* out = SSL_get_wbio(ssl_.get());
        std::array<std::byte, kReadChunk> buf{};
        for (;;) {
            const int n = BIO_read(out, buf.data(), static_cast<int>(buf.size()));
            if (n <= 0) {
                return;
            }
            to_peer.append(utils::bytes_view{buf.data(), static_cast<std::size_t>(n)});
        }
    }

    ssl_ptr ssl_;
    bool client_;
    bool established_ = false;
};

class openssl_context final : public context {
public:
    openssl_context(ctx_ptr ctx, bool client, std::string server_name) : ctx_(std::move(ctx)), client_(client), server_name_(std::move(server_name)) {}

    result<std::unique_ptr<engine>> make_engine() override {
        ssl_ptr ssl{SSL_new(ctx_.get())};
        bio_ptr in{BIO_new(BIO_s_mem())};
        bio_ptr out{BIO_new(BIO_s_mem())};
        if (ssl == nullptr || in == nullptr || out == nullptr) {
            return failure(errc::kTransport, "can't start a TLS connection");
        }
        BIO_set_mem_eof_return(in.get(), -1);                // an empty input is "want more", not EOF
        SSL_set_bio(ssl.get(), in.release(), out.release()); // the SSL owns both from here
        if (client_) {
            SSL_set_connect_state(ssl.get());
            if (!server_name_.empty()) {
                // An IP address is checked against the certificate's IP addresses and sent in no SNI
                // (RFC 6066 has no place for one); a name against its DNS names, and sent.
                const bool ip = X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl.get()), server_name_.c_str()) == 1;
                ERR_clear_error(); // a name isn't an address: nothing to report
                if (!ip && (SSL_set_tlsext_host_name(ssl.get(), server_name_.c_str()) != 1 || SSL_set1_host(ssl.get(), server_name_.c_str()) != 1)) {
                    return failure(errc::kInvalidArgument, "bad server_name");
                }
            }
        } else {
            SSL_set_accept_state(ssl.get());
        }
        return std::make_unique<openssl_engine>(std::move(ssl), client_);
    }

private:
    ctx_ptr ctx_;
    bool client_;
    std::string server_name_;
};

[[nodiscard]] result<ctx_ptr> new_context(bool client) {
    ctx_ptr ctx{SSL_CTX_new(client ? TLS_client_method() : TLS_server_method())};
    if (ctx == nullptr) {
        return failure(errc::kTransport, "can't create a TLS context");
    }
    // TLS 1.3 only; no session tickets (a reconnect resumes RHP's session, not TLS's).
    if (SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) != 1 || SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION) != 1) {
        return failure(errc::kTransport, "TLS 1.3 is not available");
    }
    SSL_CTX_set_options(ctx.get(), SSL_OP_NO_TICKET);
    (void)SSL_CTX_set_num_tickets(ctx.get(), 0);
    SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_OFF);
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
    return ctx;
}

} // namespace

result<std::shared_ptr<context>> openssl::server(const settings& s) {
    auto ctx = new_context(false);
    if (!ctx) {
        return std::unexpected{std::move(ctx).error()};
    }
    auto cert = s.cert_pem.empty() ? use_ephemeral_certificate(ctx->get()) : use_certificate(ctx->get(), s);
    if (!cert) {
        return std::unexpected{std::move(cert).error()};
    }
    return std::make_shared<openssl_context>(std::move(*ctx), false, std::string{});
}

result<std::shared_ptr<context>> openssl::client(const settings& s) {
    auto ctx = new_context(true);
    if (!ctx) {
        return std::unexpected{std::move(ctx).error()};
    }
    if (!s.ca_pem.empty()) {
        if (auto ok = trust(ctx->get(), s); !ok) {
            return std::unexpected{std::move(ok).error()};
        }
    }
    return std::make_shared<openssl_context>(std::move(*ctx), true, s.server_name);
}

} // namespace Rhp::security::tls

#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/security/tls/openssl.hpp>
#include <rhp/security/tls/p256.hpp>
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

// ---- P-256 for key handles ------------------------------------------------------------------------

namespace Rhp::security::tls::detail {

namespace {

struct bn_free {
    void operator()(BIGNUM* p) const noexcept { BN_clear_free(p); }
};
struct group_free {
    void operator()(EC_GROUP* p) const noexcept { EC_GROUP_free(p); }
};
struct point_free {
    void operator()(EC_POINT* p) const noexcept { EC_POINT_free(p); }
};
struct param_bld_free {
    void operator()(OSSL_PARAM_BLD* p) const noexcept { OSSL_PARAM_BLD_free(p); }
};
struct params_free {
    void operator()(OSSL_PARAM* p) const noexcept { OSSL_PARAM_free(p); }
};
struct pkey_ctx_free {
    void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); }
};
struct md_ctx_free {
    void operator()(EVP_MD_CTX* p) const noexcept { EVP_MD_CTX_free(p); }
};
struct ecdsa_sig_free {
    void operator()(ECDSA_SIG* p) const noexcept { ECDSA_SIG_free(p); }
};

using bn_ptr = std::unique_ptr<BIGNUM, bn_free>;
using group_ptr = std::unique_ptr<EC_GROUP, group_free>;
using point_ptr = std::unique_ptr<EC_POINT, point_free>;
using param_bld_ptr = std::unique_ptr<OSSL_PARAM_BLD, param_bld_free>;
using params_ptr = std::unique_ptr<OSSL_PARAM, params_free>;
using pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, pkey_ctx_free>;
using md_ctx_ptr = std::unique_ptr<EVP_MD_CTX, md_ctx_free>;
using ecdsa_sig_ptr = std::unique_ptr<ECDSA_SIG, ecdsa_sig_free>;

[[nodiscard]] const unsigned char* uc(const std::byte* p) noexcept {
    return reinterpret_cast<const unsigned char*>(p);
}

// d as a BIGNUM, checked to be a P-256 scalar (0 < d < n).
[[nodiscard]] result<bn_ptr> scalar(std::span<const std::byte, kP256PrivateKeySize> d, const EC_GROUP* group) {
    bn_ptr bn{BN_bin2bn(uc(d.data()), static_cast<int>(d.size()), nullptr)};
    if (!bn) {
        return failure(errc::kRuntime, "out of memory");
    }
    if (BN_is_zero(bn.get()) || BN_cmp(bn.get(), EC_GROUP_get0_order(group)) >= 0) {
        return fail(errc::kInvalidArgument, "not a P-256 private key (0 or not below the group order)", kWhere);
    }
    return bn;
}

// An EVP_PKEY for the public key `pub`, with the private scalar `d` when given.
[[nodiscard]] result<pkey_ptr> make_pkey(std::span<const std::byte, kP256PublicKeySize> pub, const BIGNUM* d) {
    param_bld_ptr bld{OSSL_PARAM_BLD_new()};
    if (!bld || OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) != 1 ||
        OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, pub.data(), pub.size()) != 1 ||
        (d != nullptr && OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, d) != 1)) {
        return failure(errc::kRuntime, "can't describe a P-256 key");
    }
    params_ptr params{OSSL_PARAM_BLD_to_param(bld.get())};
    pkey_ctx_ptr ctx{EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)};
    EVP_PKEY* raw = nullptr;
    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1 ||
        EVP_PKEY_fromdata(ctx.get(), &raw, d != nullptr ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params.get()) != 1) {
        return failure(errc::kInvalidArgument, "not a P-256 key");
    }
    return pkey_ptr{raw};
}

} // namespace

std::string_view p256_backend() noexcept {
    return "openssl";
}

result<p256_public_key> p256_public_from_private(std::span<const std::byte, kP256PrivateKeySize> d) {
    const group_ptr group{EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)};
    if (!group) {
        return failure(errc::kRuntime, "no P-256 group");
    }
    auto bn = scalar(d, group.get());
    if (!bn) {
        return std::unexpected{std::move(bn).error()};
    }
    const point_ptr point{EC_POINT_new(group.get())};
    p256_public_key out{};
    if (!point || EC_POINT_mul(group.get(), point.get(), bn->get(), nullptr, nullptr, nullptr) != 1 ||
        EC_POINT_point2oct(group.get(), point.get(), POINT_CONVERSION_UNCOMPRESSED, reinterpret_cast<unsigned char*>(out.data()), out.size(), nullptr) !=
            out.size()) {
        return failure(errc::kRuntime, "can't derive the P-256 public key");
    }
    return out;
}

result<p256_signature> p256_sign(std::span<const std::byte, kP256PrivateKeySize> d, std::span<const std::byte> message) {
    const auto pub = p256_public_from_private(d);
    if (!pub) {
        return std::unexpected{pub.error()};
    }
    const bn_ptr bn{BN_bin2bn(uc(d.data()), static_cast<int>(d.size()), nullptr)};
    if (!bn) {
        return failure(errc::kRuntime, "out of memory");
    }
    auto key = make_pkey(*pub, bn.get());
    if (!key) {
        return std::unexpected{std::move(key).error()};
    }
    // EVP signs DER (an X9.62 ECDSA-Sig-Value); the wire wants r || s.
    const md_ctx_ptr md{EVP_MD_CTX_new()};
    std::size_t length = 0;
    if (!md || EVP_DigestSignInit(md.get(), nullptr, EVP_sha256(), nullptr, key->get()) != 1 ||
        EVP_DigestSign(md.get(), nullptr, &length, uc(message.data()), message.size()) != 1) {
        return failure(errc::kRuntime, "P-256 signing failed");
    }
    std::vector<unsigned char> der(length);
    if (EVP_DigestSign(md.get(), der.data(), &length, uc(message.data()), message.size()) != 1) {
        return failure(errc::kRuntime, "P-256 signing failed");
    }
    const unsigned char* cursor = der.data();
    const ecdsa_sig_ptr sig{d2i_ECDSA_SIG(nullptr, &cursor, static_cast<long>(length))};
    if (!sig) {
        return failure(errc::kRuntime, "can't read OpenSSL's P-256 signature");
    }
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig.get(), &r, &s);
    p256_signature out{};
    auto* raw = reinterpret_cast<unsigned char*>(out.data());
    if (BN_bn2binpad(r, raw, 32) != 32 || BN_bn2binpad(s, raw + 32, 32) != 32) {
        return failure(errc::kRuntime, "can't encode the P-256 signature");
    }
    return out;
}

result<void> p256_verify(std::span<const std::byte, kP256PublicKeySize> public_key, std::span<const std::byte> message,
                         std::span<const std::byte, kP256SignatureSize> signature) {
    auto key = make_pkey(public_key, nullptr);
    if (!key) {
        return std::unexpected{std::move(key).error()};
    }
    // r || s back to DER for EVP.
    ecdsa_sig_ptr sig{ECDSA_SIG_new()};
    BIGNUM* r = BN_bin2bn(uc(signature.data()), 32, nullptr);
    BIGNUM* s = BN_bin2bn(uc(signature.data() + 32), 32, nullptr);
    if (!sig || r == nullptr || s == nullptr || ECDSA_SIG_set0(sig.get(), r, s) != 1) {
        BN_free(r);
        BN_free(s);
        return failure(errc::kRuntime, "out of memory");
    }
    const int der_size = i2d_ECDSA_SIG(sig.get(), nullptr);
    if (der_size <= 0) {
        return failure(errc::kRuntime, "can't encode the P-256 signature");
    }
    std::vector<unsigned char> der(static_cast<std::size_t>(der_size));
    unsigned char* cursor = der.data();
    if (i2d_ECDSA_SIG(sig.get(), &cursor) != der_size) {
        return failure(errc::kRuntime, "can't encode the P-256 signature");
    }
    const md_ctx_ptr md{EVP_MD_CTX_new()};
    if (!md || EVP_DigestVerifyInit(md.get(), nullptr, EVP_sha256(), nullptr, key->get()) != 1) {
        return failure(errc::kRuntime, "P-256 verification failed");
    }
    if (EVP_DigestVerify(md.get(), der.data(), der.size(), uc(message.data()), message.size()) != 1) {
        ERR_clear_error();
        return fail(errc::kBadSignature, "the P-256 signature doesn't match", kWhere);
    }
    return {};
}

} // namespace Rhp::security::tls::detail

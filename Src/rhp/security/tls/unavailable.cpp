// The factories of the TLS backends this build doesn't have: they report kDisabled, so a config
// may still name them (and Rhp::security::tls::auto_backend never picks them).
#include <cstddef>
#include <memory>
#include <span>
#include <string_view>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/security/tls/mbedtls.hpp>
#include <rhp/security/tls/openssl.hpp>
#include <rhp/security/tls/p256.hpp>
#include <rhp/security/tls/tls.hpp>

namespace Rhp::security::tls {

#if !RHP_TLS_HAS_OPENSSL
result<std::shared_ptr<context>> openssl::server(const settings&) {
    return fail(errc::kDisabled, "built without OpenSSL", "tls");
}

result<std::shared_ptr<context>> openssl::client(const settings&) {
    return fail(errc::kDisabled, "built without OpenSSL", "tls");
}
#endif

#if !RHP_TLS_HAS_MBEDTLS
result<std::shared_ptr<context>> mbedtls::server(const settings&) {
    return fail(errc::kDisabled, "built without Mbed TLS", "tls");
}

result<std::shared_ptr<context>> mbedtls::client(const settings&) {
    return fail(errc::kDisabled, "built without Mbed TLS", "tls");
}
#endif

#if !RHP_TLS_HAS_OPENSSL && !RHP_TLS_HAS_MBEDTLS
// No backend for P-256 either (and none at all with RHP_ENABLE=OFF).
namespace detail {

std::string_view p256_backend() noexcept {
    return {};
}

result<p256_public_key> p256_public_from_private(std::span<const std::byte, kP256PrivateKeySize>) {
    return fail(errc::kDisabled, "P-256 needs a TLS backend (built without OpenSSL and Mbed TLS)", "tls");
}

result<p256_signature> p256_sign(std::span<const std::byte, kP256PrivateKeySize>, std::span<const std::byte>) {
    return fail(errc::kDisabled, "P-256 needs a TLS backend (built without OpenSSL and Mbed TLS)", "tls");
}

result<void> p256_verify(std::span<const std::byte, kP256PublicKeySize>, std::span<const std::byte>, std::span<const std::byte, kP256SignatureSize>) {
    return fail(errc::kDisabled, "P-256 needs a TLS backend (built without OpenSSL and Mbed TLS)", "tls");
}

} // namespace detail
#endif

} // namespace Rhp::security::tls

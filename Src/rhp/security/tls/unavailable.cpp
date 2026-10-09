// The factories of the TLS backends this build doesn't have: they report kDisabled, so a config
// may still name them (and Rhp::security::tls::auto_backend never picks them).
#include <memory>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/security/tls/mbedtls.hpp>
#include <rhp/security/tls/openssl.hpp>
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

} // namespace Rhp::security::tls

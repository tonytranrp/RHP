// RHP_ENABLE=OFF: Monocypher isn't fetched, so HTTP proofs can't be made or checked.
#include <rhp/security/http_auth.hpp>

namespace Rhp::security {

result<std::string> http_authorization(const psk_identity&, const http_proof&, std::chrono::system_clock::time_point) {
    return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "security.http");
}

result<http_grant> verify_http_authorization(const keyring&, const http_proof&, std::chrono::system_clock::time_point) {
    return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "security.http");
}

std::string http_answer_proof(const http_answer_key&, const http_answer&) {
    return {};
}

result<void> verify_http_answer(const psk_identity&, std::string_view, const http_answer&, std::string_view) {
    return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "security.http");
}

} // namespace Rhp::security

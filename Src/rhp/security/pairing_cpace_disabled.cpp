// RHP_ENABLE=OFF: Monocypher isn't fetched, so CPace reports kDisabled.
#include <array>
#include <cstddef>
#include <span>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/pairing_cpace.hpp>

namespace Rhp::security {

namespace {

constexpr const char* kCpaceWhere = "security.cpace";
constexpr const char* kDisabledMessage = "CPace needs RHP_ENABLE";

} // namespace

result<std::array<std::byte, cpace::kMessageSize>> cpace_generator(std::span<const std::byte>, std::span<const std::byte>, std::span<const std::byte>) {
    return fail(errc::kDisabled, kDisabledMessage, kCpaceWhere);
}

result<cpace> cpace::start(cpace_role, const cpace_inputs&) {
    return fail(errc::kDisabled, kDisabledMessage, kCpaceWhere);
}

result<cpace> cpace::start(cpace_role, const cpace_inputs&, std::span<const std::byte, kScalarSize>) {
    return fail(errc::kDisabled, kDisabledMessage, kCpaceWhere);
}

result<key> cpace::finish(std::span<const std::byte>, std::span<const std::byte>) {
    return fail(errc::kDisabled, kDisabledMessage, kCpaceWhere);
}

namespace detail {

result<std::array<std::byte, 32>> cpace_scalar_mult_vfy(std::span<const std::byte, 32>, std::span<const std::byte, 32>) {
    return fail(errc::kDisabled, kDisabledMessage, kCpaceWhere);
}

} // namespace detail

} // namespace Rhp::security

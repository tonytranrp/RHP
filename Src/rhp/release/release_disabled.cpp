// RHP_ENABLE=OFF: no hashing (Monocypher isn't fetched) and no script engine, so releases can be
// neither made, checked nor run. Manifests still encode and decode (manifest.cpp).
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/release/release.hpp>

namespace Rhp::release {

namespace {

error disabled(std::string_view where) {
    return make_error(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", std::string{where});
}

} // namespace

result<release> make_release(manifest, std::vector<std::string>) {
    return std::unexpected{disabled("release.make")};
}

result<void> sign(release&, const security::signing_key&) {
    return std::unexpected{disabled("release.sign")};
}

result<std::vector<std::byte>> encode_release(const release&) {
    return std::unexpected{disabled("release")};
}

result<release> decode_release(std::span<const std::byte>) {
    return std::unexpected{disabled("release")};
}

result<std::vector<std::byte>> encode_revocation_list(const revocation_list&) {
    return std::unexpected{disabled("release.revocations")};
}

result<revocation_list> decode_revocation_list(std::span<const std::byte>) {
    return std::unexpected{disabled("release.revocations")};
}

result<signed_revocations> make_revocations(revocation_list) {
    return std::unexpected{disabled("release.revocations")};
}

result<void> sign(signed_revocations&, const security::signing_key&) {
    return std::unexpected{disabled("release.revocations")};
}

result<std::vector<std::byte>> encode_revocations(const signed_revocations&) {
    return std::unexpected{disabled("release.revocations")};
}

result<signed_revocations> decode_revocations(std::span<const std::byte>) {
    return std::unexpected{disabled("release.revocations")};
}

std::optional<confirm_mode> parse_confirm_mode(std::string_view text) noexcept {
    for (const confirm_mode m : {confirm_mode::kNow, confirm_mode::kHealth, confirm_mode::kManual}) {
        if (to_string(m) == text) {
            return m;
        }
    }
    return std::nullopt;
}

namespace detail {

class manager_impl {
public:
    manager_options options;
};

} // namespace detail

manager::manager(trust, manager_options options, any_store) : impl_(std::make_unique<detail::manager_impl>()) {
    impl_->options = std::move(options);
}
manager::~manager() = default;
manager::manager(manager&&) noexcept = default;
manager& manager::operator=(manager&&) noexcept = default;

result<void> manager::install_lib(std::string_view, result<void> (*)(script::sandbox&)) {
    return std::unexpected{disabled("release.manager")};
}

result<restore_report> manager::restore() {
    return std::unexpected{disabled("release.manager")};
}

result<apply_result> manager::apply(std::span<const std::byte>, confirm_mode) {
    return std::unexpected{disabled("release.manager")};
}

result<void> manager::confirm(std::string_view) {
    return std::unexpected{disabled("release.manager")};
}

result<void> manager::deactivate(std::string_view, bool) {
    return std::unexpected{disabled("release.manager")};
}

result<std::size_t> manager::revoke(std::span<const std::byte>) {
    return std::unexpected{disabled("release.manager")};
}

std::vector<channel_status> manager::status() const {
    return {};
}

std::uint64_t manager::revocation_seq() const noexcept {
    return 0;
}

void manager::pump() {}

void manager::on_event(std::function<void(const release_event&)>) {}

script::sandbox* manager::sandbox(std::string_view) noexcept {
    return nullptr;
}

const manager_options& manager::options() const noexcept {
    return impl_->options;
}

} // namespace Rhp::release

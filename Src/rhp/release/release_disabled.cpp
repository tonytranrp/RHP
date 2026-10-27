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
#include <rhp/release/bytecode.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/release/release.hpp>

namespace Rhp::release {

namespace {

error disabled(std::string_view where) {
    return make_error(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", std::string{where});
}

} // namespace

security::digest256 compiled_build() {
    return {};
}

result<std::vector<std::byte>> seal_compiled(const compiled_release&, const security::key&) {
    return std::unexpected{disabled("release.bytecode")};
}

result<compiled_release> open_compiled(std::span<const std::byte>, const security::key&) {
    return std::unexpected{disabled("release.bytecode")};
}

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

result<release_id> manager::confirm(std::string_view, std::optional<release_id>) {
    return std::unexpected{disabled("release.manager")};
}

result<release_id> manager::deactivate(std::string_view, bool, std::optional<release_id>) {
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

const std::optional<restore_report>& manager::last_restore() const noexcept {
    static const std::optional<restore_report> kNone;
    return kNone;
}

void manager::pump() {}

Rhp::subscription manager::on_event(std::function<void(const release_event&)>) {
    return {};
}

script::sandbox* manager::sandbox(std::string_view) noexcept {
    return nullptr;
}

bytecode_stats manager::bytecode_cache_stats() const {
    return {};
}

const manager_options& manager::options() const noexcept {
    return impl_->options;
}

} // namespace Rhp::release

// RHP_ENABLE=0: the sandbox is an inert stub and no Lua is linked. Every operation reports
// errc::kDisabled; patch points compile to direct calls (see patch_point.hpp).

#include <cstddef>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include <rhp/script/sandbox.hpp>

namespace Rhp::script {

namespace detail {

class sandbox_impl {
public:
    explicit sandbox_impl(sandbox_options options) : options_(std::move(options)) {}

    sandbox_options options_;
    ledger effects_;
};

} // namespace detail

namespace {

std::unexpected<error> disabled() {
    return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)");
}

} // namespace

sandbox::sandbox(sandbox_options options) : impl_(std::make_unique<detail::sandbox_impl>(std::move(options))) {}
sandbox::~sandbox() = default;
sandbox::sandbox(sandbox&&) noexcept = default;
sandbox& sandbox::operator=(sandbox&&) noexcept = default;

result<void> sandbox::install_lib(std::string_view, c_function) {
    return disabled();
}

result<value_list> sandbox::exec(std::string_view, std::string_view) {
    return disabled();
}

result<module_id> sandbox::load(std::string_view, std::string_view) {
    return disabled();
}

result<value_list> sandbox::call(module_id, std::string_view, std::span<const value>) {
    return disabled();
}

result<revert_report> sandbox::revert(module_id) {
    return disabled();
}

result<revert_report> sandbox::unload(module_id) {
    return disabled();
}

result<void> sandbox::checkpoint(std::string_view) {
    return disabled();
}

result<revert_report> sandbox::revert_to(std::string_view) {
    return disabled();
}

revert_report sandbox::revert_all() {
    return {};
}

result<module_id> sandbox::find(std::string_view) const {
    return disabled();
}

std::optional<module_info> sandbox::status(module_id) const {
    return std::nullopt;
}

std::vector<module_info> sandbox::list() const {
    return {};
}

module_id sandbox::scratch_module() const noexcept {
    return {};
}

void sandbox::cancel() noexcept {}

void sandbox::pump() {}

role sandbox::caller_role() const noexcept {
    return impl_->options_.caller_role;
}

std::size_t sandbox::memory_used() const noexcept {
    return 0;
}

const ledger& sandbox::effects() const noexcept {
    return impl_->effects_;
}

} // namespace Rhp::script

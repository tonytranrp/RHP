// RHP_ENABLE=0: the sandbox is an inert stub and no Lua is linked. Every operation reports
// errc::kDisabled; patch points compile to direct calls (see patch_point.hpp).

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
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
    std::vector<value (*)(role)> apis_; // the libs' descriptions still work without Lua (sandbox::api)
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

result<void> sandbox::install_lib(std::string_view, c_function, stub_fn, detail::tunables_fn, api_fn api) {
    if (api != nullptr) {
        impl_->apis_.push_back(api);
    }
    return disabled();
}

result<value_list> sandbox::exec(std::string_view, std::string_view) {
    return disabled();
}

result<value_list> sandbox::exec_cached(std::string_view, std::string_view) {
    return disabled();
}

result<module_id> sandbox::load(std::string_view, std::string_view) {
    return disabled();
}

result<revision_id> sandbox::reload(module_id, std::string_view) {
    return disabled();
}

result<std::string> sandbox::compile_module(std::string_view, std::string_view) {
    return disabled();
}

result<module_id> sandbox::load(std::string_view, std::string_view, trusted_bytecode) {
    return disabled();
}

result<revision_id> sandbox::reload(module_id, std::string_view, trusted_bytecode) {
    return disabled();
}

std::string_view bytecode_build() {
    return {};
}

result<revision_id> sandbox::rollback(module_id, std::size_t) {
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

result<revert_report> sandbox::unload(module_id, force_t) {
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

void sandbox::cancel(request_id) noexcept {}

void sandbox::pump() {}

request_id sandbox::last_request() const noexcept {
    return {};
}

std::size_t sandbox::suspended() const noexcept {
    return 0;
}

bool sandbox::pending(request_id) const noexcept {
    return false;
}

std::uint64_t sandbox::frame() const noexcept {
    return 0;
}

role sandbox::caller_role() const noexcept {
    return impl_->options_.caller_role;
}

std::size_t sandbox::memory_used() const noexcept {
    return 0;
}

const ledger& sandbox::effects() const noexcept {
    return impl_->effects_;
}

value sandbox::api() const {
    value::array libs;
    for (const auto describe : impl_->apis_) {
        libs.push_back(describe(impl_->options_.caller_role));
    }
    value::map out;
    out.emplace_back(value{"libs"}, value{std::move(libs)});
    out.emplace_back(value{"events"}, value{value::array{}});
    out.emplace_back(value{"points"}, value{value::array{}});
    return value{std::move(out)};
}

std::string sandbox::stubs() const {
    return {};
}

Rhp::subscription sandbox::on_script_event(std::string_view, script_event_fn) {
    return {};
}

sandbox_stats sandbox::stats() const {
    return {};
}

async_leftovers sandbox::release_async() {
    return {};
}

async_leftovers::async_leftovers() = default;
async_leftovers::~async_leftovers() = default;
async_leftovers::async_leftovers(async_leftovers&&) noexcept = default;
async_leftovers& async_leftovers::operator=(async_leftovers&&) noexcept = default;

std::size_t async_leftovers::pump() {
    return 0;
}

void async_leftovers::close() noexcept {}

} // namespace Rhp::script

namespace Rhp::script {

result<std::vector<tunable_info>> sandbox::tunables(std::string_view) {
    return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "sandbox");
}

result<void> sandbox::tune(std::string_view, const value&) {
    return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "sandbox");
}

} // namespace Rhp::script

namespace Rhp::script {

result<std::vector<std::uint32_t>> sandbox::set_breakpoints(std::string_view, std::span<const std::uint32_t>) {
    return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "sandbox");
}

void sandbox::debug_pause() {}

void sandbox::debug_reset() {}

std::vector<debug_stop> sandbox::paused() const {
    return {};
}

result<void> sandbox::debug_resume(request_id, step_mode) {
    return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "sandbox");
}

result<std::vector<debug_frame>> sandbox::debug_stack(request_id) {
    return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "sandbox");
}

result<std::vector<debug_variable>> sandbox::debug_variables(request_id, std::uint32_t, debug_scope, std::span<const std::string>) {
    return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "sandbox");
}

result<debug_variable> sandbox::debug_evaluate(request_id, std::uint32_t, std::string_view) {
    return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "sandbox");
}

result<void> sandbox::start_profile(profile_options) {
    return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", "sandbox");
}

profile_report sandbox::profile() const {
    return {};
}

profile_report sandbox::stop_profile() {
    return {};
}

void sandbox::start_metering() {}

void sandbox::stop_metering() {}

run_meter sandbox::meter() {
    return {};
}

void sandbox::reset_peak() noexcept {}

result<void> sandbox::collect_garbage(int) {
    return disabled();
}

result<void> sandbox::set_gc_mode(gc_mode) {
    return disabled();
}

result<void> sandbox::start_coverage() {
    return disabled();
}

coverage_report sandbox::coverage() const {
    return {};
}

coverage_report sandbox::stop_coverage() {
    return {};
}

result<void> sandbox::enable_testing(testing_options) {
    return disabled();
}

std::optional<std::chrono::steady_clock::time_point> sandbox::next_due() const {
    return std::nullopt;
}

result<value_list> sandbox::call_point(std::string_view, std::span<const value>) {
    return disabled();
}

result<void> sandbox::fire_event(std::string_view, std::span<const value>) {
    return disabled();
}

} // namespace Rhp::script

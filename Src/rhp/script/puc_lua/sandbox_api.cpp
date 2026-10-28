// Rhp::script::sandbox: the public class, forwarding to sandbox_impl, and bytecode_build().

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <lauxlib.h>
#include <lua.h>

#include <rhp/script/puc_lua/sandbox_impl.hpp>
#include <rhp/script/sandbox.hpp>

namespace Rhp::script {

namespace detail {

namespace {

// A chunk exercising what bytecode encodes (integers, floats, strings, nested functions, upvalues,
// varargs, gotos, line info): its dump changes when the compiler or the dump format does.
constexpr std::string_view kProbeChunk = R"lua(local a, b, c = 1, 2.5, "probe"
local t = {a, b, c, x = -0.0, [3] = 0x7fffffffffffffff, 1e308, [[long
string]]}
local function f(n, ...)
    local s = 0
    for i = 1, n do
        s = s + i // 2 % 3
    end
    goto done
    ::done::
    return function(...) return s, t, select("#", ...), ... end
end
return f(10, a, b, c)
)lua";

// lua_pcall'd: compiles the probe chunk and dumps it into the std::string argument 1 points to.
int dump_probe(lua_State* L) {
    auto* out = static_cast<std::string*>(lua_touserdata(L, 1));
    if (luaL_loadbufferx(L, kProbeChunk.data(), kProbeChunk.size(), "=rhp.bytecode_build", "t") != LUA_OK) {
        return lua_error(L);
    }
    lua_dump(L, &dump_writer, out, 0);
    return 0;
}

std::string make_bytecode_build() {
    lua_State* L = luaL_newstate();
    if (L == nullptr) {
        return {};
    }
    std::string dumped;
    bool made = false;
    try {
        lua_pushcfunction(L, &dump_probe);
        lua_pushlightuserdata(L, &dumped);
        made = lua_pcall(L, 1, 0, 0) == LUA_OK && !dumped.empty();
    } catch (const std::exception&) { // out of memory while dumping
        made = false;
    }
    lua_close(L);
    return made ? std::format("rhp bytecode build: lua {}\n", LUA_VERSION_RELEASE_NUM) + dumped : std::string{};
}

} // namespace

} // namespace detail

// ---- sandbox (public) ------------------------------------------------------------------------------

sandbox::sandbox(sandbox_options options) : impl_(std::make_unique<detail::sandbox_impl>(std::move(options))) {}

sandbox::~sandbox() = default;
sandbox::sandbox(sandbox&&) noexcept = default;
sandbox& sandbox::operator=(sandbox&&) noexcept = default;

result<void> sandbox::install_lib(std::string_view name, c_function build, stub_fn describe, detail::tunables_fn collect, api_fn api,
                                  std::span<const detail::cap_ref> caps) {
    return impl_->install_lib(name, build, describe, collect, api, caps);
}

result<std::vector<tunable_info>> sandbox::tunables(std::string_view prefix) {
    return impl_->tunables(prefix);
}

result<void> sandbox::tune(std::string_view path, const value& v) {
    return impl_->tune(path, v);
}

result<std::vector<std::uint32_t>> sandbox::set_breakpoints(std::string_view source, std::span<const std::uint32_t> lines) {
    return impl_->set_breakpoints(source, lines);
}

void sandbox::debug_pause() {
    impl_->debug_pause();
}

void sandbox::debug_reset() {
    impl_->debug_reset();
}

std::vector<debug_stop> sandbox::paused() const {
    return impl_->paused();
}

result<void> sandbox::debug_resume(request_id request, step_mode mode) {
    return impl_->debug_resume(request, mode);
}

result<std::vector<debug_frame>> sandbox::debug_stack(request_id request) {
    return impl_->debug_stack(request);
}

result<std::vector<debug_variable>> sandbox::debug_variables(request_id request, std::uint32_t frame, debug_scope scope, std::span<const std::string> path) {
    return impl_->debug_variables(request, frame, scope, path);
}

result<debug_variable> sandbox::debug_evaluate(request_id request, std::uint32_t frame, std::string_view expression) {
    return impl_->debug_evaluate(request, frame, expression);
}

result<void> sandbox::start_profile(profile_options options) {
    return impl_->start_profile(options);
}

profile_report sandbox::profile() const {
    return impl_->profile();
}

profile_report sandbox::stop_profile() {
    return impl_->stop_profile();
}

void sandbox::start_metering() {
    impl_->start_metering();
}

void sandbox::stop_metering() {
    impl_->stop_metering();
}

run_meter sandbox::meter() {
    return impl_->meter();
}

void sandbox::reset_peak() noexcept {
    impl_->reset_peak();
}

result<void> sandbox::collect_garbage(int cycles) {
    return impl_->collect_garbage(cycles);
}

result<void> sandbox::set_gc_mode(gc_mode mode) {
    return impl_->set_gc_mode(mode);
}

result<void> sandbox::start_coverage() {
    return impl_->start_coverage();
}

coverage_report sandbox::coverage() const {
    return impl_->coverage();
}

coverage_report sandbox::stop_coverage() {
    return impl_->stop_coverage();
}

result<void> sandbox::enable_testing(testing_options options) {
    return impl_->enable_testing(std::move(options));
}

std::optional<std::chrono::steady_clock::time_point> sandbox::next_due() const {
    return impl_->next_due();
}

result<value_list> sandbox::call_point(std::string_view id, std::span<const value> args) {
    return impl_->call_point(id, args);
}

result<void> sandbox::fire_event(std::string_view name, std::span<const value> args) {
    return impl_->fire_event(name, args);
}

result<value_list> sandbox::exec(std::string_view source, std::string_view chunk_name) {
    return impl_->exec(source, chunk_name);
}

result<value_list> sandbox::exec_cached(std::string_view source, std::string_view chunk_name) {
    return impl_->exec(source, chunk_name, true);
}

result<module_id> sandbox::load(std::string_view name, std::string_view source) {
    return impl_->load(name, source);
}

result<revision_id> sandbox::reload(module_id mod, std::string_view source) {
    return impl_->reload(mod, source);
}

result<std::string> sandbox::compile_module(std::string_view name, std::string_view source) {
    return impl_->compile_module(name, source);
}

result<module_id> sandbox::load(std::string_view name, std::string_view source, trusted_bytecode code) {
    return impl_->load(name, source, code.bytes());
}

result<revision_id> sandbox::reload(module_id mod, std::string_view source, trusted_bytecode code) {
    return impl_->reload(mod, source, code.bytes());
}

result<revision_id> sandbox::rollback(module_id mod, std::size_t steps) {
    return impl_->rollback(mod, steps);
}

result<value_list> sandbox::call(module_id mod, std::string_view function, std::span<const value> args) {
    return impl_->call(mod, function, args);
}

result<revert_report> sandbox::revert(module_id mod) {
    return impl_->revert(mod);
}

result<revert_report> sandbox::unload(module_id mod) {
    return impl_->unload(mod, false);
}

result<revert_report> sandbox::unload(module_id mod, force_t) {
    return impl_->unload(mod, true);
}

result<void> sandbox::checkpoint(std::string_view tag) {
    return impl_->checkpoint(tag);
}

result<revert_report> sandbox::revert_to(std::string_view tag) {
    return impl_->revert_to(tag);
}

revert_report sandbox::revert_all() {
    return impl_->revert_all();
}

void sandbox::restore_builtins() {
    impl_->restore_shared_tables();
}

result<module_id> sandbox::find(std::string_view name) const {
    return impl_->find(name);
}

std::optional<module_info> sandbox::status(module_id mod) const {
    return impl_->status(mod);
}

std::vector<module_info> sandbox::list() const {
    return impl_->list();
}

module_id sandbox::scratch_module() const noexcept {
    return impl_->scratch_module();
}

void sandbox::cancel() noexcept {
    impl_->cancel();
}

void sandbox::cancel(request_id request) noexcept {
    impl_->cancel(request);
}

void sandbox::pump() {
    impl_->pump();
}

result<bool> sandbox::collect_idle(std::chrono::microseconds budget) {
    return impl_->collect_idle(budget);
}

request_id sandbox::last_request() const noexcept {
    return impl_->last_request();
}

std::size_t sandbox::suspended() const noexcept {
    return impl_->suspended();
}

bool sandbox::pending(request_id request) const noexcept {
    return impl_->live(request);
}

std::uint64_t sandbox::frame() const noexcept {
    return impl_->frame();
}

role sandbox::caller_role() const noexcept {
    return impl_->caller_role();
}

std::size_t sandbox::memory_used() const noexcept {
    return impl_->memory_used();
}

const ledger& sandbox::effects() const noexcept {
    return impl_->effects();
}

value sandbox::api() const {
    return impl_->api();
}

std::string sandbox::stubs() const {
    return impl_->stubs();
}

Rhp::subscription sandbox::on_script_event(std::string_view name, script_event_fn fn) {
    return impl_->on_script_event(name, std::move(fn));
}

sandbox_stats sandbox::stats() const {
    sandbox_stats s = impl_->stats();
    s.bytecode_loaded = impl_->bytecode_loaded();
    s.bytecode_rejected = impl_->bytecode_rejected();
    return s;
}

std::string_view bytecode_build() {
    static const std::string build = detail::make_bytecode_build();
    return build;
}

async_leftovers sandbox::release_async() {
    return impl_->release_async();
}

} // namespace Rhp::script

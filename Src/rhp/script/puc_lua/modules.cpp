// Modules and the operations on them: compiling (the trusted bytecode cache), exec, load, reload,
// rollback, call (and its unprotected path), faults, revert, unload, checkpoints, status and stubs.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <lauxlib.h>
#include <lua.h>

#include <rhp/core/error.hpp>
#include <rhp/script/puc_lua/sandbox_impl.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/script/stack.hpp>
#include <rhp/script/stubs.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/utils/crc32c.hpp>
#include <rhp/utils/fixed_string.hpp>

namespace Rhp::script::detail {

namespace {

// The most arguments a call without the protected setup takes (a pooled coroutine has room for
// them without growing its stack).
constexpr std::size_t kUnprotectedArgs = 8;

std::uint32_t source_hash(std::string_view source) noexcept {
    return utils::crc32c(utils::as_bytes(source));
}

// Nil, booleans and numbers: values that cross between C++ and Lua without an allocation.
bool is_scalar(int lua_type_id) noexcept {
    return lua_type_id == LUA_TNIL || lua_type_id == LUA_TBOOLEAN || lua_type_id == LUA_TNUMBER;
}

bool is_scalar(const value& v) noexcept {
    const value::kind k = v.type();
    return k == value::kind::kNil || k == value::kind::kBool || k == value::kind::kInteger || k == value::kind::kNumber;
}

// What revert, unload, revert_to and revert_all return when a run is active: they happen when it ends.
revert_report deferred_report() {
    revert_report report;
    report.deferred = true;
    return report;
}

// A module name is dotted lowercase.
result<void> check_module_name(std::string_view name) {
    if (!utils::is_dotted_name(name)) {
        return fail(errc::kInvalidArgument, std::format("'{}' is not a module name (dotted lowercase, e.g. combat.low_grav)", name));
    }
    return {};
}

// take_lua_error for a chunk Lua couldn't load: what isn't a memory error is a compile error.
error compile_error(lua_State* L, int status) {
    error err = take_lua_error(L, status);
    if (err.code == errc::kRuntime) {
        err.code = errc::kCompile;
    }
    return err;
}

// Bytecode of trusted chunks (the test framework), compiled once per process: a sandbox per test
// file would otherwise parse the same 100 KB of Lua every time. Keyed by chunk name and source; the
// bytecode keeps its debug information (lines for errors and coverage).
class bytecode_cache {
public:
    // The bytecode of (name, source), or empty when it isn't cached yet.
    std::string find(std::string_view name, std::string_view source) {
        const std::scoped_lock lock{mutex_};
        const auto it = cache_.find(key(name, source));
        return it != cache_.end() ? it->second : std::string{};
    }

    void store(std::string_view name, std::string_view source, std::string bytecode) {
        const std::scoped_lock lock{mutex_};
        // Bounded: a long-lived process running edited sources again and again starts over.
        bytes_ += name.size() + source.size() + bytecode.size();
        if (bytes_ > kMaxBytes) {
            cache_.clear();
            bytes_ = name.size() + source.size() + bytecode.size();
        }
        cache_.insert_or_assign(key(name, source), std::move(bytecode));
    }

private:
    static std::string key(std::string_view name, std::string_view source) {
        std::string k;
        k.reserve(name.size() + 1 + source.size());
        k.append(name).push_back('\0');
        k.append(source);
        return k;
    }

    static constexpr std::size_t kMaxBytes = 64u * 1024u * 1024u;

    std::mutex mutex_;
    std::unordered_map<std::string, std::string> cache_;
    std::size_t bytes_ = 0;
};

bytecode_cache& exec_bytecode() {
    static bytecode_cache cache;
    return cache;
}

// Pushes the function of trusted bytecode compiled as `chunk_name`; false (nothing pushed) when Lua
// refuses it (another Lua build, truncated, text) or it isn't a main chunk compiled under that name
// (one upvalue, _ENV; vararg; no parameters).
bool load_bytecode(lua_State* L, std::string_view bytecode, const std::string& chunk_name) {
    if (luaL_loadbufferx(L, bytecode.data(), bytecode.size(), chunk_name.c_str(), "b") != LUA_OK) {
        lua_pop(L, 1); // the error
        return false;
    }
    lua_Debug ar{};
    lua_pushvalue(L, -1);
    lua_getinfo(L, ">Su", &ar);
    if (ar.source == nullptr || std::string_view{ar.source, ar.srclen} != chunk_name || ar.nups != 1 || ar.nparams != 0 || ar.isvararg == 0) {
        lua_pop(L, 1);
        return false;
    }
    return true;
}

} // namespace

int dump_writer(lua_State*, const void* p, size_t size, void* out) {
    if (p != nullptr) {
        static_cast<std::string*>(out)->append(static_cast<const char*>(p), size);
    }
    return 0;
}

// ---- compiling ----------------------------------------------------------------------------------

result<void> sandbox_impl::compile(std::string_view source, const std::string& chunk_name, int env_ref, bool cached, std::string_view trusted) {
    lua_State* L = state_;
    bool from_trusted = false;
    if (!trusted.empty()) {
        from_trusted = load_bytecode(L, trusted, chunk_name);
        ++(from_trusted ? bytecode_loaded_ : bytecode_rejected_);
    }
    if (!from_trusted) {
        std::string bytecode = cached ? exec_bytecode().find(chunk_name, source) : std::string{};
        const int status = bytecode.empty() ? luaL_loadbufferx(L, source.data(), source.size(), chunk_name.c_str(), "t")
                                            : luaL_loadbufferx(L, bytecode.data(), bytecode.size(), chunk_name.c_str(), "b");
        if (status == LUA_OK && cached && bytecode.empty()) {
            std::string dumped;
            if (lua_dump(L, &dump_writer, &dumped, 0) == 0 && !dumped.empty()) {
                exec_bytecode().store(chunk_name, source, std::move(dumped));
            }
        }
        if (status != LUA_OK) {
            return std::unexpected{compile_error(L, status)};
        }
    }
    lua_rawgeti(L, LUA_REGISTRYINDEX, env_ref);
    lua_setupvalue(L, -2, 1); // a main chunk's first upvalue is _ENV
    if (coverage_) {
        coverage_compiled(L, without_chunk_marker(chunk_name));
    }
    return {};
}

// ---- a reload's swap ------------------------------------------------------------------------------

result<value_list> sandbox_impl::complete_load(module_record& mod, revision_id revision, lua_State* thread) {
    // on_save / on_restore of a reload that pump() completed still belong to the reload: checked.
    const operation_scope checked{*this};
    lua_State* L = state_;
    lua_xmove(thread, L, 1); // the exports table the loader returned
    if (mod.state == module_state::kLoading && mod.live.revision == revision) {
        mod.live.exports_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        mod.state = module_state::kActive;
        return value_list{};
    }
    if (!mod.pending || mod.pending->revision != revision) {
        lua_pop(L, 1);
        return fail(errc::kCancelled, "the reload was superseded");
    }
    mod.pending->exports_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // Carry state over: new.on_restore(old.on_save()).
    const effect_owner old_owner{mod.id, mod.live.revision};
    const effect_owner new_owner{mod.id, revision};
    const int base = lua_gettop(L);
    lua_pushnil(L); // the saved state
    if (mod.state == module_state::kActive && mod.live.exports_ref != kNoRef && push_export(mod.live.exports_ref, "on_save")) {
        if (auto saved = call_sync(old_owner, 0, 1); !saved) {
            lua_settop(L, base);
            saved.error().where = std::format("{}.on_save", mod.name);
            return std::unexpected{std::move(saved).error()};
        }
        lua_replace(L, base + 1);
    }
    if (push_export(mod.pending->exports_ref, "on_restore")) {
        lua_pushvalue(L, base + 1);
        if (auto restored = call_sync(new_owner, 1, 0); !restored) {
            lua_settop(L, base);
            restored.error().where = std::format("{}.on_restore", mod.name);
            return std::unexpected{std::move(restored).error()};
        }
    }
    lua_settop(L, base);

    // Swap: the old revision goes, the new one is live.
    const revision_id old_revision = mod.live.revision;
    abandon_requests([&](const request_record& r) { return r.owner.module == mod.id && r.owner.revision == old_revision; },
                     "its module revision was replaced by a reload");
    (void)ledger_.revert_revision(mod.id, old_revision);
    release(mod.live);
    mod.live = std::move(*mod.pending);
    mod.pending.reset();
    if (mod.pending_source) {
        mod.history.push_back(std::move(*mod.pending_source));
        mod.pending_source.reset();
    }
    while (mod.history.size() > std::max<std::size_t>(options_.limits.revisions, 1)) {
        mod.history.pop_front();
    }
    mod.state = module_state::kActive;
    mod.fault.reset();
    return value_list{};
}

bool sandbox_impl::push_export(int exports_ref, const char* name) {
    lua_State* L = state_;
    lua_rawgeti(L, LUA_REGISTRYINDEX, exports_ref);
    lua_getfield(L, -1, name);
    lua_remove(L, -2);
    if (lua_type(L, -1) == LUA_TFUNCTION) {
        return true;
    }
    lua_pop(L, 1);
    return false;
}

// ---- faults --------------------------------------------------------------------------------------

void sandbox_impl::fault_or_defer(const effect_owner& owner, error err) {
    if (running_.empty()) {
        fault(owner, std::move(err));
    } else {
        pending_faults_.emplace_back(owner, std::move(err));
    }
}

void sandbox_impl::fault(const effect_owner& owner, error err) {
    module_record* mod = record(owner.module);
    if (mod == nullptr) {
        return;
    }
    if (mod->scratch) {
        // Scratch code faults only its own request's effects (earlier exec effects stay).
        if (owner.request) {
            abandon_requests([&](const request_record& r) { return r.id == owner.request; }, std::format("the script faulted: {}", err));
            (void)ledger_.revert_request(scratch_, owner.request);
        } else {
            (void)ledger_.revert(scratch_);
        }
        return;
    }
    if (mod->pending && owner.revision == mod->pending->revision) {
        abort_reload(*mod); // a fault of the incoming revision fails the reload; the live one stays
        return;
    }
    if (owner.revision && owner.revision != mod->live.revision) {
        return; // a revision that was already replaced
    }
    if (mod->state != module_state::kActive && mod->state != module_state::kLoading) {
        return;
    }
    abandon_requests([&](const request_record& r) { return r.owner.module == mod->id; }, "its module faulted");
    abort_reload(*mod);
    auto report = ledger_.revert(mod->id);
    if (!report.clean()) {
        err.message += std::format(" (revert left {} effect(s) in place)", report.failures.size());
    }
    mod->state = module_state::kFaulted;
    mod->fault = std::move(err);
}

void sandbox_impl::abort_reload(module_record& mod) noexcept {
    if (!mod.pending) {
        return;
    }
    const revision_id revision = mod.pending->revision;
    try {
        abandon_requests([&](const request_record& r) { return r.owner.module == mod.id && r.owner.revision == revision; },
                         "the reload was abandoned");
        (void)ledger_.revert_revision(mod.id, revision);
    } catch (...) { // out of memory while reporting: the revision's effects are still owned by the ledger
    }
    release(*mod.pending);
    mod.pending.reset();
    mod.pending_source.reset();
}

void sandbox_impl::release(module_instance& instance) noexcept {
    luaL_unref(state_, LUA_REGISTRYINDEX, instance.exports_ref);
    luaL_unref(state_, LUA_REGISTRYINDEX, instance.env_ref);
    instance.exports_ref = kNoRef;
    instance.env_ref = kNoRef;
}

// ---- operations ----------------------------------------------------------------------------------

result<void> sandbox_impl::install_lib(std::string_view name, c_function build, std::string (*describe)(role), tunables_fn collect, value (*api)(role)) {
    drain();
    result<void> out{};
    auto glue = protect(state_, [&] {
        lua_State* L = state_;
        lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS);
        stack{L}.push_string(name);
        if (lua_rawget(L, -2) != LUA_TNIL) {
            out = fail(errc::kAlreadyLoaded, std::format("the global '{}' already exists", name), std::string{name});
            lua_pop(L, 2);
            return;
        }
        lua_pop(L, 1);
        lua_pushcfunction(L, build);
        lua_call(L, 0, 1);
        stack{L}.set_field(-2, name);
        lua_pop(L, 1);
    });
    if (!glue) {
        return std::unexpected{std::move(glue).error()};
    }
    if (out) {
        describers_.push_back(describe);
        api_describers_.push_back(api);
        collect(tunables_);
    }
    return out;
}

result<value_list> sandbox_impl::exec(std::string_view source, std::string_view chunk_name, bool cached) {
    const operation_scope operation{*this};
    drain();
    std::string chunk;
    chunk.reserve(chunk_name.size() + 1);
    chunk.push_back('=');
    chunk.append(chunk_name);
    result<value_list> out = value_list{};
    auto glue = protect(state_, [&] {
        const slice_scope slice{*this};
        if (auto compiled = compile(source, chunk, record(scratch_)->live.env_ref, cached); !compiled) {
            out = std::unexpected{std::move(compiled).error()};
            return;
        }
        request_record& req = start_request(request_kind::kExec, effect_owner{scratch_}, {}, 0, true);
        if (auto done = step(req, 0)) {
            out = std::move(*done);
        }
    });
    if (!glue) {
        out = std::unexpected{std::move(glue).error()};
    }
    drain();
    return out;
}

result<std::string> sandbox_impl::compile_module(std::string_view name, std::string_view source) {
    if (auto named = check_module_name(name); !named) {
        return std::unexpected{std::move(named).error()};
    }
    const std::string chunk = std::format("@{}", name);
    result<std::string> out = std::string{};
    auto glue = protect(state_, [&] {
        lua_State* L = state_;
        const int status = luaL_loadbufferx(L, source.data(), source.size(), chunk.c_str(), "t");
        if (status != LUA_OK) {
            out = std::unexpected{compile_error(L, status)};
            return;
        }
        std::string dumped;
        if (lua_dump(L, &dump_writer, &dumped, 0) != 0 || dumped.empty()) {
            out = fail(errc::kRuntime, "the compiled chunk couldn't be dumped");
        } else {
            out = std::move(dumped);
        }
        lua_pop(L, 1);
    });
    if (!glue) {
        out = std::unexpected{std::move(glue).error()};
    }
    if (!out && out.error().where.empty()) {
        out.error().where = std::string{name};
    }
    return out;
}

result<module_id> sandbox_impl::load(std::string_view name, std::string_view source, std::string_view bytecode) {
    const operation_scope operation{*this};
    drain();
    if (auto named = check_module_name(name); !named) {
        return std::unexpected{std::move(named).error()};
    }
    if (const auto existing = find(name)) {
        auto reloaded = reload(*existing, source, bytecode);
        if (!reloaded) {
            return std::unexpected{std::move(reloaded).error()};
        }
        return *existing;
    }
    const module_id id = ids_.next();
    {
        module_record mod;
        mod.id = id;
        mod.name = std::string{name};
        mod.state = module_state::kLoading;
        mod.revisions_made = 1;
        mod.live.revision = revision_id{1};
        mod.history.push_back(revision_source{revision_id{1}, std::string{source}, source_hash(source)});
        modules_.emplace(id, std::move(mod));
    }

    const std::string chunk = std::format("@{}", name);
    bool compiled_ok = false;
    std::optional<error> failure;
    auto glue = protect(state_, [&] {
        lua_State* L = state_;
        const slice_scope slice{*this};
        module_record& mod = *record(id);
        mod.live.env_ref = new_environment();
        if (auto compiled = compile(source, chunk, mod.live.env_ref, false, bytecode); !compiled) {
            failure = std::move(compiled).error();
            return;
        }
        compiled_ok = true;
        lua_rawgeti(L, LUA_REGISTRYINDEX, loader_ref_);
        lua_insert(L, -2);
        lua_rawgeti(L, LUA_REGISTRYINDEX, mod.live.env_ref);
        request_record& req = start_request(request_kind::kLoad, effect_owner{id, mod.live.revision}, mod.name, 2, true);
        if (auto done = step(req, 2); done && !*done) {
            failure = std::move(*done).error();
        }
    });
    if (!glue && !failure) {
        failure = std::move(glue).error();
        if (compiled_ok) {
            fault_or_defer(effect_owner{id, revision_id{1}}, *failure);
        }
    }
    if (failure && !compiled_ok) {
        if (module_record* mod = record(id)) {
            release(mod->live);
        }
        modules_.erase(id);
    }
    drain();
    if (failure) {
        if (failure->where.empty()) {
            failure->where = std::string{name};
        }
        return std::unexpected{std::move(*failure)};
    }
    return id;
}

result<revision_id> sandbox_impl::reload(module_id id, std::string_view source, std::string_view bytecode) {
    const operation_scope operation{*this};
    const module_record* found = record(id);
    if (found == nullptr || found->scratch) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (defer_if_running([this, id, src = std::string{source}] { (void)reload(id, src); })) { // parses: the bytecode's view won't live that long
        return revision_id{};
    }
    drain();
    module_record* mod = record(id);
    if (mod == nullptr) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (mod->state == module_state::kLoading) {
        return fail(errc::kInvalidArgument, std::format("module '{}' is still loading", mod->name), mod->name);
    }
    if (mod->pending) {
        return fail(errc::kInvalidArgument, std::format("a reload of module '{}' is already loading", mod->name), mod->name);
    }
    const revision_id revision{++mod->revisions_made};
    const std::string chunk = std::format("@{}", mod->name);
    result<revision_id> out = revision;
    auto glue = protect(state_, [&] {
        lua_State* L = state_;
        const slice_scope slice{*this};
        mod->pending = module_instance{revision};
        mod->pending_source = revision_source{revision, std::string{source}, source_hash(source)};
        mod->pending->env_ref = new_environment();
        if (auto compiled = compile(source, chunk, mod->pending->env_ref, false, bytecode); !compiled) {
            out = std::unexpected{std::move(compiled).error()};
            return;
        }
        lua_rawgeti(L, LUA_REGISTRYINDEX, loader_ref_);
        lua_insert(L, -2);
        lua_rawgeti(L, LUA_REGISTRYINDEX, mod->pending->env_ref);
        request_record& req = start_request(request_kind::kLoad, effect_owner{id, revision}, mod->name, 2, true);
        if (auto done = step(req, 2)) {
            if (!*done) {
                out = std::unexpected{std::move(*done).error()};
            }
        } else {
            out = revision_id{}; // still loading: the swap happens in a later pump()
        }
    });
    if (!glue) {
        out = std::unexpected{std::move(glue).error()};
    }
    if (!out) {
        if (module_record* still = record(id); still != nullptr && still->pending && still->pending->revision == revision) {
            abort_reload(*still);
        }
        if (out.error().where.empty()) {
            out.error().where = std::string{record(id) != nullptr ? record(id)->name : std::string{}};
        }
    }
    drain();
    return out;
}

result<revision_id> sandbox_impl::rollback(module_id id, std::size_t steps) {
    const module_record* mod = record(id);
    if (mod == nullptr || mod->scratch) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (steps == 0 || steps >= mod->history.size()) {
        return fail(errc::kOutOfRange, std::format("module '{}' keeps {} revision(s); can't go back {}", mod->name, mod->history.size(), steps),
                    mod->name);
    }
    const std::string source = mod->history[mod->history.size() - 1 - steps].source;
    return reload(id, source);
}

result<value_list> sandbox_impl::call(module_id id, std::string_view function, std::span<const value> args) {
    const operation_scope operation{*this};
    drain();
    module_record* mod = record(id);
    if (mod == nullptr || mod->scratch) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (mod->state != module_state::kActive) {
        return fail(errc::kInvalidArgument, std::format("module '{}' is {}", mod->name, mod->state), mod->name);
    }
    if (auto quick = call_unprotected(*mod, function, args)) {
        drain();
        return std::move(*quick);
    }
    result<value_list> out = value_list{};
    auto glue = protect(state_, [&] {
        lua_State* L = state_;
        const slice_scope slice{*this};
        const int base = lua_gettop(L);
        lua_rawgeti(L, LUA_REGISTRYINDEX, mod->live.exports_ref);
        stack{L}.push_string(function);
        lua_gettable(L, -2);
        lua_remove(L, -2);
        if (lua_type(L, -1) != LUA_TFUNCTION) {
            out = fail(errc::kNotFound, std::format("module '{}' exports no function '{}'", mod->name, function), mod->name);
            lua_settop(L, base);
            return;
        }
        remember_call_key(function); // its next call can look it up unprotected
        luaL_checkstack(L, static_cast<int>(args.size()) + 2, "rhp: too many arguments");
        for (const auto& arg : args) {
            stack{L}.push_value(arg);
        }
        request_record& req = start_request(request_kind::kCall, effect_owner{id, mod->live.revision}, mod->name, static_cast<int>(args.size()), true);
        req.label.push_back('.'); // "module.function", built in the pooled record's string: no allocation once warm
        req.label.append(function);
        if (auto done = step(req, static_cast<int>(args.size()))) {
            out = std::move(*done);
        }
    });
    if (!glue) {
        out = std::unexpected{std::move(glue).error()};
    }
    drain();
    return out;
}

// What makes this safe outside a protected run: before lua_resume nothing allocates (the name is an
// interned key pinned in the registry, the exports table has no metatable so no __index runs, the
// arguments are scalars pushed into room checked first, a spare record and coroutine are at hand and
// every C++ container used has capacity), and lua_resume is a protected call itself. After it, only a
// normal return with scalar results is completed here (no Lua allocation; the result vector is
// reserved first); an error, a stop, a suspension or other results finish inside a protected run.
std::optional<result<value_list>> sandbox_impl::call_unprotected(module_record& mod, std::string_view function, std::span<const value> args) {
    lua_State* L = state_;
    const int nargs = static_cast<int>(args.size());
    if (args.size() > kUnprotectedArgs || spare_requests_.empty() || spare_threads_.empty() || unlisted_.size() == unlisted_.capacity() ||
        running_.size() == running_.capacity() || cancel_ids_pending_.load(std::memory_order_acquire) ||
        spare_requests_.back().mapped()->label.capacity() < mod.name.size() + 1 + function.size() ||
        !std::ranges::all_of(args, [](const value& v) { return is_scalar(v); })) {
        return std::nullopt;
    }
    const int key = call_key(function);
    if (key == kNoRef || lua_checkstack(L, nargs + 8) == 0) {
        return std::nullopt;
    }
    const int base = lua_gettop(L);
    lua_rawgeti(L, LUA_REGISTRYINDEX, mod.live.exports_ref);
    if (lua_type(L, -1) != LUA_TTABLE || lua_getmetatable(L, -1) != 0) {
        lua_settop(L, base);
        return std::nullopt;
    }
    lua_rawgeti(L, LUA_REGISTRYINDEX, key);
    lua_rawget(L, -2);
    lua_remove(L, -2);
    if (lua_type(L, -1) != LUA_TFUNCTION) {
        lua_settop(L, base);
        return std::nullopt; // the protected path reports it
    }
    for (const value& arg : args) {
        push_scalar(L, arg);
    }

    const slice_scope slice{*this};
    request_record& req = start_request(request_kind::kCall, effect_owner{mod.id, mod.live.revision}, mod.name, nargs, true);
    req.label.push_back('.'); // within the capacity checked above
    req.label.append(function);
    std::optional<result<value_list>> done;
    int status = LUA_OK;
    int nresults = 0;
    // From here an unusual case finishes protected: `stage` says what is left to do.
    enum class stage : std::uint8_t {
        kStep,   // not started: a start error, or a cancel queued meanwhile (step decides)
        kFinish, // resumed: finish_step decides
        kDone
    } left = stage::kStep;
    if (!req.start_error && !cancel_ids_pending_.load(std::memory_order_acquire)) {
        status = resume_request(req, nargs, nresults);
        left = stage::kFinish;
        if (status == LUA_OK && req.budget.sticky == sticky_stop::kNone) {
            bool scalars = true;
            for (int i = 1; i <= nresults && scalars; ++i) {
                scalars = is_scalar(lua_type(req.thread, i));
            }
            value_list values;
            if (scalars) {
                try {
                    values.reserve(static_cast<std::size_t>(nresults));
                } catch (const std::bad_alloc&) { // no Lua call in this try: completed protected below
                    scalars = false;
                }
            }
            if (scalars) {
                for (int i = 1; i <= nresults; ++i) {
                    (void)append_scalar(values, req.thread, i);
                }
                done = complete(req, nresults, nullptr, &values);
                left = stage::kDone;
            }
        }
    }
    if (left != stage::kDone) {
        auto glue = protect(L, [&] {
            if (left == stage::kStep) {
                done = step(req, nargs);
            } else {
                done = finish_step(req, status, nresults, nullptr);
            }
        });
        if (!glue) {
            done = std::unexpected{std::move(glue).error()};
            release_kept(req); // a record the failed run never got to (compares addresses only)
        }
    }
    if (!done) {
        return result<value_list>{value_list{}}; // suspended: on_result reports it
    }
    return std::move(*done);
}

int sandbox_impl::call_key(std::string_view function) const noexcept {
    for (const auto& [name, ref] : call_keys_) {
        if (name == function) {
            return ref;
        }
    }
    return kNoRef;
}

void sandbox_impl::remember_call_key(std::string_view function) {
    if (call_key(function) != kNoRef) {
        return;
    }
    std::string name;
    try {
        name.assign(function);
    } catch (const std::bad_alloc&) { // no Lua call in this try: the call just isn't remembered
        return;
    }
    stack{state_}.push_string(function); // the caller runs protected
    const int ref = luaL_ref(state_, LUA_REGISTRYINDEX);
    if (call_keys_.size() < kCallKeys) {
        call_keys_.emplace_back(std::move(name), ref); // reserved in the constructor: no allocation
        return;
    }
    auto& slot = call_keys_[call_keys_next_];
    call_keys_next_ = (call_keys_next_ + 1) % kCallKeys;
    luaL_unref(state_, LUA_REGISTRYINDEX, slot.second);
    slot = {std::move(name), ref};
}

revert_report sandbox_impl::revert_module(module_record& mod) {
    abandon_requests([&](const request_record& r) { return r.owner.module == mod.id; }, "its module was reverted");
    abort_reload(mod);
    auto report = ledger_.revert(mod.id);
    if (!mod.scratch && (mod.state == module_state::kActive || mod.state == module_state::kLoading)) {
        mod.state = module_state::kReverted;
    }
    return report;
}

result<revert_report> sandbox_impl::revert(module_id id) {
    if (record(id) == nullptr) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (defer_if_running([this, id] {
            if (module_record* mod = record(id)) {
                (void)revert_module(*mod);
            }
        })) {
        return deferred_report();
    }
    drain();
    module_record* mod = record(id);
    if (mod == nullptr) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    auto report = revert_module(*mod);
    drain();
    return report;
}

revert_report sandbox_impl::unload_module(module_record& mod) {
    if (mod.state == module_state::kActive && mod.live.exports_ref != kNoRef) {
        // on_unload errors are ignored: the module is going away regardless.
        (void)protect(state_, [&] {
            lua_State* L = state_;
            const int base = lua_gettop(L);
            if (push_export(mod.live.exports_ref, "on_unload")) {
                (void)call_sync(effect_owner{mod.id, mod.live.revision}, 0, 0);
            }
            lua_settop(L, base);
        });
    }
    auto report = revert_module(mod);
    const module_id id = mod.id;
    release(mod.live);
    forget_proxy(id);
    for (auto& [other_id, other] : modules_) {
        other.live.dependencies.erase(id);
        if (other.pending) {
            other.pending->dependencies.erase(id);
        }
    }
    modules_.erase(id);
    return report;
}

result<revert_report> sandbox_impl::unload(module_id id, bool forced) {
    const operation_scope operation{*this};
    const module_record* found = record(id);
    if (found == nullptr) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    if (found->scratch) {
        return fail(errc::kInvalidArgument, "the scratch module can't be unloaded; revert it instead", found->name);
    }
    if (!forced) {
        if (const auto dependents = dependents_of(id); !dependents.empty()) {
            std::string names;
            for (const auto& name : dependents) {
                names += names.empty() ? name : ", " + name;
            }
            return fail(errc::kHasDependents, std::format("module '{}' is required by {} (unload them first, or force)", found->name, names),
                        found->name);
        }
    }
    if (defer_if_running([this, id] {
            if (module_record* mod = record(id)) {
                (void)unload_module(*mod);
            }
        })) {
        return deferred_report();
    }
    drain();
    module_record* mod = record(id);
    if (mod == nullptr) {
        return fail(errc::kNotFound, std::format("no module with id {}", id));
    }
    auto report = unload_module(*mod);
    drain();
    return report;
}

result<void> sandbox_impl::checkpoint(std::string_view tag) {
    checkpoints_.insert_or_assign(std::string{tag}, ledger::mark());
    return {};
}

result<revert_report> sandbox_impl::revert_to(std::string_view tag) {
    const auto it = checkpoints_.find(tag);
    if (it == checkpoints_.end()) {
        return fail(errc::kNotFound, std::format("no checkpoint '{}'", tag));
    }
    const std::uint64_t mark = it->second;
    const auto apply = [this, mark] {
        auto report = ledger_.revert_after(mark);
        std::erase_if(checkpoints_, [mark](const auto& entry) { return entry.second > mark; });
        return report;
    };
    if (defer_if_running([apply] { (void)apply(); })) {
        return deferred_report();
    }
    drain();
    auto report = apply();
    drain();
    return report;
}

void sandbox_impl::restore_shared_tables() {
    if (!defer_if_running([this] { restore_builtins(); })) {
        restore_builtins();
    }
}

revert_report sandbox_impl::revert_all() {
    const operation_scope operation{*this};
    const auto apply = [this] {
        revert_report report;
        std::vector<module_id> ids;
        for (const auto& [id, mod] : modules_) {
            if (!mod.scratch) {
                ids.push_back(id);
            }
        }
        for (auto it = ids.rbegin(); it != ids.rend(); ++it) {
            if (module_record* mod = record(*it)) {
                report += unload_module(*mod);
            }
        }
        report += revert_module(*record(scratch_));
        restore_builtins(); // the identity leaves no changed string, table, ... behind
        return report;
    };
    if (defer_if_running([apply] { (void)apply(); })) {
        return deferred_report();
    }
    drain();
    auto report = apply();
    drain();
    return report;
}

result<module_id> sandbox_impl::find(std::string_view name) const {
    for (const auto& [id, mod] : modules_) {
        if (!mod.scratch && mod.name == name) {
            return id;
        }
    }
    return fail(errc::kNotFound, std::format("no module '{}'", name));
}

std::optional<module_info> sandbox_impl::status(module_id id) const {
    const module_record* mod = record(id);
    if (mod == nullptr) {
        return std::nullopt;
    }
    module_info info{mod->id, mod->name, mod->state, mod->scratch, ledger_.count(id), ledger_.irreversible_count(id), mod->fault};
    info.revision = mod->live.revision;
    info.source_hash = mod->history.empty() ? 0 : mod->history.back().hash;
    info.revisions = mod->history.size();
    info.reloading = mod->pending.has_value();
    info.dependencies.assign(mod->live.dependencies.begin(), mod->live.dependencies.end());
    return info;
}

std::vector<module_info> sandbox_impl::list() const {
    std::vector<module_info> out;
    out.reserve(modules_.size());
    for (const auto& [id, mod] : modules_) {
        out.push_back(*status(id));
    }
    return out;
}

std::string sandbox_impl::stubs() const {
    std::string out = script::stubs::rhp_api(options_.caller_role);
    for (const auto describe : describers_) {
        out += '\n';
        out += describe(options_.caller_role);
    }
    return out;
}

} // namespace Rhp::script::detail

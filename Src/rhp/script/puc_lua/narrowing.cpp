// Narrowing (sandbox::narrow, decision AL13): scopes an exec request or a module revision runs with
// besides the sandbox's own, such as an operator certificate's. They follow the running code's owner
// (active_scope), so a revision's timers, event and patch handlers, tasks and calls stay narrowed;
// capability checks keep costing one mask test (context::denied_caps_ holds both sets' bits).

#include <cstddef>
#include <cstdint>
#include <format>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/scopes.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/puc_lua/sandbox_impl.hpp>
#include <rhp/script/stack.hpp>

namespace Rhp::script::detail {

namespace {

// The first lib path in `libs` (an api() "libs" array) the scopes don't leave this run: a top-level
// lib they don't allow, or a sub-lib they deny (as sandbox_options::scopes treat them).
[[nodiscard]] std::optional<std::string> denied_lib(const value* libs, const scope_set& scopes, bool top) {
    const auto* list = libs != nullptr ? libs->get_if<value::array>() : nullptr;
    if (list == nullptr) {
        return std::nullopt;
    }
    for (const value& lib : *list) {
        const value* path = lib.find("path");
        const auto* text = path != nullptr ? path->get_if<std::string>() : nullptr;
        if (text == nullptr) {
            continue;
        }
        if (top ? !scopes.allows(scope_kind::kLib, *text) : scopes.denies(scope_kind::kLib, *text)) {
            return *text;
        }
        if (auto sub = denied_lib(lib.find("libs"), scopes, false)) {
            return sub;
        }
    }
    return std::nullopt;
}

} // namespace

void sandbox_impl::narrow(scope_set scopes) {
    if (scopes.unrestricted()) {
        pending_narrowing_.reset();
    } else {
        pending_narrowing_ = std::move(scopes);
    }
}

void sandbox_impl::refuse_narrowed(lua_State* L, std::string_view where) const {
    if (active_narrowing_ != nullptr && active_narrowing_->exec) {
        stack{L}.raise(make_error(errc::kForbidden,
                                  "a narrowed exec (a script signed under scopes) can't leave handlers or patches behind: load it as a module", std::string{where}));
    }
}

result<void> sandbox_impl::check_narrowed_libs(const scope_set& scopes) const {
    if (scopes.unrestricted(scope_kind::kLib)) {
        return {};
    }
    const value described = api();
    if (const auto lib = denied_lib(described.find("libs"), scopes, true)) {
        return fail(errc::kForbidden, std::format("its scopes don't allow lib {}, which identity {} has (a lib can't be taken away from one script)", *lib, options_.identity),
                    *lib);
    }
    return {};
}

void sandbox_impl::attach_narrowing(narrowing_key key, bool exec) {
    if (!pending_narrowing_) {
        return;
    }
    narrowing n;
    n.scopes = *pending_narrowing_;
    n.exec = exec;
    n.caps_seen = installed_caps_.size() + 1; // worked out when it first runs
    narrowed_.insert_or_assign(key, std::move(n));
}

void sandbox_impl::narrow_to(const effect_owner& owner) noexcept {
    const narrowing_key key = owner.module == scratch_ ? narrowing_key{scratch_.value(), owner.request.value()} : narrowing_key{owner.module.value(), owner.revision.value()};
    const auto it = narrowed_.find(key);
    set_active_narrowing(it != narrowed_.end() ? &it->second : nullptr);
}

void sandbox_impl::set_active_narrowing(narrowing* n) noexcept {
    if (n != nullptr && n->caps_seen != installed_caps_.size()) {
        n->denied = 0;
        for (const auto& [name, bit] : installed_caps_) {
            if (!n->scopes.allows(scope_kind::kCap, name)) {
                n->denied |= bit;
            }
        }
        n->caps_seen = installed_caps_.size();
    }
    active_narrowing_ = n;
    denied_caps_ = base_denied_caps_ | (n != nullptr ? n->denied : 0);
}

void sandbox_impl::forget_narrowing(narrowing_key key) noexcept {
    if (!narrowed_.contains(key)) {
        return;
    }
    try {
        narrowing_drops_.push_back(key);
    } catch (...) { // out of memory: the entry stays (it narrows nothing that runs any more)
    }
    if (running_.empty()) {
        drop_narrowings();
    }
}

void sandbox_impl::forget_narrowings(module_id mod) noexcept {
    for (auto it = narrowed_.lower_bound({mod.value(), 0}); it != narrowed_.end() && it->first.first == mod.value(); ++it) {
        try {
            narrowing_drops_.push_back(it->first);
        } catch (...) {
        }
    }
    if (running_.empty()) {
        drop_narrowings();
    }
}

void sandbox_impl::drop_narrowings() noexcept {
    // Once no run is active nothing points at an entry (active_narrowing_ is null outside runs);
    // the one still active, if any, waits for the next time.
    std::erase_if(narrowing_drops_, [this](const narrowing_key& key) {
        const auto it = narrowed_.find(key);
        if (it == narrowed_.end()) {
            return true;
        }
        if (&it->second == active_narrowing_) {
            return false;
        }
        narrowed_.erase(it);
        return true;
    });
}

} // namespace Rhp::script::detail

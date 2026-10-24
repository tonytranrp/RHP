#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>

#include <rhp/build_config.hpp>
#include <rhp/core/result.hpp>
#include <rhp/script/detail/context.hpp>
#include <rhp/script/detail/patch_layers.hpp>
#include <rhp/script/detail/patch_registry.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/stack.hpp>
#include <rhp/utils/fixed_string.hpp>
#include <rhp/utils/function_traits.hpp>

namespace Rhp {

namespace script::detail {

// Gives patch_point an operator() with exactly the default's signature (CRTP over the signature).
template <class Point, class Sig>
struct point_call;

template <class Point, class R, class... Args>
struct point_call<Point, R(Args...)> {
    R operator()(Args... args) const { return Point::dispatch(std::forward<Args>(args)...); }
};

} // namespace script::detail

// A named, overridable call site:
//
//   float default_damage(float base, int target);
//   inline constexpr Rhp::patch_point<"combat.damage", &default_damage> damage{};
//
//   float d = damage(base, target);   // RHP_ENABLE=1: one acquire load + a predictable branch
//                                     // RHP_ENABLE=0: a direct call to default_damage
//
// Lua replaces or wraps it, and the override is reverted with its module:
//
//   rhp.patch("combat.damage", function(original, base, target)
//       return original(base, target) * 2
//   end)
//
// The id is dotted lowercase. The default is a function pointer or a captureless lambda; its
// signature is the point's signature. Overrides from several modules stack (newest on top) and can
// be reverted in any order. The point registers itself process-wide before main the first time the
// program contains a call to it. One point type per id.
template <utils::fixed_string Id, auto Default>
    requires(utils::is_dotted_name(Id.view())) && script::detail::patch_default<decltype(Default)>
class patch_point : public script::detail::point_call<patch_point<Id, Default>, script::detail::signature_of_t<decltype(Default)>> {
public:
    using signature = script::detail::signature_of_t<decltype(Default)>;

    static constexpr std::string_view id = Id.view();
    static constexpr std::add_pointer_t<signature> default_function = Default;

    constexpr patch_point() noexcept = default;

    // Overrides currently installed (all sandboxes). 0 when RHP_ENABLE=0.
    [[nodiscard]] static std::size_t depth() {
#if RHP_ENABLE
        return state_.depth();
#else
        return 0;
#endif
    }

    [[nodiscard]] static bool patched() noexcept {
#if RHP_ENABLE
        return state_.patched();
#else
        return false;
#endif
    }

    // Calls that met an override owned by another thread and skipped it.
    [[nodiscard]] static std::uint64_t off_thread_misses() noexcept {
#if RHP_ENABLE
        return state_.off_thread_misses();
#else
        return 0;
#endif
    }

private:
    friend struct script::detail::point_call<patch_point, signature>;

    template <class... Args>
    static decltype(auto) dispatch(Args&&... args) {
#if RHP_ENABLE
        (void)registered_; // odr-use: instantiates the registration below
        return state_.call(std::forward<Args>(args)...);
#else
        return default_function(std::forward<Args>(args)...);
#endif
    }

#if RHP_ENABLE
    static result<std::unique_ptr<script::effect>> attach_lua(script::stack& s, int fn_index) {
        if (s.type(fn_index) != script::type_kind::kFunction) {
            return fail(errc::kTypeMismatch, std::format("expected function, got {}", s.type_name(fn_index)), std::string{id});
        }
        auto& ctx = s.context();
        s.push_copy(fn_index);
        const int fn_ref = s.ref();
        auto layer = std::make_unique<script::detail::lua_patch_layer<signature>>(ctx, ctx.current_owner(), fn_ref, state_, id);
        return std::make_unique<script::detail::patch_effect<signature>>(state_, std::move(layer));
    }

    static std::size_t depth_erased() { return state_.depth(); }
    static std::uint64_t misses_erased() { return state_.off_thread_misses(); }

    static constexpr script::detail::point_descriptor descriptor_{
        id,
        utils::arity_v<decltype(Default)>,
        &attach_lua,
        &depth_erased,
        &misses_erased,
    };

    static inline constinit script::detail::point_state<signature> state_{Default};
    static inline const bool registered_ = script::detail::register_point(&descriptor_);
#endif
};

} // namespace Rhp

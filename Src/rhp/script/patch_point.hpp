#pragma once

#include <cstddef>
#include <cstdint>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include <rhp/build_config.hpp>
#include <rhp/core/convert.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/detail/context.hpp>
#include <rhp/script/detail/patch_layers.hpp>
#include <rhp/script/detail/patch_registry.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/stack.hpp>
#include <rhp/utils/fixed_string.hpp>
#include <rhp/utils/function_traits.hpp>
#include <rhp/utils/scope_guard.hpp>
#include <rhp/utils/type_list.hpp>

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
        if (!state_.patched()) [[likely]] {
            return Default(std::forward<Args>(args)...); // known here, so the compiler may inline it
        }
        return state_.call_below(nullptr, std::forward<Args>(args)...);
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
        // Until the layer owns the reference: building it allocates Lua objects, which may raise.
        bool owned = false;
        const utils::scope_guard release{[&]() noexcept {
            if (!owned) {
                s.unref(fn_ref);
            }
        }};
        auto layer = std::make_unique<script::detail::lua_patch_layer<signature>>(s, ctx.current_owner(), fn_ref, state_, id);
        owned = true;
        return std::make_unique<script::detail::patch_effect<signature>>(state_, std::move(layer));
    }

    static std::size_t depth_erased() { return state_.depth(); }
    static std::uint64_t misses_erased() { return state_.off_thread_misses(); }

    // Calls the point from values (test runners call points this way): every parameter must come
    // from a value and the result go back to one.
    static result<std::vector<value>> invoke_erased(std::span<const value> args) {
        using traits = utils::function_traits<signature>;
        if (args.size() != traits::arity) {
            return fail(errc::kInvalidArgument, std::format("expected {} arguments, got {}", traits::arity, args.size()), std::string{id});
        }
        return [&]<class... A>(utils::type_list<A...>) -> result<std::vector<value>> {
            return [&]<std::size_t... I>(std::index_sequence<I...>) -> result<std::vector<value>> {
                std::tuple<result<std::remove_cvref_t<A>>...> converted{from_value<std::remove_cvref_t<A>>(args[I])...};
                std::optional<error> bad;
                ((bad || std::get<I>(converted) ? void() : void(bad = std::get<I>(converted).error())), ...);
                if (bad) {
                    bad->where = std::format("{} argument {}", id, bad->where.empty() ? std::string{"?"} : bad->where);
                    return std::unexpected{std::move(*bad)};
                }
                using R = typename traits::return_type;
                if constexpr (std::is_void_v<R>) {
                    dispatch(std::move(*std::get<I>(converted))...);
                    return std::vector<value>{};
                } else {
                    return std::vector<value>{to_value(dispatch(std::move(*std::get<I>(converted))...))};
                }
            }(std::index_sequence_for<A...>{});
        }(typename traits::args{});
    }

    template <class A>
    static constexpr bool kValueParameter = from_value_convertible<std::remove_cvref_t<A>> &&
                                            !(std::is_lvalue_reference_v<A> && !std::is_const_v<std::remove_reference_t<A>>);

    static constexpr bool kValueCallable = []<class... A>(utils::type_list<A...>) {
        using R = typename utils::function_traits<signature>::return_type;
        return (kValueParameter<A> && ...) && (std::is_void_v<R> || to_value_convertible<std::remove_cvref_t<R>>);
    }(typename utils::function_traits<signature>::args{});

    // invoke_erased, or nullptr (its body isn't instantiated then).
    static constexpr auto invoker_ = [] {
        if constexpr (kValueCallable) {
            return &patch_point::invoke_erased;
        } else {
            return static_cast<decltype(&patch_point::invoke_erased)>(nullptr);
        }
    }();

    static constexpr script::detail::point_descriptor descriptor_{
        id,
        utils::arity_v<decltype(Default)>,
        &attach_lua,
        &depth_erased,
        &misses_erased,
        invoker_,
    };

    static inline constinit script::detail::point_state<signature> state_{Default};
    static inline const bool registered_ = script::detail::register_point(&descriptor_);
#endif
};

} // namespace Rhp

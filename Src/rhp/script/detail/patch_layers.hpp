#pragma once

#include <algorithm>
#include <atomic>
#include <concepts>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <thread>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include <rhp/core/ids.hpp>
#include <rhp/core/result.hpp>
#include <rhp/script/detail/context.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/marshal.hpp>
#include <rhp/script/stack.hpp>
#include <rhp/utils/function_traits.hpp>
#include <rhp/utils/scope_guard.hpp>

namespace Rhp::script::detail {

// ---- signatures ------------------------------------------------------------------------------

template <class R, class List>
struct make_signature;

template <class R, class... Args>
struct make_signature<R, utils::type_list<Args...>> {
    using type = R(Args...);
};

template <class F>
using signature_of_t = typename make_signature<utils::return_type_t<F>, utils::args_t<F>>::type;

template <class T>
concept patch_param = convertible<T> && (!std::is_reference_v<T> || std::is_const_v<std::remove_reference_t<T>>);

// A result that only views memory it doesn't own. A Lua override's result is pulled from a Lua
// string that is unrooted once the handler returns, so a view of it would dangle at the next GC:
// patch points return owning values (std::string, not std::string_view).
// (A user Rhp::convert<T>::pull must likewise return a value that owns its data.)
template <class T>
inline constexpr bool borrowed_result_v = std::same_as<std::remove_cv_t<T>, std::string_view>;

template <class T>
inline constexpr bool borrowed_result_v<std::optional<T>> = borrowed_result_v<T>;

template <class T>
concept borrowed_result = borrowed_result_v<std::remove_cv_t<T>>;

template <class T>
concept patch_return = std::is_void_v<T> || (convertible<T> && !std::is_reference_v<T> && !borrowed_result<T>);

template <class List>
inline constexpr bool patch_params_v = false;

template <class... Args>
inline constexpr bool patch_params_v<utils::type_list<Args...>> = (patch_param<Args> && ...);

// The default of a patch point: a free function pointer or a captureless lambda whose parameters
// and result cross the Lua boundary (no non-const references).
template <class F>
concept patch_default = utils::has_function_traits<F> && !utils::function_traits<F>::is_member &&
                        std::convertible_to<F, std::add_pointer_t<signature_of_t<F>>> &&
                        patch_return<utils::return_type_t<F>> && patch_params_v<utils::args_t<F>>;

// ---- layers ----------------------------------------------------------------------------------

template <class Sig>
class patch_layer;

// One override installed on a patch point. Invoked only on its owner thread.
template <class R, class... Args>
class patch_layer<R(Args...)> {
public:
    explicit patch_layer(std::thread::id owner) noexcept : owner_(owner) {}
    patch_layer(const patch_layer&) = delete;
    patch_layer& operator=(const patch_layer&) = delete;
    virtual ~patch_layer() = default;

    virtual R invoke(Args... args) = 0;

    [[nodiscard]] std::thread::id owner() const noexcept { return owner_; }

private:
    std::thread::id owner_;
};

template <class Sig>
class point_state;

// Shared state of one patch point type: the layer stack (oldest first) and the C++ default.
//
// Threading: layers are pushed, removed and invoked only on their owner thread. A call walks the
// stack under the mutex, picks the highest layer owned by the calling thread and invokes it
// unlocked - safe because only that same thread could free it. Layers owned by other threads
// are skipped and counted as off-thread misses; with none left, the C++ default runs.
template <class R, class... Args>
class point_state<R(Args...)> {
public:
    using layer = patch_layer<R(Args...)>;
    using fallback_fn = R (*)(Args...);

    constexpr explicit point_state(fallback_fn fallback) noexcept : fallback_(fallback) {}

    // Invokes the next runnable layer below `above` (nullptr = from the top), else the default.
    R call_below(const layer* above, Args... args) {
        if (layer* next = select_below(above)) {
            return next->invoke(std::forward<Args>(args)...);
        }
        return fallback_(std::forward<Args>(args)...);
    }

    void push(layer* l) {
        const std::scoped_lock lock{mutex_};
        if (!layers_) {
            layers_ = std::make_unique<std::vector<layer*>>();
        }
        layers_->push_back(l);
        patched_.store(true, std::memory_order_release);
    }

    void remove(const layer* l) noexcept {
        const std::scoped_lock lock{mutex_};
        if (!layers_) {
            return;
        }
        if (const auto it = std::ranges::find(*layers_, l); it != layers_->end()) {
            layers_->erase(it);
        }
        patched_.store(!layers_->empty(), std::memory_order_release);
    }

    [[nodiscard]] std::size_t depth() {
        const std::scoped_lock lock{mutex_};
        return layers_ ? layers_->size() : 0;
    }

    [[nodiscard]] bool patched() const noexcept { return patched_.load(std::memory_order_acquire); }
    [[nodiscard]] std::uint64_t off_thread_misses() const noexcept { return misses_.load(std::memory_order_relaxed); }

private:
    layer* select_below(const layer* above) {
        const auto me = std::this_thread::get_id();
        const std::scoped_lock lock{mutex_};
        if (!layers_) {
            return nullptr;
        }
        auto& stack = *layers_;
        auto it = stack.end();
        if (above != nullptr) {
            it = std::ranges::find(stack, above);
            if (it == stack.end()) {
                return nullptr; // `above` was removed mid-call: nothing below it is meaningful
            }
        }
        while (it != stack.begin()) {
            --it;
            if ((*it)->owner() == me) {
                return *it;
            }
            misses_.fetch_add(1, std::memory_order_relaxed);
        }
        return nullptr;
    }

    fallback_fn fallback_;
    std::atomic<bool> patched_{false};
    std::atomic<std::uint64_t> misses_{0};
    std::mutex mutex_;
    // Created on the first patch: keeps the whole state constant-initialized (constinit), so a
    // point is safe to call during static initialization, before anything is ever patched.
    std::unique_ptr<std::vector<layer*>> layers_;
};

// The ledger effect of one rhp.patch(): owns the layer, removes it on undo or destruction.
template <class Sig>
class patch_effect final : public effect {
public:
    patch_effect(point_state<Sig>& state, std::unique_ptr<patch_layer<Sig>> layer) : state_(state), layer_(std::move(layer)) {
        state_.push(layer_.get());
    }

    patch_effect(const patch_effect&) = delete;
    patch_effect& operator=(const patch_effect&) = delete;

    ~patch_effect() override { detach(); }

    void undo() override { detach(); }

private:
    void detach() noexcept {
        if (layer_) {
            state_.remove(layer_.get());
            layer_.reset();
        }
    }

    point_state<Sig>& state_;
    std::unique_ptr<patch_layer<Sig>> layer_;
};

// ---- Lua-backed layer --------------------------------------------------------------------------

// Userdata behind the `original` function handed to a patch handler. Valid only while the
// handler runs; afterwards `frame` is null and calling `original` raises an error. One per layer,
// made with it: a call points it at its frame and restores what it held (a re-entrant call of the
// same layer) when it ends.
struct original_token {
    void* frame = nullptr;
};

inline constexpr std::string_view kOriginalTokenKey = "rhp.original";

template <class Sig>
class lua_patch_layer;

template <class R, class... Args>
class lua_patch_layer<R(Args...)> final : public patch_layer<R(Args...)> {
public:
    using state_type = point_state<R(Args...)>;

    // Made while rhp.patch runs on `s`: builds the layer's `original` (a closure over its token).
    lua_patch_layer(stack& s, const effect_owner& owner, int fn_ref, state_type& state, std::string_view id)
        : patch_layer<R(Args...)>(std::this_thread::get_id()), ctx_(s.context()), owner_(owner), fn_ref_(fn_ref), state_(state), id_(id) {
        token_ = static_cast<original_token*>(s.push_userdata(sizeof(original_token), kOriginalTokenKey));
        token_->frame = nullptr;
        s.push_function(&original, 1); // original, holding the token as its upvalue
        original_ref_ = s.ref();
    }

    ~lua_patch_layer() override {
        const stack s{ctx_.main_state()};
        s.unref(original_ref_);
        s.unref(fn_ref_);
    }

    R invoke(Args... args) override {
        frame f{this, std::tuple<std::remove_reference_t<Args>&...>{args...}, {}};
        auto ran = ctx_.run_handler(owner_, &run, &f);
        if (ran && f.done) {
            if constexpr (std::is_void_v<R>) {
                return;
            } else {
                return std::move(*f.result);
            }
        }
        error err = ran ? std::move(f.failure) : std::move(ran).error();
        if (err.where.empty()) {
            err.where = std::string{id_};
        }
        ctx_.report_fault(owner_, std::move(err));
        return state_.call_below(this, std::forward<Args>(args)...);
    }

private:
    struct frame {
        lua_patch_layer* self;
        std::tuple<std::remove_reference_t<Args>&...> args;
        std::conditional_t<std::is_void_v<R>, char, std::optional<std::remove_cvref_t<R>>> result;
        bool done = false;
        error failure{};
    };

    // Runs inside lua_pcall: push handler, original, args; call; pull the result.
    static int run(lua_State* L) {
        stack s{L};
        auto* f = static_cast<frame*>(s.to_light_userdata(1));
        lua_patch_layer& self = *f->self;
        s.push_ref(self.fn_ref_);       // the handler
        s.push_ref(self.original_ref_); // original
        original_token* token = self.token_;
        void* const outer = token->frame; // set when the handler re-entered its own patch point
        token->frame = f;
        // Runs on success and while a Lua error unwinds through this frame alike.
        const utils::scope_guard expire{[token, outer]() noexcept { token->frame = outer; }};
        std::apply([&](auto&... a) { (push(s, a), ...); }, f->args);
        s.call_unprotected(1 + static_cast<int>(sizeof...(Args)), std::is_void_v<R> ? 0 : 1);
        if constexpr (!std::is_void_v<R>) {
            auto r = pull<std::remove_cvref_t<R>>(s, -1);
            if (!r) {
                f->failure = std::move(r).error();
                f->failure.message = "patch handler returned a bad value: " + f->failure.message;
                return 0;
            }
            f->result.emplace(std::move(*r));
        }
        f->done = true;
        return 0;
    }

    // `original(...)` inside a handler: calls the layer below this one, or the C++ default.
    static int original(lua_State* L) {
        stack s{L};
        // The upvalue is this layer's token unless an admin script replaced it (debug.setupvalue):
        // checked by its metatable, never trusted blindly.
        auto* token = static_cast<original_token*>(s.to_userdata(stack::upvalue_index(1), kOriginalTokenKey));
        if (token == nullptr || token->frame == nullptr) {
            s.raise(make_error(errc::kInvalidArgument, "original() is only valid while its patch handler runs"));
        }
        auto* f = static_cast<frame*>(token->frame);
        return call_original(s, *f->self, std::index_sequence_for<Args...>{});
    }

    template <std::size_t... Is>
    static int call_original(stack& s, lua_patch_layer& self, std::index_sequence<Is...>) {
        std::tuple<result<std::remove_cvref_t<Args>>...> pulled{pull<std::remove_cvref_t<Args>>(s, static_cast<int>(Is) + 1)...};
        std::optional<error> bad;
        ((bad || std::get<Is>(pulled) ? void() : void(bad = std::get<Is>(pulled).error())), ...);
        if (bad) {
            s.raise(*bad);
        }
        std::optional<error> thrown;
        int pushed = 0;
        if constexpr (std::is_void_v<R>) {
            try {
                self.state_.call_below(&self, std::move(*std::get<Is>(pulled))...);
            } catch (const Rhp::exception& e) {
                thrown = e.err();
            } catch (const std::exception& e) {
                thrown = make_error(errc::kRuntime, e.what());
            }
        } else {
            std::optional<std::remove_cvref_t<R>> out;
            try {
                out.emplace(self.state_.call_below(&self, std::move(*std::get<Is>(pulled))...));
            } catch (const Rhp::exception& e) {
                thrown = e.err();
            } catch (const std::exception& e) {
                thrown = make_error(errc::kRuntime, e.what());
            }
            if (!thrown) {
                push(s, *out);
                pushed = 1;
            }
        }
        if (thrown) {
            s.raise(*thrown);
        }
        return pushed;
    }

    context& ctx_;
    effect_owner owner_;
    int fn_ref_;
    int original_ref_ = -2; // LUA_NOREF until built
    original_token* token_ = nullptr;
    state_type& state_;
    std::string_view id_;
};

} // namespace Rhp::script::detail

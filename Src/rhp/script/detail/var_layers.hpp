#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <iterator>
#include <memory>
#include <mutex>
#include <type_traits>
#include <utility>
#include <vector>

#include <rhp/script/ledger.hpp>

namespace Rhp::script::detail {

// Whether a variable of type T can be read and written through std::atomic_ref without a lock (where
// the standard library has it).
template <class T>
consteval bool lock_free_var() {
#if defined(__cpp_lib_atomic_ref)
    if constexpr (std::is_trivially_copyable_v<T>) {
        return std::atomic_ref<T>::is_always_lock_free && std::atomic_ref<T>::required_alignment <= alignof(T);
    } else {
        return false;
    }
#else
    return false;
#endif
}

// Process-wide stack of script writes to one C++ variable (one instantiation per variable).
//
// Each write remembers the value it replaced. Undoing the newest write restores that value;
// undoing an older write hands its remembered value to the next newer write instead, so the
// variable always ends up exactly as if the undone write had never happened - whatever order
// modules (or sandboxes) are reverted in.
//
// Threading: RHP's own reads (read), writes (assign) and undos of the variable are serialized by one
// lock per variable (reads of a small trivially copyable one are atomic loads instead), so sandboxes
// on different threads may expose the same variable. The application's own accesses to it are its
// business (the pump thread, or its own synchronization).
template <auto Ptr>
class var_layers {
    struct locked {}; // assign() holds the lock and layers the effect itself

public:
    using value_type = std::remove_pointer_t<decltype(Ptr)>;

    // Small trivially copyable variables (numbers, bools, enums) are read without the lock: RHP's own
    // writes store them atomically too, so a read never sees half of one.
    static constexpr bool kAtomic = lock_free_var<value_type>();

    class write_effect;

    // A script's write: remembers the value it replaces, layers itself and assigns, in one step under
    // the variable's lock, so writes from sandboxes on different threads stack in the order they
    // happened.
    [[nodiscard]] static std::unique_ptr<write_effect> assign(value_type incoming) {
        const std::scoped_lock lock{mutex()};
        auto& stack = layers();
        if (stack.size() == stack.capacity()) { // the one allocation, before anything changes (doubling: no quadratic growth)
            stack.reserve(std::max<std::size_t>(8, stack.capacity() * 2));
        }
        // Not layered until the assignment succeeded: if copying or assigning throws, its destructor
        // has nothing to detach (and doesn't take the lock this scope holds).
        std::unique_ptr<write_effect> fx{new write_effect(locked{}, *Ptr)};
        store(std::move(incoming));
        stack.push_back(fx.get()); // can't throw: reserved
        fx->layered_ = true;
        return fx;
    }

    // A script's read, serialized with every write and undo RHP makes. Copies the value out, so
    // nothing is pushed to Lua under the lock.
    [[nodiscard]] static value_type read() {
#if defined(__cpp_lib_atomic_ref)
        if constexpr (kAtomic) {
            return std::atomic_ref<value_type>{*Ptr}.load(std::memory_order_acquire);
        } else
#endif
        {
            const std::scoped_lock lock{mutex()};
            return *Ptr;
        }
    }

    class write_effect final : public effect {
    public:
        // Remembers `replaced` and layers itself; the caller assigns the variable afterwards (not in
        // the same locked step: prefer assign()).
        explicit write_effect(value_type replaced) : replaced_(std::move(replaced)) {
            const std::scoped_lock lock{mutex()};
            layers().push_back(this);
            layered_ = true;
        }

        write_effect(const write_effect&) = delete;
        write_effect& operator=(const write_effect&) = delete;

        ~write_effect() override { detach(false); }

        void undo() override { detach(true); }

    private:
        friend class var_layers;
        // assign(): the caller holds the lock and layers this effect itself.
        write_effect(locked, value_type replaced) : replaced_(std::move(replaced)) {}

        void detach(bool restore) {
            if (!layered_) {
                return;
            }
            const std::scoped_lock lock{mutex()};
            auto& stack = layers();
            // From the newest end: reverts go newest first, so this finds the effect at once.
            const auto found = std::ranges::find(stack.rbegin(), stack.rend(), this);
            if (found == stack.rend()) {
                return;
            }
            const auto it = std::prev(found.base());
            if (const auto newer = std::next(it); newer != stack.end()) {
                (*newer)->replaced_ = std::move(replaced_);
            } else if (restore) {
                store(std::move(replaced_));
            }
            stack.erase(it);
            layered_ = false;
        }

        value_type replaced_;
        bool layered_ = false; // on the stack (set under the lock; detach takes it off for good)
    };

    // Number of script writes currently layered on the variable (all sandboxes).
    [[nodiscard]] static std::size_t depth() {
        const std::scoped_lock lock{mutex()};
        return layers().size();
    }

private:
    // Under the lock (writes and undos stay serialized among themselves).
    static void store(value_type v) {
#if defined(__cpp_lib_atomic_ref)
        if constexpr (kAtomic) {
            std::atomic_ref<value_type>{*Ptr}.store(v, std::memory_order_release);
        } else
#endif
        {
            *Ptr = std::move(v);
        }
    }

    static std::mutex& mutex() {
        static std::mutex m;
        return m;
    }

    static std::vector<write_effect*>& layers() {
        static std::vector<write_effect*> stack;
        return stack;
    }
};

} // namespace Rhp::script::detail

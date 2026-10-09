#pragma once

#include <algorithm>
#include <iterator>
#include <mutex>
#include <type_traits>
#include <utility>
#include <vector>

#include <rhp/script/ledger.hpp>

namespace Rhp::script::detail {

// Process-wide stack of script writes to one C++ variable (one instantiation per variable).
//
// Each write remembers the value it replaced. Undoing the newest write restores that value;
// undoing an older write hands its remembered value to the next newer write instead, so the
// variable always ends up exactly as if the undone write had never happened — whatever order
// modules (or sandboxes) are reverted in.
template <auto Ptr>
class var_layers {
public:
    using value_type = std::remove_pointer_t<decltype(Ptr)>;

    class write_effect final : public effect {
    public:
        explicit write_effect(value_type replaced) : replaced_(std::move(replaced)) {
            const std::scoped_lock lock{mutex()};
            layers().push_back(this);
        }

        write_effect(const write_effect&) = delete;
        write_effect& operator=(const write_effect&) = delete;

        ~write_effect() override { detach(false); }

        void undo() override { detach(true); }

    private:
        void detach(bool restore) {
            const std::scoped_lock lock{mutex()};
            auto& stack = layers();
            const auto it = std::ranges::find(stack, this);
            if (it == stack.end()) {
                return;
            }
            if (const auto newer = std::next(it); newer != stack.end()) {
                (*newer)->replaced_ = std::move(replaced_);
            } else if (restore) {
                *Ptr = std::move(replaced_);
            }
            stack.erase(it);
        }

        value_type replaced_;
    };

    // Number of script writes currently layered on the variable (all sandboxes).
    [[nodiscard]] static std::size_t depth() {
        const std::scoped_lock lock{mutex()};
        return layers().size();
    }

private:
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

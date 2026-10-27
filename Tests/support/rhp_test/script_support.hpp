#pragma once

// Helpers the script tests share: a script clock moved by hand, a result's error code, and a memory
// resource that counts what it hands out.

#include <chrono>
#include <cstddef>
#include <memory_resource>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/script/sandbox.hpp>

namespace rhp_test {

// Script time the test moves by hand: sandbox_options::clock = clock.fn().
struct manual_clock {
    std::chrono::steady_clock::time_point now = std::chrono::steady_clock::time_point{} + std::chrono::hours{1};

    void advance(std::chrono::milliseconds ms) { now += ms; }
    [[nodiscard]] Rhp::script::clock_fn fn() {
        return [this] { return now; };
    }
};

// kOk for a value, else the error's code.
template <class T>
[[nodiscard]] Rhp::errc code_of(const Rhp::result<T>& r) {
    return r ? Rhp::errc::kOk : r.error().code;
}

// The new / delete resource, counting allocations and the bytes still allocated.
class counting_resource final : public std::pmr::memory_resource {
public:
    [[nodiscard]] std::size_t allocations() const noexcept { return allocations_; }
    [[nodiscard]] std::size_t live_bytes() const noexcept { return live_bytes_; }

private:
    void* do_allocate(std::size_t bytes, std::size_t alignment) override {
        ++allocations_;
        live_bytes_ += bytes;
        return std::pmr::new_delete_resource()->allocate(bytes, alignment);
    }

    void do_deallocate(void* p, std::size_t bytes, std::size_t alignment) override {
        live_bytes_ -= bytes;
        std::pmr::new_delete_resource()->deallocate(p, bytes, alignment);
    }

    [[nodiscard]] bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override { return this == &other; }

    std::size_t allocations_ = 0;
    std::size_t live_bytes_ = 0;
};

} // namespace rhp_test

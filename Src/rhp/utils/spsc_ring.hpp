#pragma once

#include <atomic>
#include <bit>
#include <concepts>
#include <cstddef>
#include <memory>
#include <new>
#include <optional>
#include <utility>

namespace Rhp::utils {

#if defined(__cpp_lib_hardware_interference_size)
inline constexpr std::size_t kCacheLine = std::hardware_destructive_interference_size;
#else
inline constexpr std::size_t kCacheLine = 64;
#endif

#if defined(_MSC_VER) && !defined(__clang__)
#pragma warning(push)
#pragma warning(disable : 4324) // padded due to alignment specifier: intended
#endif

// Bounded single-producer / single-consumer queue: the only lock-free structure RHP hand-rolls.
// Exactly one thread may call the producer side (try_push / try_emplace) and exactly one thread
// the consumer side (try_pop). Capacity is rounded up to a power of two.
//
// Ordering: each side publishes its index with release and reads the other side's index with
// acquire, so an element's construction happens-before its consumption and its destruction
// happens-before the slot is reused.
template <std::movable T>
class spsc_ring {
public:
    explicit spsc_ring(std::size_t min_capacity)
        : capacity_(std::bit_ceil(min_capacity < 2 ? std::size_t{2} : min_capacity)),
          mask_(capacity_ - 1),
          slots_(std::make_unique<slot[]>(capacity_)) {}

    spsc_ring(const spsc_ring&) = delete;
    spsc_ring& operator=(const spsc_ring&) = delete;
    spsc_ring(spsc_ring&&) = delete;
    spsc_ring& operator=(spsc_ring&&) = delete;

    ~spsc_ring() {
        while (try_pop()) {
        }
    }

    template <class... Args>
        requires std::constructible_from<T, Args...>
    [[nodiscard]] bool try_emplace(Args&&... args) noexcept(std::is_nothrow_constructible_v<T, Args...>) {
        const std::size_t tail = tail_.load(std::memory_order_relaxed);
        if (tail - cached_head_ == capacity_) {
            cached_head_ = head_.load(std::memory_order_acquire);
            if (tail - cached_head_ == capacity_) {
                return false;
            }
        }
        ::new (static_cast<void*>(slots_[tail & mask_].bytes)) T(std::forward<Args>(args)...);
        tail_.store(tail + 1, std::memory_order_release);
        return true;
    }

    // Moves (or copies) `value` in only when there is room: a full ring leaves it untouched.
    [[nodiscard]] bool try_push(T&& value) noexcept(std::is_nothrow_move_constructible_v<T>) {
        return try_emplace(std::move(value));
    }

    [[nodiscard]] bool try_push(const T& value) noexcept(std::is_nothrow_copy_constructible_v<T>)
        requires std::copy_constructible<T>
    {
        return try_emplace(value);
    }

    [[nodiscard]] std::optional<T> try_pop() noexcept(std::is_nothrow_move_constructible_v<T>) {
        const std::size_t head = head_.load(std::memory_order_relaxed);
        if (head == cached_tail_) {
            cached_tail_ = tail_.load(std::memory_order_acquire);
            if (head == cached_tail_) {
                return std::nullopt;
            }
        }
        T* item = std::launder(reinterpret_cast<T*>(slots_[head & mask_].bytes));
        std::optional<T> out{std::move(*item)};
        item->~T();
        head_.store(head + 1, std::memory_order_release);
        return out;
    }

    [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }

    // Approximate when called while the other side is active.
    [[nodiscard]] std::size_t size_approx() const noexcept {
        return tail_.load(std::memory_order_acquire) - head_.load(std::memory_order_acquire);
    }

private:
    struct slot {
        alignas(T) std::byte bytes[sizeof(T)];
    };

    const std::size_t capacity_;
    const std::size_t mask_;
    std::unique_ptr<slot[]> slots_;

    alignas(kCacheLine) std::atomic<std::size_t> head_{0}; // next slot to pop, written by consumer
    alignas(kCacheLine) std::size_t cached_tail_ = 0;      // consumer's view of tail_
    alignas(kCacheLine) std::atomic<std::size_t> tail_{0}; // next slot to fill, written by producer
    alignas(kCacheLine) std::size_t cached_head_ = 0;      // producer's view of head_
};

#if defined(_MSC_VER) && !defined(__clang__)
#pragma warning(pop)
#endif

} // namespace Rhp::utils

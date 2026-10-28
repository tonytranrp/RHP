#include <atomic>
#include <cstdint>
#include <mutex>

#include <rhp/script/detail/caps.hpp>

namespace Rhp::script::detail {

std::uint64_t assign_cap_bit(const cap_ref& ref) noexcept {
    if (const std::uint64_t bit = ref.bit->load(std::memory_order_acquire); bit != 0) {
        return bit;
    }
    static std::mutex mutex;
    static unsigned next = 0;
    const std::scoped_lock lock{mutex};
    std::uint64_t bit = ref.bit->load(std::memory_order_relaxed);
    if (bit == 0) {
        bit = next < 63 ? std::uint64_t{1} << next++ : kCapOverflowBit;
        ref.bit->store(bit, std::memory_order_release);
    }
    return bit;
}

} // namespace Rhp::script::detail

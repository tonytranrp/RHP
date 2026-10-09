#include <cstddef>
#include <cstdint>
#include <span>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/random.hpp>

#if defined(RHP_PLATFORM_WINDOWS)
// clang-format off
#include <windows.h> // first: bcrypt.h needs its types
#include <bcrypt.h>
// clang-format on
#elif defined(RHP_PLATFORM_LINUX)
#include <cerrno>

#include <sys/random.h>
#elif defined(RHP_PLATFORM_MACOS) || defined(RHP_PLATFORM_IOS) || defined(RHP_PLATFORM_ANDROID)
#include <cstdlib>
#endif

namespace Rhp::platform {

result<void> random_bytes(std::span<std::byte> out) {
    if (out.empty()) {
        return {};
    }
#if defined(RHP_PLATFORM_WINDOWS)
    // BCryptGenRandom takes a ULONG length: fill in chunks.
    std::size_t done = 0;
    while (done < out.size()) {
        const std::size_t chunk = out.size() - done < 0x7fff'ffffu ? out.size() - done : 0x7fff'ffffu;
        const NTSTATUS status = BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(out.data() + done), static_cast<ULONG>(chunk),
                                                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(status)) {
            return fail(errc::kInvalidArgument, "BCryptGenRandom failed", "platform.random_bytes");
        }
        done += chunk;
    }
    return {};
#elif defined(RHP_PLATFORM_LINUX)
    std::size_t done = 0;
    while (done < out.size()) {
        const ssize_t got = getrandom(out.data() + done, out.size() - done, 0);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return fail(errc::kInvalidArgument, "getrandom failed", "platform.random_bytes");
        }
        done += static_cast<std::size_t>(got);
    }
    return {};
#else
    // Apple and bionic: arc4random_buf never fails.
    arc4random_buf(out.data(), out.size());
    return {};
#endif
}

} // namespace Rhp::platform

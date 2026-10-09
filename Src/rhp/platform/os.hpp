#pragma once

#include <string_view>

namespace Rhp::platform {

enum class os_kind : unsigned char {
    kWindows,
    kLinux,
    kMacos,
    kIos,
    kAndroid
};

// The target OS, from the RHP_PLATFORM_* definition CMake sets (cmake/RhpPlatform.cmake).
#if defined(RHP_PLATFORM_WINDOWS)
inline constexpr os_kind kOs = os_kind::kWindows;
#elif defined(RHP_PLATFORM_LINUX)
inline constexpr os_kind kOs = os_kind::kLinux;
#elif defined(RHP_PLATFORM_MACOS)
inline constexpr os_kind kOs = os_kind::kMacos;
#elif defined(RHP_PLATFORM_IOS)
inline constexpr os_kind kOs = os_kind::kIos;
#elif defined(RHP_PLATFORM_ANDROID)
inline constexpr os_kind kOs = os_kind::kAndroid;
#else
#error "RHP: no RHP_PLATFORM_* definition; link Rhp::platform (or any Rhp:: target)"
#endif

[[nodiscard]] constexpr std::string_view to_string(os_kind os) noexcept {
    switch (os) {
    case os_kind::kWindows: return "windows";
    case os_kind::kLinux: return "linux";
    case os_kind::kMacos: return "macos";
    case os_kind::kIos: return "ios";
    case os_kind::kAndroid: return "android";
    }
    return "unknown";
}

// "windows", "linux", "macos", "ios", "android" — sent in the handshake, shown in status.
inline constexpr std::string_view kOsName = to_string(kOs);

} // namespace Rhp::platform

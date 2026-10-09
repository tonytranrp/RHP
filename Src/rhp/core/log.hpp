#pragma once

#include <concepts>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <utility>

namespace Rhp {

enum class log_level : std::uint8_t {
    kTrace,
    kDebug,
    kInfo,
    kWarn,
    kError,
    kCritical,
    kOff
};

[[nodiscard]] constexpr std::string_view to_string(log_level level) noexcept {
    switch (level) {
    case log_level::kTrace: return "trace";
    case log_level::kDebug: return "debug";
    case log_level::kInfo: return "info";
    case log_level::kWarn: return "warn";
    case log_level::kError: return "error";
    case log_level::kCritical: return "critical";
    case log_level::kOff: return "off";
    }
    return "unknown";
}

namespace core {

// Logger policy for Rhp::config<>::logger<...>. Plug in spdlog, logcat, os_log, your engine log.
//   enabled(level) lets RHP skip formatting entirely for filtered levels.
template <class L>
concept logger = requires(L& l, const L& cl, log_level level, std::string_view message) {
    { cl.enabled(level) } -> std::convertible_to<bool>;
    l.write(level, message);
};

// Discards everything; every call compiles away.
struct null_logger {
    [[nodiscard]] static constexpr bool enabled(log_level) noexcept { return false; }
    static constexpr void write(log_level, std::string_view) noexcept {}
};

// "[rhp warn] message" to stderr.
class stderr_logger {
public:
    explicit stderr_logger(log_level min_level = log_level::kInfo) noexcept : min_level_(min_level) {}

    [[nodiscard]] bool enabled(log_level level) const noexcept { return level >= min_level_ && level != log_level::kOff; }
    void write(log_level level, std::string_view message) const;
    void set_min_level(log_level level) noexcept { min_level_ = level; }

private:
    log_level min_level_;
};

} // namespace core

// Rhp::log(logger, log_level::kInfo, "loaded {}", name) — formats only when enabled.
template <core::logger L, class... Args>
void log(L& logger, log_level level, std::format_string<Args...> fmt, Args&&... args) {
    if (logger.enabled(level)) {
        logger.write(level, std::format(fmt, std::forward<Args>(args)...));
    }
}

} // namespace Rhp

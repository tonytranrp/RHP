#pragma once

#include <atomic>
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
// A host default-constructs its own logger and calls it from several threads: its pump thread, its
// network thread, and whichever thread constructs or destroys it or calls set_enabled().
//   enabled(level) may run concurrently with itself, with write() and with whatever the application
//   does to the logger (host.logger()): make it thread-safe (an atomic level). RHP asks it before
//   formatting, so filtered levels cost one call and no allocation.
//   write(level, message) calls of one host never overlap; a sink shared with other hosts or with
//   the application must synchronize itself.
template <class L>
concept logger = std::default_initializable<L> && requires(L& l, const L& cl, log_level level, std::string_view message) {
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
    stderr_logger(const stderr_logger& other) noexcept : min_level_(other.min_level()) {}
    stderr_logger& operator=(const stderr_logger& other) noexcept {
        set_min_level(other.min_level());
        return *this;
    }
    ~stderr_logger() = default;

    // Thread-safe: RHP's threads ask while the application changes the level.
    [[nodiscard]] bool enabled(log_level level) const noexcept { return level != log_level::kOff && level >= min_level(); }
    void write(log_level level, std::string_view message) const;
    void set_min_level(log_level level) noexcept { min_level_.store(level, std::memory_order_relaxed); }
    [[nodiscard]] log_level min_level() const noexcept { return min_level_.load(std::memory_order_relaxed); }

private:
    std::atomic<log_level> min_level_; // relaxed: no other data is published through the level
};

} // namespace core

// Rhp::log(logger, log_level::kInfo, "loaded {}", name) - formats only when enabled.
template <core::logger L, class... Args>
void log(L& logger, log_level level, std::format_string<Args...> fmt, Args&&... args) {
    if (logger.enabled(level)) {
        logger.write(level, std::format(fmt, std::forward<Args>(args)...));
    }
}

} // namespace Rhp

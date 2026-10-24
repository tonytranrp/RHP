#include <atomic>
#include <concepts>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/log.hpp>

using Rhp::log_level;

namespace {

struct capture_logger {
    log_level min = log_level::kInfo;
    std::vector<std::pair<log_level, std::string>> lines;
    int format_calls = 0;

    [[nodiscard]] bool enabled(log_level level) const noexcept { return level >= min; }
    void write(log_level level, std::string_view message) { lines.emplace_back(level, std::string{message}); }
};

struct counts_formatting {
    int* calls;
};

} // namespace

template <>
struct std::formatter<counts_formatting> : std::formatter<int> {
    auto format(const counts_formatting& c, std::format_context& ctx) const {
        ++*c.calls;
        return std::formatter<int>::format(*c.calls, ctx);
    }
};

TEST_CASE("logger concept", "[core][log]") {
    STATIC_REQUIRE(Rhp::core::logger<capture_logger>);
    STATIC_REQUIRE(Rhp::core::logger<Rhp::core::null_logger>);
    STATIC_REQUIRE(Rhp::core::logger<Rhp::core::stderr_logger>);
}

TEST_CASE("Rhp::log formats only enabled levels", "[core][log]") {
    capture_logger logger;
    int formats = 0;
    Rhp::log(logger, log_level::kDebug, "hidden {}", counts_formatting{&formats});
    REQUIRE(formats == 0);
    REQUIRE(logger.lines.empty());

    Rhp::log(logger, log_level::kWarn, "loaded {} in {} ms", "combat.low_grav", 3);
    REQUIRE(logger.lines.size() == 1);
    REQUIRE(logger.lines[0].first == log_level::kWarn);
    REQUIRE(logger.lines[0].second == "loaded combat.low_grav in 3 ms");
}

TEST_CASE("stderr_logger filtering", "[core][log]") {
    Rhp::core::stderr_logger logger{log_level::kError};
    REQUIRE_FALSE(logger.enabled(log_level::kWarn));
    REQUIRE(logger.enabled(log_level::kCritical));
    REQUIRE_FALSE(logger.enabled(log_level::kOff));
    logger.set_min_level(log_level::kTrace);
    REQUIRE(logger.enabled(log_level::kTrace));
    REQUIRE(Rhp::to_string(log_level::kCritical) == "critical");
}

TEST_CASE("stderr_logger level may change while another thread checks it", "[core][log]") {
    Rhp::core::stderr_logger logger{log_level::kOff};
    std::atomic<int> seen{0};
    std::jthread reader{[&] {
        for (int i = 0; i < 20'000; ++i) {
            if (logger.enabled(log_level::kCritical)) { // use the result: a dead load would be optimized away
                seen.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }};
    for (int i = 0; i < 20'000; ++i) {
        logger.set_min_level(i % 2 == 0 ? log_level::kCritical : log_level::kOff);
    }
    reader.join();
    logger.set_min_level(log_level::kWarn);
    CHECK(logger.min_level() == log_level::kWarn);
    CHECK(logger.enabled(log_level::kError));
    CHECK_FALSE(logger.enabled(log_level::kInfo));
    STATIC_REQUIRE(std::copyable<Rhp::core::stderr_logger>);
    Rhp::core::stderr_logger copy = logger;
    CHECK(copy.min_level() == log_level::kWarn);
}

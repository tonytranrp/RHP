#include <string>
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

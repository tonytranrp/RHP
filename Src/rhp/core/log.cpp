#include <cstdio>
#include <print>

#include <rhp/core/log.hpp>

namespace Rhp::core {

void stderr_logger::write(log_level level, std::string_view message) const {
    if (enabled(level)) {
        std::println(stderr, "[rhp {}] {}", to_string(level), message);
    }
}

} // namespace Rhp::core

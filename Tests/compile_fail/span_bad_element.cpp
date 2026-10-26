// A span of something that isn't a number (or std::byte) must not compile: a typed view only holds
// arithmetic elements.
#include <span>
#include <string>

#include <rhp/script/lib.hpp>

namespace span_bad_element_fixture {

inline float total(std::span<const float> v) {
    return v.empty() ? 0.0f : v[0];
}

using ok_lib = Rhp::lib<"cf_ok">::fn<"total", &total>;

#if defined(RHP_COMPILE_FAIL)
inline std::size_t names(std::span<const std::string> v) {
    return v.size();
}

using bad_lib = Rhp::lib<"cf_bad">::fn<"names", &names>;
#endif

} // namespace span_bad_element_fixture

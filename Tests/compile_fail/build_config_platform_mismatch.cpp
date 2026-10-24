// A translation unit that names another target OS than the one RHP was built for doesn't compile:
// <rhp/build_config.hpp> refuses every RHP_PLATFORM_* but its own.
#if defined(RHP_COMPILE_FAIL)
#if defined(RHP_PLATFORM_WINDOWS)
#define RHP_PLATFORM_LINUX 1
#else
#define RHP_PLATFORM_WINDOWS 1
#endif
#endif

#include <rhp/build_config.hpp>
#include <rhp/core/result.hpp>

namespace build_config_platform_mismatch_fixture {

inline Rhp::result<int> answer() {
    return 42;
}

} // namespace build_config_platform_mismatch_fixture

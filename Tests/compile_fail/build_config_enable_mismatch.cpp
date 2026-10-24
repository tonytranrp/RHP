// A translation unit can't see RHP's headers with an RHP_ENABLE other than the one RHP was built
// with (the library and the headers would disagree about what a host is): <rhp/build_config.hpp>
// stops the build.
#if defined(RHP_COMPILE_FAIL)
#if RHP_ENABLE
#undef RHP_ENABLE
#define RHP_ENABLE 0
#else
#undef RHP_ENABLE
#define RHP_ENABLE 1
#endif
#endif

#include <rhp/build_config.hpp>
#include <rhp/core/result.hpp>

namespace build_config_enable_mismatch_fixture {

inline Rhp::result<int> answer() {
    return 42;
}

} // namespace build_config_enable_mismatch_fixture

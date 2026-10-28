// A translation unit can't see RHP's headers with an RHP_HARDENING other than the one RHP was built
// with (it would compile code the library left out): <rhp/build_config.hpp> stops the build.
#if defined(RHP_COMPILE_FAIL)
#undef RHP_HARDENING
#define RHP_HARDENING 7 // no build has this level
#endif

#include <rhp/build_config.hpp>
#include <rhp/core/hardening.hpp>

namespace build_config_hardening_mismatch_fixture {

inline constexpr bool dev = Rhp::kBuildHardening == Rhp::hardening::kDev;

} // namespace build_config_hardening_mismatch_fixture

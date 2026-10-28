// A config may raise the build's hardening level (RHP_HARDENING), never lower it: a weaker level
// fails where the config names it. (Registered for lan and production builds: in a dev build no
// level is weaker.)
#include <rhp/config/config.hpp>
#include <rhp/core/hardening.hpp>

#if defined(RHP_COMPILE_FAIL)
using broken = Rhp::config<>::hardening<Rhp::hardening::kDev>;
Rhp::hardening unused = broken::hardening_v;
#else
using fine = Rhp::config<>::hardening<Rhp::kBuildHardening>;
Rhp::hardening unused = fine::hardening_v;
#endif

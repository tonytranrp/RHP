#include <rhp/config/config.hpp>

#if defined(RHP_COMPILE_FAIL)
using broken = Rhp::config<>::discovery<int>;
broken::discovery_t* unused = nullptr;
#else
using fine = Rhp::config<>::discovery<Rhp::net::no_discovery>;
fine::discovery_t* unused = nullptr;
#endif

// A config slot is checked where it is written: int is not a Rhp::net::transport.
#include <rhp/config/config.hpp>

#if defined(RHP_COMPILE_FAIL)
using broken = Rhp::config<>::transport<int>;
broken::transport_t* unused = nullptr;
#else
using fine = Rhp::config<>::transport<Rhp::net::tcp>;
fine::transport_t* unused = nullptr;
#endif

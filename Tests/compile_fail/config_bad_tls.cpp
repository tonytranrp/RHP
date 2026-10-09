// A config slot is checked where it is written: a type without server / client factories is not a TLS backend.
#include <rhp/config/config.hpp>
#include <rhp/security/tls/tls.hpp>

struct not_a_tls_backend {
    static constexpr const char* name = "nope";
};

#if defined(RHP_COMPILE_FAIL)
using broken = Rhp::config<>::tls<not_a_tls_backend>;
broken::tls_t* unused = nullptr;
#else
using fine = Rhp::config<>::tls<Rhp::security::tls::none>;
fine::tls_t* unused = nullptr;
#endif

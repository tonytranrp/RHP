// A config slot is checked where it is written: a type without key / trust is not a signer.
#include <rhp/config/config.hpp>
#include <rhp/security/signer.hpp>

struct half_a_signer {
    struct key {};
};

#if defined(RHP_COMPILE_FAIL)
using broken = Rhp::config<>::signer<half_a_signer>;
broken::signer_t* unused = nullptr;
#else
using fine = Rhp::config<>::signer<Rhp::security::unsigned_scripts>;
fine::signer_t* unused = nullptr;
#endif

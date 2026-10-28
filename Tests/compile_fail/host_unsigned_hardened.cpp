// A host runs unsigned scripts (signer<unsigned_scripts>) only at hardening dev: a config above it
// that turns signing off names no host.
#include <rhp/config/config.hpp>
#include <rhp/core/hardening.hpp>
#include <rhp/host/host.hpp>
#include <rhp/security/signer.hpp>

using hardened = Rhp::config<>::hardening<Rhp::hardening::kProduction>;

#if defined(RHP_COMPILE_FAIL)
using broken = Rhp::host<hardened::signer<Rhp::security::unsigned_scripts>>;
broken* unused = nullptr;
#else
using fine = Rhp::host<hardened>;
fine* unused = nullptr;
#endif

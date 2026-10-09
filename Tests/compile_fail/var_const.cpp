// Binding a const object as a writable var must not compile (use ::ro instead).
#include <rhp/script/lib.hpp>

namespace var_const_fixture {

inline int g_mutable = 0;
inline const int g_constant = 1;

using ok_lib = Rhp::lib<"game">::var<"x", &g_mutable>::ro<"y", &g_constant>;

#if defined(RHP_COMPILE_FAIL)
using bad_lib = Rhp::lib<"game">::var<"x", &g_constant>;
#endif

} // namespace var_const_fixture

// Event arguments are plain value types: a reference argument must not compile.
#include <rhp/script/lua_event.hpp>

namespace event_arg_reference_fixture {

inline constexpr Rhp::lua_event<"tests.event_arg", int> ok_event{};

#if defined(RHP_COMPILE_FAIL)
inline constexpr Rhp::lua_event<"tests.event_arg_ref", int&> bad_event{};
#endif

} // namespace event_arg_reference_fixture

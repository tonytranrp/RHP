// An event name that is not dotted lowercase must not compile.
#include <rhp/script/lua_event.hpp>

namespace event_bad_name_fixture {

inline constexpr Rhp::lua_event<"tests.good_event", int> ok_event{};

#if defined(RHP_COMPILE_FAIL)
inline constexpr Rhp::lua_event<"Player Died", int> bad_event{};
#endif

} // namespace event_bad_name_fixture

// An undo that accepts neither the binding's result nor its arguments must not compile.
#include <string>

#include <rhp/script/lib.hpp>

namespace lib_undo_not_invocable_fixture {

inline int spawn(int x) {
    return x;
}

inline void despawn(int) {}

inline void forget(std::string) {}

using ok_lib = Rhp::lib<"game">::fn<"spawn", &spawn, Rhp::undo<&despawn>>;

#if defined(RHP_COMPILE_FAIL)
using bad_lib = Rhp::lib<"game">::fn<"spawn", &spawn, Rhp::undo<&forget>>;
#endif

} // namespace lib_undo_not_invocable_fixture

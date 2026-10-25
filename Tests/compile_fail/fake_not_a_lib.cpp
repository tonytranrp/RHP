// Rhp::test::fake<L> takes a lib: anything else must not compile.
#include <rhp/script/lib.hpp>
#include <rhp/test/fake.hpp>

namespace fake_not_a_lib_fixture {

inline int twice(int x) {
    return 2 * x;
}

using game_lib = Rhp::lib<"game">::fn<"twice", &twice>;
using ok_fake = Rhp::test::fake<game_lib>;

#if defined(RHP_COMPILE_FAIL)
using bad_fake = Rhp::test::fake<int>;
inline constexpr bool kUse = sizeof(bad_fake) > 0;
#endif

} // namespace fake_not_a_lib_fixture

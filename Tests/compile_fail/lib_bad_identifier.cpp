// A binding name that is not a Lua identifier must not compile.
#include <rhp/script/lib.hpp>

namespace lib_bad_identifier_fixture {

inline int find(int x) {
    return x;
}

using ok_lib = Rhp::lib<"game">::fn<"find_it", &find>;

#if defined(RHP_COMPILE_FAIL)
using bad_lib = Rhp::lib<"game">::fn<"find-it", &find>;
#endif

} // namespace lib_bad_identifier_fixture

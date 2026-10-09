// Two entries with the same name in one lib must not compile.
#include <rhp/script/lib.hpp>

namespace lib_duplicate_name_fixture {

inline int find(int x) {
    return x;
}

inline int other(int x) {
    return x;
}

using ok_lib = Rhp::lib<"game">::fn<"find", &find>::fn<"other", &other>;

#if defined(RHP_COMPILE_FAIL)
using bad_lib = Rhp::lib<"game">::fn<"find", &find>::fn<"find", &other>;
#endif

} // namespace lib_duplicate_name_fixture

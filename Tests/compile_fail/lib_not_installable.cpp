// Installing a lib whose binding takes a type with no Rhp::convert must not compile.
#include <rhp/script/lib.hpp>
#include <rhp/script/sandbox.hpp>

namespace lib_not_installable_fixture {

struct no_conversion {};

inline int fine(int x) {
    return x;
}

inline void take(no_conversion) {}

using ok_lib = Rhp::lib<"ok">::fn<"fine", &fine>;
// Declaring it is allowed (handles may come later); installing it is not.
using bad_lib = Rhp::lib<"bad">::fn<"take", &take>;

inline void use(Rhp::script::sandbox& box) {
    (void)box.install<ok_lib>();
#if defined(RHP_COMPILE_FAIL)
    (void)box.install<bad_lib>();
#endif
}

} // namespace lib_not_installable_fixture

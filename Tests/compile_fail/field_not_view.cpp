// Installing a lib with a field of a type no ::view of the tree declares must not compile.
#include <rhp/script/lib.hpp>
#include <rhp/script/sandbox.hpp>

namespace field_not_view_fixture {

struct point {
    float x = 0;
};

struct body {
    point at{};
    int hp = 0;
};

using ok_lib = Rhp::lib<"cf_ok">::view<"point", point>::view<"body", body>::field<"at", &body::at>::field<"hp", &body::hp>;
// Declaring it is allowed (the view may be declared after its fields); installing it is not.
using bad_lib = Rhp::lib<"cf_bad">::view<"body", body>::field<"at", &body::at>;

inline void use(Rhp::script::sandbox& box) {
    (void)box.install<ok_lib>();
#if defined(RHP_COMPILE_FAIL)
    (void)box.install<bad_lib>();
#endif
}

} // namespace field_not_view_fixture

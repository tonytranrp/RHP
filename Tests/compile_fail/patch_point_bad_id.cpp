// A patch point id that is not dotted lowercase must not compile.
#include <rhp/script/patch_point.hpp>

namespace patch_point_bad_id_fixture {

inline int base(int x) {
    return x;
}

inline constexpr Rhp::patch_point<"tests.good_id", &base> ok_point{};

#if defined(RHP_COMPILE_FAIL)
inline constexpr Rhp::patch_point<"Bad.Id", &base> bad_point{};
#endif

} // namespace patch_point_bad_id_fixture

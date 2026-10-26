// A struct view of a type that isn't standard layout (here: virtual functions) must not compile:
// its fields have no fixed offsets to read and restore.
#include <rhp/script/lib.hpp>

namespace view_not_standard_layout_fixture {

struct plain {
    float x = 0;
};

using ok_lib = Rhp::lib<"cf_ok">::view<"plain", plain>::field<"x", &plain::x>;

#if defined(RHP_COMPILE_FAIL)
struct shape {
    virtual ~shape() = default;
    float area = 0;
};

using bad_lib = Rhp::lib<"cf_bad">::view<"shape", shape>;
#endif

} // namespace view_not_standard_layout_fixture

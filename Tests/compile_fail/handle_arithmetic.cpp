// A builtin arithmetic type as a handle must not compile (every int would become a handle).
#include <rhp/script/lib.hpp>

namespace handle_arithmetic_fixture {

struct entity_id {
    int v = 0;
    bool operator==(const entity_id&) const = default;
};

inline bool is_alive(const entity_id& e) {
    return e.v != 0;
}

inline bool is_alive_int(const int& v) {
    return v != 0;
}

using ok_lib = Rhp::lib<"game">::handle<"h", entity_id, &is_alive>;

#if defined(RHP_COMPILE_FAIL)
using bad_lib = Rhp::lib<"game">::handle<"h", int, &is_alive_int>;
#endif

} // namespace handle_arithmetic_fixture

// A property returning several values must not compile: h.name is one value.
#include <tuple>

#include <rhp/core/async.hpp>
#include <rhp/script/lib.hpp>

namespace property_tuple_fixture {

struct handle_id {
    int v = 0;
    bool operator==(const handle_id&) const = default;
};

inline bool alive(const handle_id&) {
    return true;
}

inline int good(handle_id h) {
    return h.v;
}

using ok_lib = Rhp::lib<"cf_ok">::handle<"h", handle_id, &alive>::property<"v", &good>;

#if defined(RHP_COMPILE_FAIL)
inline std::tuple<int, int> bad(handle_id) {
    return {1, 2};
}

using bad_lib = Rhp::lib<"cf_bad">::handle<"h", handle_id, &alive>::property<"x", &bad>;
#endif

} // namespace property_tuple_fixture

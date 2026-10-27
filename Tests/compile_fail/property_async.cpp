// A property must not wait: it can't return Rhp::async<T>.
#include <rhp/core/async.hpp>
#include <rhp/script/lib.hpp>

namespace property_async_fixture {

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
inline Rhp::async<int> bad(handle_id) {
    return Rhp::async<int>::completed(1);
}

using bad_lib = Rhp::lib<"cf_bad">::handle<"h", handle_id, &alive>::property<"x", &bad>;
#endif

} // namespace property_async_fixture

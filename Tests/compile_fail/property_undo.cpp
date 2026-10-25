// A property has nothing to undo: undo<> on it must not compile.
#include <tuple>

#include <rhp/core/async.hpp>
#include <rhp/script/lib.hpp>

namespace property_undo_fixture {

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
inline int bad(handle_id) {
    return 1;
}
inline void undo_bad(handle_id) {}

using bad_lib = Rhp::lib<"cf_bad">::handle<"h", handle_id, &alive>::property<"x", &bad, Rhp::undo<&undo_bad>>;
#endif

} // namespace property_undo_fixture

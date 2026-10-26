// A binding returning a span is called again on every access of its view: undo<> on it must not
// compile (the effect would be journaled once and repeated many times).
#include <span>

#include <rhp/script/lib.hpp>

namespace span_result_undo_fixture {

inline float g_values[4] = {};

inline std::span<float> values() {
    return g_values;
}

using ok_lib = Rhp::lib<"cf_ok">::fn<"values", &values>;

#if defined(RHP_COMPILE_FAIL)
inline void forget() {}

using bad_lib = Rhp::lib<"cf_bad">::fn<"values", &values, Rhp::undo<&forget>>;
#endif

} // namespace span_result_undo_fixture

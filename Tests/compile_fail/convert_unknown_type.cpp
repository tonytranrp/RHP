// A type without an Rhp::convert specialization must be rejected at the call site.
#include <rhp/core/convert.hpp>

namespace {

struct no_conversion {};

[[maybe_unused]] void use() {
    [[maybe_unused]] const Rhp::value ok = Rhp::to_value(1);
#if defined(RHP_COMPILE_FAIL)
    [[maybe_unused]] const Rhp::value bad = Rhp::to_value(no_conversion{});
#endif
}

} // namespace

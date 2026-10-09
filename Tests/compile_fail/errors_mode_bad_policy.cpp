// Error-mode slots only accept types satisfying Rhp::errors::mode.
#include <rhp/core/errors_mode.hpp>

namespace {

struct not_a_mode {};

template <Rhp::errors::mode M>
struct uses_mode {};

[[maybe_unused]] uses_mode<Rhp::errors::expected> ok;

#if defined(RHP_COMPILE_FAIL)
[[maybe_unused]] uses_mode<not_a_mode> bad;
#endif

} // namespace

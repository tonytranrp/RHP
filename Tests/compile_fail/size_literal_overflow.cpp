// A size literal that overflows std::size_t must be a compile error, not a wrapped value.
#include <cstddef>

#include <rhp/utils/units.hpp>

using namespace Rhp::literals;

[[maybe_unused]] constexpr std::size_t kOk = 64_MiB;

#if defined(RHP_COMPILE_FAIL)
[[maybe_unused]] constexpr std::size_t kBad = 18446744073709551615_GiB;
#endif

// <windows.h> before RHP, without NOMINMAX or WIN32_LEAN_AND_MEAN: its min / max macros (and
// everything else it defines) must not break RHP's public headers.
#include <windows.h>

#include <rhp/rhp.hpp>

int main() {
    // Instantiates the paths that use std::numeric_limits<...>::max.
    const auto big = Rhp::to_value(static_cast<unsigned long long>(1) << 40);
    const auto back = Rhp::from_value<unsigned long long>(big);
    return back && *back == (static_cast<unsigned long long>(1) << 40) ? 0 : 1;
}

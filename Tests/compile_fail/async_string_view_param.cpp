// An asynchronous binding that takes a std::string_view must not compile: the view would
// outlive the Lua string it points into once the binding returns.
#include <string>
#include <string_view>
#include <utility>

#include <rhp/core/async.hpp>
#include <rhp/core/result.hpp>
#include <rhp/script/lib.hpp>

namespace async_string_view_param_fixture {

inline Rhp::async<std::string> good(std::string text) {
    return Rhp::async<std::string>::ready(std::move(text));
}

using ok_lib = Rhp::lib<"cf_ok">::fn<"good", &good>;

#if defined(RHP_COMPILE_FAIL)
inline Rhp::async<int> bad(std::string_view) {
    return Rhp::async<int>::ready(0);
}

using bad_lib = Rhp::lib<"cf_bad">::fn<"bad", &bad>;
#endif

} // namespace async_string_view_param_fixture

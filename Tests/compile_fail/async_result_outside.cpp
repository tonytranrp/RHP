// Rhp::result<Rhp::async<T>> must not compile: an async that fails at once is async<T>::ready(error).
#include <string>
#include <string_view>
#include <utility>

#include <rhp/core/async.hpp>
#include <rhp/core/result.hpp>
#include <rhp/script/lib.hpp>

namespace async_result_outside_fixture {

inline Rhp::async<std::string> good(std::string text) {
    return Rhp::async<std::string>::ready(std::move(text));
}

using ok_lib = Rhp::lib<"cf_ok">::fn<"good", &good>;

#if defined(RHP_COMPILE_FAIL)
inline Rhp::result<Rhp::async<int>> bad(int) {
    return Rhp::async<int>::ready(0);
}

using bad_lib = Rhp::lib<"cf_bad">::fn<"bad", &bad>;
#endif

} // namespace async_result_outside_fixture

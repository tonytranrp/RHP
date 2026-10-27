// Rhp::async<Rhp::result<T>> must not compile: the async already carries an error.
#include <string>
#include <utility>

#include <rhp/core/async.hpp>
#include <rhp/core/result.hpp>
#include <rhp/script/lib.hpp>

namespace async_result_inside_fixture {

inline Rhp::async<std::string> good(std::string text) {
    return Rhp::async<std::string>::completed(std::move(text));
}

using ok_lib = Rhp::lib<"cf_ok">::fn<"good", &good>;

#if defined(RHP_COMPILE_FAIL)
inline Rhp::async<Rhp::result<int>> bad(int) {
    return Rhp::async<Rhp::result<int>>::completed(Rhp::result<int>{0});
}

using bad_lib = Rhp::lib<"cf_bad">::fn<"bad", &bad>;
#endif

} // namespace async_result_inside_fixture

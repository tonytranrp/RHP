// An asynchronous binding returning Rhp::async<Rhp::async<T>> must not compile.
#include <string>
#include <utility>

#include <rhp/core/async.hpp>
#include <rhp/script/lib.hpp>

namespace async_nested_fixture {

inline Rhp::async<std::string> good(std::string text) {
    return Rhp::async<std::string>::completed(std::move(text));
}

using ok_lib = Rhp::lib<"cf_ok">::fn<"good", &good>;

#if defined(RHP_COMPILE_FAIL)
inline Rhp::async<Rhp::async<int>> bad(int) {
    return Rhp::async<Rhp::async<int>>::completed(Rhp::async<int>::completed(0));
}

using bad_lib = Rhp::lib<"cf_bad">::fn<"bad", &bad>;
#endif

} // namespace async_nested_fixture

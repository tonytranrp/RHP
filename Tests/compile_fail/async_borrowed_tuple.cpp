// An asynchronous binding whose tuple result holds a std::string_view must not compile.
#include <string>
#include <string_view>
#include <tuple>

#include <rhp/core/async.hpp>
#include <rhp/script/lib.hpp>

namespace async_borrowed_tuple_fixture {

inline Rhp::async<std::tuple<std::string, int>> good(int) {
    return Rhp::async<std::tuple<std::string, int>>::completed(std::tuple<std::string, int>{"ok", 1});
}

using ok_lib = Rhp::lib<"cf_ok">::fn<"good", &good>;

#if defined(RHP_COMPILE_FAIL)
inline Rhp::async<std::tuple<std::string_view, int>> bad(int) {
    return Rhp::async<std::tuple<std::string_view, int>>::completed(std::tuple<std::string_view, int>{});
}

using bad_lib = Rhp::lib<"cf_bad">::fn<"bad", &bad>;
#endif

} // namespace async_borrowed_tuple_fixture

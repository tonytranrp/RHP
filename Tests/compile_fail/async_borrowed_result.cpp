// An asynchronous binding whose result only views memory (std::string_view) must not compile.
#include <string>
#include <string_view>
#include <utility>

#include <rhp/core/async.hpp>
#include <rhp/core/result.hpp>
#include <rhp/script/lib.hpp>

namespace async_borrowed_result_fixture {

inline Rhp::async<std::string> good(std::string text) {
    return Rhp::async<std::string>::completed(std::move(text));
}

using ok_lib = Rhp::lib<"cf_ok">::fn<"good", &good>;

#if defined(RHP_COMPILE_FAIL)
inline Rhp::async<std::string_view> bad(int) {
    return Rhp::async<std::string_view>::completed(std::string_view{});
}

using bad_lib = Rhp::lib<"cf_bad">::fn<"bad", &bad>;
#endif

} // namespace async_borrowed_result_fixture

// A patch point whose result only views memory (std::string_view) must not compile: a Lua
// override's result string is unrooted once the handler returns.
#include <optional>
#include <string>
#include <string_view>

#include <rhp/script/patch_point.hpp>

namespace patch_point_borrowed_result_fixture {

inline std::string owned(int) {
    return "owned";
}

inline constexpr Rhp::patch_point<"tests.cf.owned_result", &owned> ok_point{};

inline std::optional<std::string> maybe_owned(int) {
    return std::nullopt;
}

inline constexpr Rhp::patch_point<"tests.cf.maybe_owned_result", &maybe_owned> ok_optional_point{};

#if defined(RHP_COMPILE_FAIL)
inline std::string_view borrowed(int) {
    return "borrowed";
}

inline constexpr Rhp::patch_point<"tests.cf.borrowed_result", &borrowed> bad_point{};
#endif

} // namespace patch_point_borrowed_result_fixture

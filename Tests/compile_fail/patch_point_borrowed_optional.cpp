// A borrowed result stays borrowed inside std::optional: std::optional<std::string_view> as a
// patch point's result must not compile either.
#include <optional>
#include <string>
#include <string_view>

#include <rhp/script/patch_point.hpp>

namespace patch_point_borrowed_optional_fixture {

inline std::optional<std::string> maybe_owned(int) {
    return std::nullopt;
}

inline constexpr Rhp::patch_point<"tests.cf.optional_owned_result", &maybe_owned> ok_point{};

#if defined(RHP_COMPILE_FAIL)
inline std::optional<std::string_view> maybe_borrowed(int) {
    return std::nullopt;
}

inline constexpr Rhp::patch_point<"tests.cf.optional_borrowed_result", &maybe_borrowed> bad_point{};
#endif

} // namespace patch_point_borrowed_optional_fixture

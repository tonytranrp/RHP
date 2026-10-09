#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/convert.hpp>

using Rhp::errc;
using Rhp::from_value;
using Rhp::to_value;
using Rhp::value;

namespace {

struct vec3 {
    float x = 0;
    float y = 0;
    float z = 0;
    bool operator==(const vec3&) const = default;
};

struct not_convertible {};

} // namespace

// A user-side specialization, exactly as the docs show it.
template <>
struct Rhp::convert<vec3> {
    static value to_value(const vec3& v) { return value{value::map{{"x", v.x}, {"y", v.y}, {"z", v.z}}}; }

    static Rhp::result<vec3> from_value(const value& v) {
        const auto x = v.find("x");
        const auto y = v.find("y");
        const auto z = v.find("z");
        if (x == nullptr || y == nullptr || z == nullptr) {
            return Rhp::fail(errc::kTypeMismatch, "expected {x, y, z}");
        }
        auto fx = Rhp::from_value<float>(*x);
        auto fy = Rhp::from_value<float>(*y);
        auto fz = Rhp::from_value<float>(*z);
        if (!fx || !fy || !fz) {
            return Rhp::fail(errc::kTypeMismatch, "expected numbers");
        }
        return vec3{*fx, *fy, *fz};
    }
};

TEST_CASE("convertible concepts", "[core][convert]") {
    STATIC_REQUIRE(Rhp::wire_convertible<int>);
    STATIC_REQUIRE(Rhp::wire_convertible<std::uint64_t>);
    STATIC_REQUIRE(Rhp::wire_convertible<double>);
    STATIC_REQUIRE(Rhp::wire_convertible<std::string>);
    STATIC_REQUIRE(Rhp::wire_convertible<std::vector<std::optional<int>>>);
    STATIC_REQUIRE(Rhp::wire_convertible<std::map<std::string, std::vector<double>>>);
    STATIC_REQUIRE(Rhp::wire_convertible<vec3>);
    STATIC_REQUIRE(Rhp::to_value_convertible<std::string_view>);
    STATIC_REQUIRE_FALSE(Rhp::from_value_convertible<std::string_view>);
    STATIC_REQUIRE_FALSE(Rhp::to_value_convertible<not_convertible>);
    STATIC_REQUIRE_FALSE(Rhp::wire_convertible<std::vector<not_convertible>>);
}

TEST_CASE("scalars round-trip", "[core][convert]") {
    REQUIRE(from_value<bool>(to_value(true)) == true);
    REQUIRE(from_value<int>(to_value(-5)) == -5);
    REQUIRE(from_value<double>(to_value(0.25)) == 0.25);
    REQUIRE(from_value<std::string>(to_value(std::string{"hi"})) == "hi");
    REQUIRE(to_value("literal") == value{"literal"});
    REQUIRE(to_value(std::string_view{"view"}) == value{"view"});
}

TEST_CASE("integer conversions check range and integrality", "[core][convert]") {
    REQUIRE(from_value<std::uint8_t>(value{255}) == std::uint8_t{255});
    REQUIRE(from_value<std::uint8_t>(value{256}).error().code == errc::kOutOfRange);
    REQUIRE(from_value<std::uint32_t>(value{-1}).error().code == errc::kOutOfRange);
    REQUIRE(from_value<int>(value{3.0}) == 3);
    REQUIRE(from_value<int>(value{3.5}).error().code == errc::kOutOfRange);
    REQUIRE(from_value<int>(value{"3"}).error().code == errc::kTypeMismatch);
    REQUIRE(to_value(std::numeric_limits<std::uint64_t>::max()).is_number());
    REQUIRE(to_value(std::uint64_t{5}).is_integer());
}

TEST_CASE("numbers accept integers", "[core][convert]") {
    REQUIRE(from_value<float>(value{2}) == 2.0f);
    REQUIRE(from_value<double>(value{true}).error().code == errc::kTypeMismatch);
}

TEST_CASE("containers round-trip and report element errors", "[core][convert]") {
    const std::vector<int> ints{1, 2, 3};
    REQUIRE(from_value<std::vector<int>>(to_value(ints)) == ints);

    const value mixed{value::array{1, "two", 3}};
    const auto bad = from_value<std::vector<int>>(mixed);
    REQUIRE_FALSE(bad.has_value());
    REQUIRE(bad.error().code == errc::kTypeMismatch);
    REQUIRE(bad.error().where == "[2]");

    const std::map<std::string, int> m{{"a", 1}, {"b", 2}};
    REQUIRE(from_value<std::map<std::string, int>>(to_value(m)) == m);

    REQUIRE(to_value(std::optional<int>{}).is_nil());
    const auto none = from_value<std::optional<int>>(value{});
    REQUIRE(none.has_value());
    REQUIRE_FALSE(none->has_value());
    const auto nine = from_value<std::optional<int>>(value{9});
    REQUIRE(nine.has_value());
    REQUIRE(nine->value() == 9);
}

TEST_CASE("user specializations plug in", "[core][convert]") {
    const vec3 v{1, 2, 3};
    REQUIRE(from_value<vec3>(to_value(v)) == v);
    REQUIRE(from_value<std::vector<vec3>>(to_value(std::vector<vec3>{v, v}))->size() == 2);
    REQUIRE(from_value<vec3>(value{1}).error().code == errc::kTypeMismatch);
}

TEST_CASE("bytes accept strings", "[core][convert]") {
    const auto b = from_value<value::bytes>(value{"ab"});
    REQUIRE(b.has_value());
    REQUIRE(b->size() == 2);
    REQUIRE((*b)[0] == std::byte{'a'});
}

#include <cstddef>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <rhp/utils/utf8.hpp>

using Rhp::utils::utf8_sequence_length;

TEST_CASE("utf8_sequence_length measures well-formed sequences", "[utils][utf8]") {
    STATIC_REQUIRE(utf8_sequence_length("a", 0) == 1);
    STATIC_REQUIRE(utf8_sequence_length("\xC3\xA9", 0) == 2);         // U+00E9
    STATIC_REQUIRE(utf8_sequence_length("\xE2\x82\xAC", 0) == 3);     // U+20AC
    STATIC_REQUIRE(utf8_sequence_length("\xF0\x9F\x98\x80", 0) == 4); // U+1F600
    STATIC_REQUIRE(utf8_sequence_length("\xF4\x8F\xBF\xBF", 0) == 4); // U+10FFFF
    STATIC_REQUIRE(utf8_sequence_length("\xEF\xBF\xBF", 0) == 3);     // U+FFFF is well-formed UTF-8
    constexpr std::string_view text = "x\xC3\xA9y";
    STATIC_REQUIRE(utf8_sequence_length(text, 1) == 2);
    STATIC_REQUIRE(utf8_sequence_length(text, 3) == 1);
}

TEST_CASE("utf8_sequence_length rejects ill-formed sequences", "[utils][utf8]") {
    STATIC_REQUIRE(utf8_sequence_length("", 0) == 0);
    STATIC_REQUIRE(utf8_sequence_length("a", 1) == 0);                // past the end
    STATIC_REQUIRE(utf8_sequence_length("\x80", 0) == 0);             // a continuation byte
    STATIC_REQUIRE(utf8_sequence_length("\xC0\x80", 0) == 0);         // overlong
    STATIC_REQUIRE(utf8_sequence_length("\xC1\xBF", 0) == 0);         // overlong
    STATIC_REQUIRE(utf8_sequence_length("\xE0\x9F\xBF", 0) == 0);     // overlong
    STATIC_REQUIRE(utf8_sequence_length("\xF0\x8F\xBF\xBF", 0) == 0); // overlong
    STATIC_REQUIRE(utf8_sequence_length("\xED\xA0\x80", 0) == 0);     // a surrogate
    STATIC_REQUIRE(utf8_sequence_length("\xF4\x90\x80\x80", 0) == 0); // above U+10FFFF
    STATIC_REQUIRE(utf8_sequence_length("\xF5\x80\x80\x80", 0) == 0); // 0xF5-0xFF lead nothing
    STATIC_REQUIRE(utf8_sequence_length("\xFF", 0) == 0);
    STATIC_REQUIRE(utf8_sequence_length("\xC3", 0) == 0);     // cut short
    STATIC_REQUIRE(utf8_sequence_length("\xE2\x82", 0) == 0); // cut short
    STATIC_REQUIRE(utf8_sequence_length("\xE2\x82"
                                        "a",
                                        0) == 0); // not a continuation byte
}

#include <string>

#include <catch2/catch_test_macros.hpp>

#include <rhp/net/detail/http.hpp>

TEST_CASE("http: heads are bounded and unambiguous", "[net][http]") {
    using Rhp::net::detail::parse_http_head;
    auto partial = parse_http_head("POST /exec HTTP/1.1\r\nHost: x\r\n", 16);
    REQUIRE(partial);
    CHECK_FALSE(*partial);
    auto valid = parse_http_head("POST /exec HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc", 16);
    REQUIRE(valid);
    REQUIRE(*valid);
    CHECK((**valid).header("host") == "x");
    CHECK((**valid).content_length == 3);
    for (const auto* text : {
             "GET / HTTP/1.1\r\nHost: x\r\nhost: y\r\n\r\n",
             "GET / HTTP/1.1\r\n Host: x\r\n\r\n",
             "POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
             "POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\n",
             "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"}) {
        CHECK_FALSE(parse_http_head(text, 16));
    }
    CHECK_FALSE(parse_http_head(std::string(16385, 'x'), 16));
    CHECK(Rhp::net::detail::http_token("keep-alive, Upgrade", "upgrade"));
    CHECK_FALSE(Rhp::net::detail::http_token("notupgrade", "upgrade"));
}


TEST_CASE("http: field names compare case-insensitively", "[net][http]") {
    auto head = Rhp::net::detail::parse_http_head("GET / HTTP/1.1\r\nHOST: x\r\nX-Rhp-Request: job\r\n\r\n", 0);
    REQUIRE(head);
    REQUIRE(*head);
    CHECK((**head).header("host") == "x");
    CHECK((**head).header("X-RHP-REQUEST") == "job");
    CHECK(Rhp::net::detail::reason_phrase(404) == "Not Found");
}

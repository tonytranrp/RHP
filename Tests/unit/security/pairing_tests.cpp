// Pairing formats: the rhp-pair:// link and the host's book of one-time secrets. No cryptography:
// built with RHP_ENABLE=OFF too.
#include <array>
#include <chrono>
#include <cstddef>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/pairing.hpp>

using Rhp::errc;
using namespace Rhp::security;

namespace {

// 16 bytes in unpadded base64url (the form of key_fingerprint).
constexpr std::string_view kFingerprint = "q83vEjRWeJCrze8SNFZ4kA";

[[nodiscard]] key secret_bytes(unsigned char first) {
    std::array<std::byte, kPairingSecretSize> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::byte>(first + i * 7);
    }
    return *key::from_bytes(bytes);
}

[[nodiscard]] pairing_link sample_link() {
    pairing_link link;
    link.host = "game-pc.local";
    link.port = 47100;
    link.secret = secret_bytes(0xf0);
    link.fingerprint = kFingerprint;
    link.name = "Living room PC";
    return link;
}

[[nodiscard]] std::vector<std::byte> bytes_of(const key& k) {
    return {k.bytes().begin(), k.bytes().end()};
}

// The secret's text from a formatted link.
[[nodiscard]] std::string secret_text() {
    const std::string text = *sample_link().to_text();
    const auto at = text.find("secret=") + 7;
    return text.substr(at, text.find('&', at) - at);
}

} // namespace

TEST_CASE("pairing link: format and parse round trip", "[security][pairing]") {
    const pairing_link link = sample_link();
    auto text = link.to_text();
    REQUIRE(text);
    CHECK(text->starts_with("rhp-pair://game-pc.local:47100?secret="));
    CHECK(text->ends_with(std::format("&fp={}&name=Living%20room%20PC", kFingerprint)));
    CHECK(secret_text().size() == 43);

    auto back = pairing_link::parse(*text);
    REQUIRE(back);
    CHECK(back->host == link.host);
    CHECK(back->port == link.port);
    CHECK(bytes_of(back->secret) == bytes_of(link.secret));
    CHECK(back->fingerprint == link.fingerprint);
    CHECK(back->name == link.name);
    CHECK(*back->to_text() == *text);
}

TEST_CASE("pairing link: IPv6 hosts go in brackets", "[security][pairing]") {
    pairing_link link = sample_link();
    link.host = "fe80::1";
    link.name.clear();
    auto text = link.to_text();
    REQUIRE(text);
    CHECK(text->starts_with("rhp-pair://[fe80::1]:47100?"));
    CHECK(text->find("name=") == std::string::npos);
    auto back = pairing_link::parse(*text);
    REQUIRE(back);
    CHECK(back->host == "fe80::1");
    CHECK(back->name.empty());

    auto v4 = pairing_link::parse(std::format("RHP-PAIR://192.168.1.20:1?fp={}&secret={}", kFingerprint, secret_text()));
    REQUIRE(v4);
    CHECK(v4->host == "192.168.1.20");
    CHECK(v4->port == 1);
}

TEST_CASE("pairing link: names are percent-encoded UTF-8", "[security][pairing]") {
    pairing_link link = sample_link();
    link.name = "Caf\xc3\xa9 & bar?";
    auto text = link.to_text();
    REQUIRE(text);
    CHECK(text->ends_with("&name=Caf%C3%A9%20%26%20bar%3F"));
    CHECK(pairing_link::parse(*text)->name == link.name);
}

TEST_CASE("pairing link: malformed links are refused", "[security][pairing]") {
    const std::string secret = secret_text();
    const std::string fp{kFingerprint};
    const std::vector<std::string> bad{
        "",
        std::format("http://host:1?secret={}&fp={}", secret, fp),
        std::format("rhp-pair:host:1?secret={}&fp={}", secret, fp),
        std::format("rhp-pair://host?secret={}&fp={}", secret, fp),                  // no port
        std::format("rhp-pair://host:0?secret={}&fp={}", secret, fp),                // port 0
        std::format("rhp-pair://host:65536?secret={}&fp={}", secret, fp),            // port too big
        std::format("rhp-pair://host:080?secret={}&fp={}", secret, fp),              // leading zero
        std::format("rhp-pair://host:1x?secret={}&fp={}", secret, fp),               // not a number
        std::format("rhp-pair://fe80::1:1?secret={}&fp={}", secret, fp),             // IPv6 without brackets
        std::format("rhp-pair://[fe80::1:1?secret={}&fp={}", secret, fp),            // unclosed bracket
        std::format("rhp-pair://[host]:1?secret={}&fp={}", secret, fp),              // brackets around a name
        std::format("rhp-pair://user@host:1?secret={}&fp={}", secret, fp),           // user info
        std::format("rhp-pair://host:1/path?secret={}&fp={}", secret, fp),           // path
        std::format("rhp-pair://host:1?secret={}&fp={}#frag", secret, fp),           // fragment
        std::format("rhp-pair://-host:1?secret={}&fp={}", secret, fp),               // bad label
        std::format("rhp-pair://ho_st:1?secret={}&fp={}", secret, fp),               // bad character
        std::format("rhp-pair://host:1?fp={}", fp),                                  // no secret
        std::format("rhp-pair://host:1?secret={}", secret),                          // no fingerprint
        std::format("rhp-pair://host:1?secret={}&fp={}", secret.substr(1), fp),      // short secret
        std::format("rhp-pair://host:1?secret={}A&fp={}", secret, fp),               // long secret
        std::format("rhp-pair://host:1?secret={}=&fp={}", secret.substr(1), fp),     // padding
        std::format("rhp-pair://host:1?secret={}&fp={}", secret, fp.substr(1)),      // short fingerprint
        std::format("rhp-pair://host:1?secret={}&fp={}B", secret, fp.substr(0, 21)), // non-canonical
        std::format("rhp-pair://host:1?secret={}&fp={}&fp={}", secret, fp, fp),      // repeated key
        std::format("rhp-pair://host:1?secret={}&fp={}&x=1", secret, fp),            // unknown key
        std::format("rhp-pair://host:1?secret={}&fp={}&", secret, fp),               // empty field
        std::format("rhp-pair://host:1?secret={}&fp={}&name", secret, fp),           // no value
        std::format("rhp-pair://host:1?secret={}&fp={}&name=a%0Ab", secret, fp),     // control character
        std::format("rhp-pair://host:1?secret={}&fp={}&name=a%2", secret, fp),       // cut escape
        std::format("rhp-pair://host:1?secret={}&fp={}&name=a b", secret, fp),       // unescaped space
        std::format("rhp-pair://host:1?secret={}&fp={}&name={}", secret, fp, std::string(129, 'n')),
    };
    for (const auto& text : bad) {
        INFO(text);
        auto link = pairing_link::parse(text);
        REQUIRE_FALSE(link);
        CHECK(link.error().code == errc::kInvalidArgument);
    }
    CHECK(pairing_link::parse(std::format("rhp-pair://host:65535?secret={}&fp={}&name={}", secret, fp, std::string(128, 'n'))));
}

TEST_CASE("pairing link: to_text checks its fields", "[security][pairing]") {
    auto refused = [](const pairing_link& link) {
        auto text = link.to_text();
        return !text && text.error().code == errc::kInvalidArgument;
    };
    pairing_link link = sample_link();
    link.port = 0;
    CHECK(refused(link));
    link = sample_link();
    link.host = "bad host";
    CHECK(refused(link));
    link = sample_link();
    link.secret = *key::from_bytes(std::vector<std::byte>(16));
    CHECK(refused(link));
    link = sample_link();
    link.fingerprint = "abc";
    CHECK(refused(link));
    link = sample_link();
    link.name = "a\nb";
    CHECK(refused(link));
}

TEST_CASE("pairing book: a secret is accepted once", "[security][pairing]") {
    pairing_book book;
    const auto now = pairing_book::clock::now();
    auto first = book.issue(std::chrono::minutes{5}, now);
    auto second = book.issue(std::chrono::minutes{5}, now);
    REQUIRE(first);
    REQUIRE(second);
    CHECK(first->value.bytes().size() == kPairingSecretSize);
    CHECK(bytes_of(first->value) != bytes_of(second->value));
    CHECK(first->expires == now + std::chrono::minutes{5});
    CHECK(book.outstanding(now) == 2);

    CHECK(book.consume(second->value.bytes(), now));
    CHECK(book.consume(second->value.bytes(), now).error().code == errc::kAuth);
    CHECK(book.outstanding(now) == 1);

    std::vector<std::byte> wrong = bytes_of(first->value);
    wrong.back() ^= std::byte{1};
    CHECK(book.consume(wrong, now).error().code == errc::kAuth);
    CHECK(book.consume(std::span{first->value.bytes()}.first(16), now).error().code == errc::kAuth);
    CHECK(book.consume(first->value.bytes(), now));
    CHECK(book.outstanding(now) == 0);
}

TEST_CASE("pairing book: secrets expire", "[security][pairing]") {
    pairing_book book;
    const auto now = pairing_book::clock::now();
    auto secret = book.issue(std::chrono::seconds{30}, now);
    REQUIRE(secret);
    CHECK(book.outstanding(now + std::chrono::seconds{29}) == 1);
    CHECK(book.outstanding(now + std::chrono::seconds{30}) == 0);
    CHECK(book.consume(secret->value.bytes(), now + std::chrono::seconds{30}).error().code == errc::kExpired);
    CHECK(book.consume(secret->value.bytes(), now).error().code == errc::kAuth); // removed when found expired

    CHECK(book.issue(std::chrono::seconds{0}, now).error().code == errc::kInvalidArgument);
    auto later = book.issue(std::chrono::seconds{1}, now);
    REQUIRE(later);
    book.clear();
    CHECK(book.consume(later->value.bytes(), now).error().code == errc::kAuth);
}

TEST_CASE("pairing book: capacity counts unexpired secrets", "[security][pairing]") {
    pairing_book book{2};
    const auto now = pairing_book::clock::now();
    REQUIRE(book.issue(std::chrono::seconds{10}, now));
    REQUIRE(book.issue(std::chrono::seconds{20}, now));
    CHECK(book.issue(std::chrono::seconds{20}, now).error().code == errc::kLimitExceeded);
    CHECK(book.issue(std::chrono::seconds{20}, now + std::chrono::seconds{10}));
}

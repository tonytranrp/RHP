// Operator certificates (decision AL11): issuing, the encoding and the .rhpcert text, the trusted-CA
// file, and verify's refusals (expired, wrong CA, critical options, tampering).
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/role.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/operator_cert.hpp>

using Rhp::errc;
using namespace Rhp::security;

namespace operator_cert_fixtures {

constexpr std::uint64_t kNow = 1'800'000'000; // Unix seconds

[[nodiscard]] std::chrono::system_clock::time_point at(std::uint64_t seconds) {
    return std::chrono::system_clock::time_point{std::chrono::seconds{seconds}};
}

[[nodiscard]] operator_cert_fields fields_for(const ed25519_secret_key& operator_key) {
    operator_cert_fields f;
    f.serial = 7;
    f.principal = "alice@ops";
    const auto pub_key = operator_key.public_key(); // bytes() views it: keep it alive
    const auto pub = pub_key.bytes();
    f.pub.assign(pub.begin(), pub.end());
    f.not_before = kNow - 60;
    f.not_after = kNow + 3600;
    f.max_role = Rhp::role::kPatch;
    f.apps = {"game", "editor", "game"};
    f.envs = {"prod"};
    f.scopes = {"lib:economy.*"};
    return f;
}

struct pki {
    ed25519_secret_key ca = *ed25519_secret_key::generate();
    ed25519_secret_key op = *ed25519_secret_key::generate();

    [[nodiscard]] trusted_cas cas() const {
        trusted_cas out;
        REQUIRE(out.add({"ops", ca.public_key(), ""}));
        return out;
    }
};

} // namespace operator_cert_fixtures

using namespace operator_cert_fixtures;

TEST_CASE("operator certs: issue then verify", "[security][opcert]") {
    pki k;
    auto cert = issue_operator_cert(k.ca, fields_for(k.op));
    REQUIRE(cert);
    CHECK(cert->id() == "alice@ops#7");
    CHECK(cert->fields.apps == std::vector<std::string>{"editor", "game"}); // canonical: sorted and unique
    CHECK(*cert->operator_key() == k.op.public_key());
    const trusted_cas cas = k.cas();
    const auto ca = verify_operator_cert(*cert, cas, at(kNow));
    REQUIRE(ca);
    CHECK((*ca)->name == "ops");
}

TEST_CASE("operator certs: the encoding and the text form round trip", "[security][opcert]") {
    pki k;
    auto cert = issue_operator_cert(k.ca, fields_for(k.op));
    REQUIRE(cert);
    auto bytes = encode_operator_cert(*cert);
    REQUIRE(bytes);
    auto back = decode_operator_cert(*bytes);
    REQUIRE(back);
    CHECK(back->fields == cert->fields);
    CHECK(back->body == cert->body);
    CHECK(back->sig == cert->sig);

    auto text = operator_cert_to_text(*cert);
    REQUIRE(text);
    CHECK(text->find("-----BEGIN RHP OPERATOR CERTIFICATE-----") != std::string::npos);
    auto parsed = operator_cert_from_text(*text);
    REQUIRE(parsed);
    CHECK(parsed->fields == cert->fields);
    CHECK(verify_operator_cert(*parsed, k.cas(), at(kNow)));

    const auto path = std::filesystem::temp_directory_path() / "rhp_opcert_test.rhpcert";
    REQUIRE(save_operator_cert(path.string(), *cert));
    auto loaded = load_operator_cert(path.string());
    std::filesystem::remove(path);
    REQUIRE(loaded);
    CHECK(loaded->fields == cert->fields);
}

TEST_CASE("operator certs: outside the validity window is expired", "[security][opcert]") {
    pki k;
    auto cert = issue_operator_cert(k.ca, fields_for(k.op));
    REQUIRE(cert);
    CHECK(verify_operator_cert(*cert, k.cas(), at(kNow + 3600)).error().code == errc::kExpired); // not_after is exclusive
    CHECK(verify_operator_cert(*cert, k.cas(), at(kNow - 61)).error().code == errc::kExpired);
    CHECK(verify_operator_cert(*cert, k.cas(), at(kNow + 3599)));
}

TEST_CASE("operator certs: a CA the host doesn't trust is refused", "[security][opcert]") {
    pki k;
    const auto other = *ed25519_secret_key::generate();
    auto cert = issue_operator_cert(other, fields_for(k.op));
    REQUIRE(cert);
    CHECK(verify_operator_cert(*cert, k.cas(), at(kNow)).error().code == errc::kBadSignature);
    // A trusted CA's key in the cert, someone else's signature.
    cert->ca = k.ca.public_key();
    CHECK(verify_operator_cert(*cert, k.cas(), at(kNow)).error().code == errc::kBadSignature);
}

TEST_CASE("operator certs: an unknown critical option refuses the certificate", "[security][opcert]") {
    pki k;
    for (const char* option : {"source-address", "observe-only", "frobnicate"}) {
        auto f = fields_for(k.op);
        f.critical = {option};
        auto cert = issue_operator_cert(k.ca, f);
        REQUIRE(cert);
        CHECK(verify_operator_cert(*cert, k.cas(), at(kNow)).error().code == errc::kForbidden);
    }
}

TEST_CASE("operator certs: fields changed after signing are refused", "[security][opcert]") {
    pki k;
    auto cert = issue_operator_cert(k.ca, fields_for(k.op));
    REQUIRE(cert);
    cert->fields.max_role = Rhp::role::kAdmin;
    CHECK(verify_operator_cert(*cert, k.cas(), at(kNow)).error().code == errc::kBadSignature);
    auto again = issue_operator_cert(k.ca, fields_for(k.op));
    REQUIRE(again);
    again->body.back() = static_cast<std::byte>(static_cast<unsigned>(again->body.back()) ^ 1u);
    CHECK_FALSE(verify_operator_cert(*again, k.cas(), at(kNow)));
}

TEST_CASE("operator certs: issuing refuses invalid fields", "[security][opcert]") {
    pki k;
    auto f = fields_for(k.op);
    f.serial = 0;
    CHECK(issue_operator_cert(k.ca, f).error().code == errc::kInvalidArgument);
    f = fields_for(k.op);
    f.not_after = f.not_before;
    CHECK_FALSE(issue_operator_cert(k.ca, f));
    f = fields_for(k.op);
    f.envs = {"staging"};
    CHECK_FALSE(issue_operator_cert(k.ca, f));
    f = fields_for(k.op);
    f.alg = "p256";
    CHECK_FALSE(issue_operator_cert(k.ca, f));
    f = fields_for(k.op);
    f.pub.pop_back();
    CHECK_FALSE(issue_operator_cert(k.ca, f));
}

TEST_CASE("operator certs: the trusted CA file", "[security][opcert]") {
    pki k;
    const auto dev = *ed25519_secret_key::generate();
    const std::string text = "# operator CAs\n" + trusted_ca_line("ops", k.ca.public_key(), "prod") + "\n" + trusted_ca_line("lab", dev.public_key(), "dev") + "  # a comment\n" +
                             trusted_ca_line("plain", ed25519_secret_key::generate()->public_key()) + "\n";
    auto cas = trusted_cas::parse(text);
    REQUIRE(cas);
    REQUIRE(cas->size() == 3);
    CHECK(cas->find(k.ca.public_key())->env == "prod");
    CHECK(cas->find(dev.public_key())->env == "dev");
    CHECK(cas->entries()[2].env.empty());
    CHECK_FALSE(trusted_cas::parse("ops " + k.ca.public_key().to_base64() + " env=staging"));
    CHECK_FALSE(trusted_cas::parse("ops " + k.ca.public_key().to_base64() + " prod"));
    CHECK(trusted_cas::parse("a " + k.ca.public_key().to_base64() + "\nb " + k.ca.public_key().to_base64()).error().code == errc::kInvalidArgument);
}

TEST_CASE("operator certs: the CA key file round trips", "[security][opcert]") {
    auto ca = operator_ca_key::generate("ops", "prod");
    REQUIRE(ca);
    auto back = operator_ca_key::parse(ca->to_text());
    REQUIRE(back);
    CHECK(back->name == "ops");
    CHECK(back->env == "prod");
    CHECK(back->secret.public_key() == ca->secret.public_key());
    CHECK(ca->trusted_line() == trusted_ca_line("ops", ca->secret.public_key(), "prod"));
    CHECK_FALSE(operator_ca_key::generate("two words"));
    CHECK_FALSE(operator_ca_key::parse("name = \"x\"\n"));
}

// RHP_ENABLE=OFF: keys and signer files still load; nothing can be signed or checked.
#include <cstddef>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/value.hpp>
#include <rhp/security/certified.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/identity_file.hpp>
#include <rhp/security/operator_cert.hpp>
#include <rhp/security/key_handle.hpp>

using Rhp::errc;
using namespace Rhp::security;

TEST_CASE("disabled signing: keys load while signing and checking report kDisabled", "[security][disabled]") {
    auto secret = ed25519_secret_key::generate();
    REQUIRE(secret);
    auto again = ed25519_secret_key::from_base64(secret->to_base64());
    REQUIRE(again);
    const signing_key key{"dev", *again};
    CHECK(key.sign("return 1").error().code == errc::kDisabled);

    auto trust = trusted_signers::parse("dev AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n");
    REQUIRE(trust);
    CHECK(trust->size() == 1);
    CHECK(trust->verify("return 1", Rhp::value{}).error().code == errc::kDisabled);

    auto id = identity_file::generate("dev");
    REQUIRE(id);
    CHECK(identity_file::parse(id->to_text())->name == "dev");
}

TEST_CASE("disabled signing: operator certificates and certified signatures report kDisabled", "[security][disabled]") {
    auto ca = operator_ca_key::generate("ops");
    REQUIRE(ca);
    CHECK(operator_ca_key::parse(ca->to_text())->name == "ops");
    auto cas = trusted_cas::parse("ops AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= env=prod\n");
    REQUIRE(cas);
    operator_cert_fields f;
    f.serial = 1;
    f.principal = "alice";
    f.pub.resize(32);
    f.not_before = 1;
    f.not_after = 2;
    CHECK(issue_operator_cert(ca->secret, f).error().code == errc::kDisabled);
    const certified::trust trust{*cas};
    CHECK(trust.verify("return 1", Rhp::value{}).error().code == errc::kDisabled);
    CHECK(certified::key{}.sign("return 1").error().code == errc::kDisabled);
}

TEST_CASE("disabled key handles: none can be made and nothing verifies", "[security][disabled]") {
    const std::vector<std::byte> seed(32, std::byte{7});
    CHECK(key_handle::from_private_key(key_algorithm::kEd25519, seed).error().code == errc::kDisabled);
    CHECK(key_handle::from_callback(key_algorithm::kEd25519, seed, {}).error().code == errc::kDisabled);
    CHECK(generate_private_key(key_algorithm::kP256).error().code == errc::kDisabled);
    CHECK(verify(key_algorithm::kEd25519, seed, seed, std::vector<std::byte>(64)).error().code == errc::kDisabled);
    CHECK(key_handle{}.sign(seed).error().code == errc::kDisabled);
}

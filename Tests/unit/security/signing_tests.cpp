#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/hash.hpp>
#include <rhp/security/identity_file.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/signer.hpp>

using Rhp::errc;
using Rhp::value;
using namespace Rhp::security;

namespace {

std::vector<std::byte> from_hex(std::string_view hex) {
    std::vector<std::byte> out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        const auto nibble = [](char c) { return static_cast<unsigned>(c <= '9' ? c - '0' : c - 'a' + 10); };
        out.push_back(static_cast<std::byte>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
    }
    return out;
}

value signature_with(std::string signer, std::vector<std::byte> sig) {
    return value{value::map{{value{"signer"}, value{std::move(signer)}}, {value{"sig"}, value{value::bytes(sig.begin(), sig.end())}}}};
}

} // namespace

TEST_CASE("BLAKE2b-256 matches the reference vectors", "[security][hash]") {
    CHECK(to_hex(blake2b_256(std::string_view{})) == "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
    CHECK(to_hex(blake2b_256(std::string_view{"abc"})) == "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
}

TEST_CASE("Ed25519 matches RFC 8032 test 1", "[security][ed25519]") {
    const auto seed = from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    auto secret = ed25519_secret_key::from_bytes(seed);
    REQUIRE(secret);
    const ed25519_public_key pub = secret->public_key();
    const auto want_pub = from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    CHECK(std::vector<std::byte>(pub.bytes().begin(), pub.bytes().end()) == want_pub);
    const auto sig = secret->sign({});
    const auto want_sig = from_hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    CHECK(std::vector<std::byte>(sig.begin(), sig.end()) == want_sig);
    CHECK(ed25519_check(pub, sig, {}));
    std::array<std::byte, 1> other{std::byte{1}};
    CHECK_FALSE(ed25519_check(pub, sig, other));
}

TEST_CASE("Ed25519 keys round-trip through base64 and reject bad sizes", "[security][ed25519]") {
    auto k = ed25519_secret_key::generate();
    REQUIRE(k);
    auto again = ed25519_secret_key::from_base64(k->to_base64());
    REQUIRE(again);
    CHECK(again->public_key() == k->public_key());
    auto pub = ed25519_public_key::from_base64(k->public_key().to_base64());
    REQUIRE(pub);
    CHECK(*pub == k->public_key());
    CHECK(ed25519_secret_key::from_bytes(std::vector<std::byte>(31)).error().code == errc::kInvalidArgument);
    CHECK(ed25519_public_key::from_bytes(std::vector<std::byte>(33)).error().code == errc::kInvalidArgument);
    CHECK_FALSE(ed25519_secret_key::from_base64("not base64!"));
}

TEST_CASE("a trusted signer's script signature verifies; everything else is kBadSignature", "[security][signing]") {
    const auto dev_secret = *ed25519_secret_key::generate();
    const auto stranger_secret = *ed25519_secret_key::generate();
    const signing_key dev{"dev", dev_secret};
    trusted_signers trust{{"dev", dev_secret.public_key()}};

    const std::string source = "game.gravity = -1.6";
    auto sig = dev.sign(source);
    REQUIRE(sig);
    auto who = trust.verify(source, *sig);
    REQUIRE(who);
    CHECK(*who == "dev");

    // A different source, a nil signature, an unknown signer, the wrong key under a trusted name,
    // a malformed value.
    CHECK(trust.verify("game.gravity = 0", *sig).error().code == errc::kBadSignature);
    CHECK(trust.verify(source, value{}).error().code == errc::kBadSignature);
    CHECK(trust.verify(source, *signing_key{"stranger", stranger_secret}.sign(source)).error().code == errc::kBadSignature);
    CHECK(trust.verify(source, *signing_key{"dev", stranger_secret}.sign(source)).error().code == errc::kBadSignature);
    CHECK(trust.verify(source, value{"sig"}).error().code == errc::kBadSignature);
    CHECK(trust.verify(source, signature_with("dev", std::vector<std::byte>(10))).error().code == errc::kBadSignature);

    // The signature covers the domain prefix too: a raw Ed25519 signature of the source is not one.
    const auto raw = dev_secret.sign(std::as_bytes(std::span{source.data(), source.size()}));
    CHECK(trust.verify(source, signature_with("dev", {raw.begin(), raw.end()})).error().code == errc::kBadSignature);

    CHECK(signing_key{"", dev_secret}.sign(source).error().code == errc::kInvalidArgument);
    CHECK(trust.add("dev", dev_secret.public_key()).error().code == errc::kAlreadyLoaded);
}

TEST_CASE("unsigned_scripts signs nothing and trusts everything", "[security][signing]") {
    const unsigned_scripts::key k;
    const unsigned_scripts::trust t;
    CHECK(k.sign("x")->is_nil());
    CHECK(t.verify("x", value{}) == std::string{});
}

TEST_CASE("trusted signers and keyrings load from text", "[security][files]") {
    const auto a = *ed25519_secret_key::generate();
    const auto b = *ed25519_secret_key::generate();
    auto trust = trusted_signers::parse("# developers\n\ndev " + a.public_key().to_base64() + "\n  qa   " + b.public_key().to_base64() + "  # QA\n");
    REQUIRE(trust);
    CHECK(trust->size() == 2);
    REQUIRE(trust->find("qa") != nullptr);
    CHECK(*trust->find("qa") == b.public_key());
    CHECK(trusted_signers::parse("dev").error().message.find("line 1") != std::string::npos);
    CHECK(trusted_signers::parse("dev AAAA\n").error().code == errc::kInvalidArgument);
    CHECK(trusted_signers::parse("dev " + a.public_key().to_base64() + "\ndev " + b.public_key().to_base64()).error().code == errc::kAlreadyLoaded);
    CHECK(trusted_signers::from_file("no/such/file.pub").error().code == errc::kNotFound);

    const key psk = *key::generate();
    auto ring = keyring::parse("dev admin " + psk.to_base64() + "\nviewer observe " + psk.to_base64() + "\n");
    REQUIRE(ring);
    CHECK(ring->size() == 2);
    REQUIRE(ring->find("viewer") != nullptr);
    CHECK(ring->find("viewer")->granted == Rhp::role::kObserve);
    CHECK(keyring::parse("dev root " + psk.to_base64()).error().code == errc::kInvalidArgument);
    CHECK(keyring::parse("dev admin").error().code == errc::kInvalidArgument);
}

TEST_CASE("identity files round-trip and print the host's lines", "[security][files]") {
    auto id = identity_file::generate("dev");
    REQUIRE(id);
    auto again = identity_file::parse(id->to_text());
    REQUIRE(again);
    CHECK(again->name == "dev");
    REQUIRE(again->signing);
    CHECK(again->signing->public_key() == id->signing->public_key());
    CHECK(std::vector<std::byte>(again->psk.bytes().begin(), again->psk.bytes().end()) == std::vector<std::byte>(id->psk.bytes().begin(), id->psk.bytes().end()));

    // The lines it prints are what the host's files parse.
    auto ring = keyring::parse(id->keyring_line(Rhp::role::kPatch));
    REQUIRE(ring);
    CHECK(ring->find("dev")->granted == Rhp::role::kPatch);
    auto trust = trusted_signers::parse(*id->signers_line());
    REQUIRE(trust);
    auto key = id->signer_key();
    REQUIRE(key);
    CHECK(trust->verify("return 1", *key->sign("return 1")) == std::string{"dev"});

    // A separate signer name.
    auto renamed = identity_file::parse(id->to_text() + "signer = \"build-bot\"\n");
    REQUIRE(renamed);
    CHECK(renamed->signer_key()->name == "build-bot");
    CHECK(renamed->signers_line()->starts_with("build-bot "));

    const auto path = (std::filesystem::temp_directory_path() / "rhp_identity_test.rhpid").string();
    REQUIRE(id->save(path));
#if !defined(_WIN32)
    // Owner-only: other local users can't read the PSK or the signing key.
    const auto perms = std::filesystem::status(path).permissions();
    CHECK((perms & (std::filesystem::perms::group_all | std::filesystem::perms::others_all)) == std::filesystem::perms::none);
#endif
    auto loaded = identity_file::load(path);
    REQUIRE(loaded);
    CHECK(loaded->name == "dev");
    std::filesystem::remove(path);

    CHECK(identity_file::parse("name = dev").error().code == errc::kInvalidArgument);
    CHECK(identity_file::parse("name = \"dev\"").error().code == errc::kInvalidArgument); // no psk
    CHECK(identity_file::parse("colour = \"red\"").error().code == errc::kInvalidArgument);
    CHECK(identity_file::load("no/such/file").error().code == errc::kNotFound);
    CHECK(identity_file::generate("").error().code == errc::kInvalidArgument);
}

TEST_CASE("repeated script signatures and verdicts are remembered but never stretched", "[security][signing]") {
    // A repeated source is signed and verified from the recent-scripts cache: same bytes, same
    // answer, and nothing cached lets a different source, signature or keyring through.
    const auto dev_secret = *ed25519_secret_key::generate();
    const auto other_secret = *ed25519_secret_key::generate();
    const signing_key dev{"dev", dev_secret};
    const std::string source = "return 'cached'";
    const auto first = dev.sign(source);
    const auto second = dev.sign(source);
    REQUIRE(first);
    REQUIRE(second);
    CHECK(*first == *second); // Ed25519 is deterministic: the cache gives the same bytes

    trusted_signers trust{{"dev", dev_secret.public_key()}};
    REQUIRE(trust.verify(source, *first));
    REQUIRE(trust.verify(source, *first)); // from the cache
    CHECK(trust.verify(source + " ", *first).error().code == errc::kBadSignature);

    // The cached signature under a name another keyring gives a different key, or doesn't know.
    trusted_signers other{{"dev", other_secret.public_key()}};
    CHECK(other.verify(source, *first).error().code == errc::kBadSignature);
    trusted_signers nobody{{"someone", other_secret.public_key()}};
    CHECK(nobody.verify(source, *first).error().code == errc::kBadSignature);

    // A flipped bit in the cached signature is a different signature.
    auto bytes = *first->find("sig")->get_if<value::bytes>();
    bytes[5] ^= std::byte{0x01};
    CHECK(trust.verify(source, signature_with("dev", bytes)).error().code == errc::kBadSignature);

    // More distinct scripts than the cache holds still verify (older entries are replaced).
    for (int i = 0; i < 100; ++i) {
        const std::string each = "return " + std::to_string(i);
        const auto s = dev.sign(each);
        REQUIRE(s);
        REQUIRE(trust.verify(each, *s));
    }
    REQUIRE(trust.verify(source, *first));
}

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "release_support.hpp"
#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/value.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/release/release.hpp>
#include <rhp/release/trust.hpp>
#include <rhp/security/hash.hpp>
#include <rhp/security/signer.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/wire/codec/msgpack.hpp>

using Rhp::errc;
using namespace release_test;

namespace {

Rhp::release::manifest full_manifest() {
    Rhp::release::manifest m = manifest_for("game.balance", 7, {{"tuning", "x = 1"}, {"spawns", "y = 2"}});
    m.app = "mygame";
    m.builds = {"1.4.2", "1.4.1"};
    m.platforms = {"windows", "android"};
    m.not_before = 1'700'000'000;
    m.not_after = 1'800'000'000;
    m.run_as = Rhp::role::kAdmin;
    m.libs = {"game", "ui"};
    m.health.fail_events = {"game.crashed"};
    m.health.max_handler_failures = 3;
    for (auto& mod : m.modules) {
        mod.hash = Rhp::security::blake2b_256(mod.name);
    }
    return m;
}

std::vector<std::byte> encode_value(const Rhp::value& v) {
    Rhp::utils::byte_buffer out;
    REQUIRE(Rhp::wire::msgpack::encode(v, out));
    const auto view = out.view();
    return {view.begin(), view.end()};
}

} // namespace

TEST_CASE("release manifest round-trips through its canonical encoding", "[release][manifest]") {
    const auto m = full_manifest();
    const auto body = Rhp::release::encode_manifest(m);
    REQUIRE(body.has_value());
    const auto back = Rhp::release::decode_manifest(*body);
    REQUIRE(back.has_value());
    // Sets come back sorted.
    auto expected = m;
    expected.builds = {"1.4.1", "1.4.2"};
    expected.platforms = {"android", "windows"};
    CHECK(*back == expected);
    // One manifest, one encoding.
    CHECK(*Rhp::release::encode_manifest(*back) == *body);
}

TEST_CASE("release manifest decoding refuses anything not canonical", "[release][manifest]") {
    const auto body = *Rhp::release::encode_manifest(full_manifest());
    auto v = Rhp::wire::msgpack::decode(Rhp::utils::bytes_view{body.data(), body.size()});
    REQUIRE(v.has_value());
    auto& fields = *v->get_if<Rhp::value::map>();

    SECTION("fields out of order") {
        std::swap(fields[1], fields[2]);
        CHECK(Rhp::release::decode_manifest(encode_value(*v)).error().code == errc::kProtocol);
    }
    SECTION("an extra field") {
        fields.emplace_back(Rhp::value{"extra"}, Rhp::value{1});
        CHECK(Rhp::release::decode_manifest(encode_value(*v)).error().code == errc::kProtocol);
    }
    SECTION("an unsorted set") {
        fields[5].second = Rhp::value{Rhp::value::array{Rhp::value{"b"}, Rhp::value{"a"}}};
        const auto r = Rhp::release::decode_manifest(encode_value(*v));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().message.find("canonical") != std::string::npos);
    }
    SECTION("a wrong type") {
        fields[2].second = Rhp::value{"seven"};
        CHECK(Rhp::release::decode_manifest(encode_value(*v)).error().code == errc::kProtocol);
    }
    SECTION("another document") {
        fields[0].second = Rhp::value{"state"};
        CHECK(Rhp::release::decode_manifest(encode_value(*v)).error().code == errc::kProtocol);
    }
    SECTION("garbage") {
        const std::vector<std::byte> junk{std::byte{0xc1}, std::byte{0x00}};
        CHECK(Rhp::release::decode_manifest(junk).error().code == errc::kProtocol);
    }
}

TEST_CASE("release manifest validation", "[release][manifest]") {
    auto m = full_manifest();
    CHECK(Rhp::release::validate(m));
    for (const char* bad : {"", "Game", "game..x", ".game", "game.", "game balance", "a/b"}) {
        auto copy = m;
        copy.channel = bad;
        CHECK(Rhp::release::validate(copy).error().code == errc::kInvalidArgument);
    }
    {
        auto copy = m;
        copy.seq = 0;
        CHECK_FALSE(Rhp::release::validate(copy));
    }
    {
        auto copy = m;
        copy.not_after = copy.not_before;
        CHECK_FALSE(Rhp::release::validate(copy));
    }
    {
        auto copy = m;
        copy.run_as = Rhp::role::kObserve;
        CHECK_FALSE(Rhp::release::validate(copy));
    }
    {
        auto copy = m;
        copy.modules.push_back(copy.modules.front());
        CHECK_FALSE(Rhp::release::validate(copy));
    }
    {
        auto copy = m;
        copy.modules.clear();
        CHECK_FALSE(Rhp::release::validate(copy));
    }
}

TEST_CASE("release ids print as hex and parse back", "[release][manifest]") {
    const auto id = Rhp::security::blake2b_256(std::string_view{"x"});
    const auto hex = Rhp::release::to_hex(id);
    CHECK(hex.size() == 64);
    CHECK(*Rhp::release::id_from_hex(hex) == id);
    CHECK(Rhp::release::short_id(id) == hex.substr(0, 8));
    CHECK_FALSE(Rhp::release::id_from_hex("zz"));
    CHECK_FALSE(Rhp::release::id_from_hex(std::string(64, 'G')));
}

TEST_CASE("a release envelope round-trips with its sources and signatures", "[release][envelope]") {
    const signer dev{"dev"};
    const auto bytes = envelope("game.balance", 1, {{"tuning", "x = 1"}}, dev);
    const auto r = Rhp::release::decode_release(bytes);
    REQUIRE(r.has_value());
    CHECK(r->body.channel == "game.balance");
    CHECK(r->sources == std::vector<std::string>{"x = 1"});
    REQUIRE(r->signatures.size() == 1);
    CHECK(r->signatures[0].signer == "dev");
    CHECK(r->id == Rhp::security::blake2b_256(r->body_bytes));
    CHECK(*Rhp::release::encode_release(*r) == bytes);
}

TEST_CASE("a release envelope whose source was changed is refused", "[release][envelope]") {
    const signer dev{"dev"};
    auto r = *Rhp::release::make_release(manifest_for("game.balance", 1, {{"tuning", "x = 1"}}), {"x = 1"});
    REQUIRE(Rhp::release::sign(r, dev.key()));
    r.sources[0] = "x = 999";
    const auto bytes = *Rhp::release::encode_release(r);
    const auto back = Rhp::release::decode_release(bytes);
    REQUIRE_FALSE(back.has_value());
    CHECK(back.error().code == errc::kIntegrity);
}

TEST_CASE("make_release needs one source per module", "[release][envelope]") {
    CHECK(Rhp::release::make_release(manifest_for("game.x", 1, {{"a", "1"}, {"b", "2"}}), {"only one"}).error().code == errc::kInvalidArgument);
}

TEST_CASE("signing again by the same signer replaces the signature", "[release][envelope]") {
    const signer dev{"dev"};
    auto r = *Rhp::release::make_release(manifest_for("game.x", 1, {{"a", "1"}}), {"1"});
    REQUIRE(Rhp::release::sign(r, dev.key()));
    REQUIRE(Rhp::release::sign(r, dev.key()));
    CHECK(r.signatures.size() == 1);
}

TEST_CASE("trust checks signers, channels, thresholds and revoked keys", "[release][trust]") {
    const signer dev{"dev"};
    const signer ops{"ops"};
    const signer stranger{"stranger"};
    const auto r = *Rhp::release::decode_release(envelope(manifest_for("game.balance", 1, {{"a", "1"}}), {{"a", "1"}}, {&dev, &ops, &stranger}));

    auto t = trust_of({{&dev, {"game.*"}}, {&ops, {"*"}}});
    const auto signers = t.verify(r);
    REQUIRE(signers.has_value());
    CHECK(*signers == std::vector<std::string>{"dev", "ops"});

    REQUIRE(t.set_threshold(2));
    CHECK(t.verify(r));
    REQUIRE(t.set_threshold(3));
    CHECK(t.verify(r).error().code == errc::kBadSignature);

    REQUIRE(t.set_threshold(2));
    const std::vector<Rhp::security::ed25519_public_key> revoked{dev.secret.public_key()};
    CHECK(t.verify(r, revoked).error().code == errc::kBadSignature);

    auto narrow = trust_of({{&dev, {"ui.*"}}});
    const auto refused = narrow.verify(r);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().message.find("may not sign for channel 'game.balance'") != std::string::npos);
}

TEST_CASE("two names for one key count once toward the threshold", "[release][trust]") {
    const signer dev{"dev"};
    signer alias{"alias"};
    alias.secret = dev.secret;
    const auto r = *Rhp::release::decode_release(envelope(manifest_for("game.x", 1, {{"a", "1"}}), {{"a", "1"}}, {&dev, &alias}));
    auto t = trust_of({{&dev, {}}, {&alias, {}}});
    REQUIRE(t.set_threshold(2));
    CHECK(t.verify(r).error().code == errc::kBadSignature);
}

TEST_CASE("an unsigned release is refused", "[release][trust]") {
    const signer dev{"dev"};
    const auto r = *Rhp::release::decode_release(envelope(manifest_for("game.x", 1, {{"a", "1"}}), {{"a", "1"}}, {}));
    const auto t = trust_of({{&dev, {}}});
    const auto out = t.verify(r);
    REQUIRE_FALSE(out.has_value());
    CHECK(out.error().message.find("not signed") != std::string::npos);
}

TEST_CASE("a release signature does not verify a script or a revocation list", "[release][trust]") {
    const signer dev{"dev"};
    const auto r = *Rhp::release::decode_release(envelope(manifest_for("game.x", 1, {{"a", "1"}}), {{"a", "1"}}, {&dev}));
    const auto t = trust_of({{&dev, {}}});
    CHECK(t.verify(Rhp::release::kRevocationSignatureDomain, r.body_bytes, r.signatures, "*").error().code == errc::kBadSignature);
    CHECK(t.verify(Rhp::security::kScriptSignatureDomain, r.body_bytes, r.signatures, "game.x").error().code == errc::kBadSignature);
}

TEST_CASE("trust parses its text form", "[release][trust]") {
    const signer dev{"dev"};
    const signer ops{"ops"};
    const std::string text = "# release keys\n" + std::string{"dev "} + dev.secret.public_key().to_base64() + " game.*,ui.menu\nops " +
                             ops.secret.public_key().to_base64() + "\n";
    const auto t = Rhp::release::trust::parse(text);
    REQUIRE(t.has_value());
    REQUIRE(t->entries().size() == 2);
    CHECK(t->entries()[0].channels == std::vector<std::string>{"game.*", "ui.menu"});
    CHECK(t->entries()[1].channels == std::vector<std::string>{"*"});
    CHECK_FALSE(Rhp::release::trust::parse("dev notbase64"));
    CHECK_FALSE(Rhp::release::trust::parse("dev " + dev.secret.public_key().to_base64() + " Bad.Pattern"));
}

TEST_CASE("channel patterns", "[release][trust]") {
    using Rhp::release::channel_matches;
    CHECK(channel_matches("*", "game.balance"));
    CHECK(channel_matches("game.balance", "game.balance"));
    CHECK(channel_matches("game.*", "game.balance"));
    CHECK(channel_matches("game.*", "game.balance.extra"));
    CHECK_FALSE(channel_matches("game.*", "game"));
    CHECK_FALSE(channel_matches("game.*", "gameplay.x"));
    CHECK_FALSE(channel_matches("game.balance", "game.balance2"));
}

TEST_CASE("revocation lists round-trip canonically and verify", "[release][revocations]") {
    const signer ops{"ops"};
    Rhp::release::revocation_list list;
    list.seq = 3;
    list.issued_at = 1'750'000'000;
    list.releases = {Rhp::security::blake2b_256(std::string_view{"b"}), Rhp::security::blake2b_256(std::string_view{"a"})};
    list.keys = {ops.secret.public_key()};
    list.floors = {{"ui.menu", 4}, {"game.balance", 9}};
    const auto bytes = revocations(list, {&ops});
    const auto back = Rhp::release::decode_revocations(bytes);
    REQUIRE(back.has_value());
    CHECK(back->body.seq == 3);
    CHECK(back->body.floors.front().channel == "game.balance"); // sorted
    CHECK(back->body.releases.size() == 2);
    const auto t = trust_of({{&ops, {"*"}}});
    CHECK(t.verify(*back));
    const auto narrow = trust_of({{&ops, {"game.*"}}});
    CHECK(narrow.verify(*back).error().code == errc::kBadSignature);
}

TEST_CASE("revocation list validation", "[release][revocations]") {
    Rhp::release::revocation_list list;
    CHECK(Rhp::release::encode_revocation_list(list).error().code == errc::kInvalidArgument); // seq 0
    list.seq = 1;
    list.floors = {{"game.x", 1}, {"game.x", 2}};
    CHECK(Rhp::release::encode_revocation_list(list).error().code == errc::kInvalidArgument);
}

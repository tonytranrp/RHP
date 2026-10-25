// Release documents: arbitrary bytes offered to the envelope, revocation and manifest decoders.
// Whatever decodes must encode back to bytes that decode to the same thing, and a manifest body
// that decodes is canonical: it encodes to exactly the bytes it came from.
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "fuzz_support.hpp"

#include <rhp/release/manifest.hpp>
#include <rhp/release/release.hpp>
#include <rhp/security/ed25519.hpp>

namespace {

std::string text_of(const std::vector<std::byte>& bytes) {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

} // namespace

std::vector<std::string> rhp_fuzz_seeds() {
    std::vector<std::string> out;
    const Rhp::security::signing_key dev{"dev", *Rhp::security::ed25519_secret_key::generate()};
    Rhp::release::manifest m;
    m.channel = "game.balance";
    m.seq = 7;
    m.label = "seed";
    m.app = "mygame";
    m.builds = {"1.0"};
    m.platforms = {"linux", "windows"};
    m.libs = {"game"};
    m.health.fail_events = {"game.crashed"};
    m.modules = {{"tuning", {}}, {"spawns", {}}};
    if (auto r = Rhp::release::make_release(m, {"game.speed = 2", "game.spawn(1)"})) {
        (void)Rhp::release::sign(*r, dev);
        out.push_back(text_of(r->body_bytes));
        if (auto e = Rhp::release::encode_release(*r)) {
            out.push_back(text_of(*e));
        }
    }
    Rhp::release::revocation_list list;
    list.seq = 3;
    list.issued_at = 1'760'000'000;
    list.floors = {{"game.balance", 9}};
    list.keys = {dev.secret.public_key()};
    if (auto r = Rhp::release::make_revocations(list)) {
        (void)Rhp::release::sign(*r, dev);
        out.push_back(text_of(r->body_bytes));
        if (auto e = Rhp::release::encode_revocations(*r)) {
            out.push_back(text_of(*e));
        }
    }
    return out;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span<const std::byte> in{reinterpret_cast<const std::byte*>(data), size};
    if (auto m = Rhp::release::decode_manifest(in)) {
        const auto again = Rhp::release::encode_manifest(*m);
        RHP_FUZZ_CHECK(again.has_value());
        RHP_FUZZ_CHECK(std::vector<std::byte>(in.begin(), in.end()) == *again);
    }
    if (auto r = Rhp::release::decode_release(in)) {
        const auto bytes = Rhp::release::encode_release(*r);
        RHP_FUZZ_CHECK(bytes.has_value());
        const auto back = Rhp::release::decode_release(*bytes);
        RHP_FUZZ_CHECK(back.has_value());
        RHP_FUZZ_CHECK(back->id == r->id && back->body == r->body && back->sources == r->sources && back->signatures == r->signatures);
    }
    if (auto l = Rhp::release::decode_revocation_list(in)) {
        const auto again = Rhp::release::encode_revocation_list(*l);
        RHP_FUZZ_CHECK(again.has_value());
        RHP_FUZZ_CHECK(std::vector<std::byte>(in.begin(), in.end()) == *again);
    }
    if (auto r = Rhp::release::decode_revocations(in)) {
        const auto bytes = Rhp::release::encode_revocations(*r);
        RHP_FUZZ_CHECK(bytes.has_value());
        const auto back = Rhp::release::decode_revocations(*bytes);
        RHP_FUZZ_CHECK(back.has_value() && back->body == r->body && back->signatures == r->signatures);
    }
    return 0;
}

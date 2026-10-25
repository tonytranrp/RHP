#pragma once

// Shared pieces of the release tests: keys, a manifest builder and envelope helpers.

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/role.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/release/release.hpp>
#include <rhp/release/trust.hpp>
#include <rhp/security/ed25519.hpp>

namespace release_test {

struct signer {
    std::string name;
    Rhp::security::ed25519_secret_key secret = *Rhp::security::ed25519_secret_key::generate();

    [[nodiscard]] Rhp::security::signing_key key() const { return {name, secret}; }
};

struct module_source {
    std::string name;
    std::string source;
};

inline Rhp::release::manifest manifest_for(std::string channel, std::uint64_t seq, const std::vector<module_source>& modules) {
    Rhp::release::manifest m;
    m.channel = std::move(channel);
    m.seq = seq;
    m.label = "test release";
    for (const module_source& mod : modules) {
        m.modules.push_back(Rhp::release::module_entry{mod.name, {}});
    }
    return m;
}

inline std::vector<std::string> sources_of(const std::vector<module_source>& modules) {
    std::vector<std::string> out;
    for (const module_source& mod : modules) {
        out.push_back(mod.source);
    }
    return out;
}

// A signed release envelope.
inline std::vector<std::byte> envelope(const Rhp::release::manifest& m, const std::vector<module_source>& modules, const std::vector<const signer*>& signers) {
    auto r = Rhp::release::make_release(m, sources_of(modules));
    REQUIRE(r.has_value());
    for (const signer* s : signers) {
        REQUIRE(Rhp::release::sign(*r, s->key()));
    }
    auto bytes = Rhp::release::encode_release(*r);
    REQUIRE(bytes.has_value());
    return *bytes;
}

inline std::vector<std::byte> envelope(std::string channel, std::uint64_t seq, const std::vector<module_source>& modules, const signer& s) {
    return envelope(manifest_for(std::move(channel), seq, modules), modules, {&s});
}

inline Rhp::release::release_id id_of(const std::vector<std::byte>& envelope) {
    auto r = Rhp::release::decode_release(envelope);
    REQUIRE(r.has_value());
    return r->id;
}

inline std::vector<std::byte> revocations(const Rhp::release::revocation_list& list, const std::vector<const signer*>& signers) {
    auto r = Rhp::release::make_revocations(list);
    REQUIRE(r.has_value());
    for (const signer* s : signers) {
        REQUIRE(Rhp::release::sign(*r, s->key()));
    }
    auto bytes = Rhp::release::encode_revocations(*r);
    REQUIRE(bytes.has_value());
    return *bytes;
}

inline Rhp::release::trust trust_of(const std::vector<std::pair<const signer*, std::vector<std::string>>>& keys) {
    Rhp::release::trust t;
    for (const auto& [s, channels] : keys) {
        REQUIRE(t.add(s->name, s->secret.public_key(), channels));
    }
    return t;
}

} // namespace release_test

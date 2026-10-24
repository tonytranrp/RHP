// J: security primitives on the request path: BLAKE2b (script hashes, frame MACs) and Ed25519
// (every patch / admin script is signed by the client and verified by the host).
#include <cstddef>
#include <vector>

#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include <rhp/security/ed25519.hpp>
#include <rhp/security/hash.hpp>

TEST_CASE("bench security: hashing and script signatures", "[bench][security]") {
    const std::vector<std::byte> script(4096, std::byte{'x'});

    BENCHMARK("security rhp: blake2b-256 of 4 KiB") {
        return Rhp::security::blake2b_256(script)[0];
    };

    const auto key = Rhp::security::ed25519_secret_key::generate();
    REQUIRE(key);
    const auto pub = key->public_key();
    const auto signature = key->sign(script);
    BENCHMARK("security rhp: ed25519 sign of 4 KiB") {
        return key->sign(script)[0];
    };
    BENCHMARK("security rhp: ed25519 verify of 4 KiB") {
        return Rhp::security::ed25519_check(pub, signature, script);
    };
}

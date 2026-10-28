// Key handles: software Ed25519 and P-256, callback (hardware) keys, and verify.
#include <algorithm>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/key_handle.hpp>
#include <rhp/security/tls/p256.hpp>

using Rhp::errc;
using namespace Rhp::security;

namespace key_handle_fixtures {

std::vector<std::byte> from_hex(std::string_view hex) {
    std::vector<std::byte> out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        const auto nibble = [](char c) { return static_cast<unsigned>(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10); };
        out.push_back(static_cast<std::byte>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
    }
    return out;
}

std::span<const std::byte> text_bytes(std::string_view text) {
    return std::as_bytes(std::span{text.data(), text.size()});
}

// Whether this build has a TLS backend to run P-256 on.
bool has_p256() {
    return !Rhp::security::tls::detail::p256_backend().empty();
}

// RFC 6979 A.2.5: the P-256 key, and its SHA-256 signatures of "sample" and "test".
constexpr std::string_view kP256Private = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
constexpr std::string_view kP256Public = "04"
                                         "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
                                         "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
constexpr std::string_view kP256SampleSig = "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
                                            "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8";
constexpr std::string_view kP256TestSig = "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367"
                                          "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083";

} // namespace key_handle_fixtures

using namespace key_handle_fixtures;

TEST_CASE("key algorithms have names", "[security][key_handle]") {
    CHECK(to_string(key_algorithm::kEd25519) == "ed25519");
    CHECK(to_string(key_algorithm::kP256) == "p256");
    CHECK(parse_key_algorithm("p256") == key_algorithm::kP256);
    CHECK(parse_key_algorithm("ed25519") == key_algorithm::kEd25519);
    CHECK_FALSE(parse_key_algorithm("rsa"));
}

TEST_CASE("an Ed25519 key handle matches RFC 8032", "[security][key_handle]") {
    // Tests 1 (empty message) and 2 (one byte).
    struct rfc_vector {
        std::string_view seed, pub, message, sig;
    };
    const rfc_vector vectors[] = {
        {"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
        {"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
    };
    for (const rfc_vector& v : vectors) {
        auto handle = key_handle::from_private_key(key_algorithm::kEd25519, from_hex(v.seed));
        REQUIRE(handle);
        CHECK(handle->alg() == key_algorithm::kEd25519);
        CHECK(std::vector<std::byte>(handle->public_key().begin(), handle->public_key().end()) == from_hex(v.pub));
        const auto message = from_hex(v.message);
        auto sig = handle->sign(message);
        REQUIRE(sig);
        CHECK(*sig == from_hex(v.sig));
        CHECK(verify(key_algorithm::kEd25519, handle->public_key(), message, *sig));
    }
}

TEST_CASE("Ed25519 key handles round-trip and refuse what isn't theirs", "[security][key_handle]") {
    auto secret = generate_private_key(key_algorithm::kEd25519);
    REQUIRE(secret);
    auto handle = key_handle::from_private_key(key_algorithm::kEd25519, secret->bytes());
    REQUIRE(handle);
    const auto same = key_handle::from_ed25519(*ed25519_secret_key::from_bytes(secret->bytes()));
    REQUIRE(same);
    CHECK(std::ranges::equal(same->public_key(), handle->public_key()));
    CHECK(same->fingerprint() == handle->fingerprint());

    const auto other = *key_handle::from_private_key(key_algorithm::kEd25519, generate_private_key(key_algorithm::kEd25519)->bytes());
    const auto message = text_bytes("rhp/device/client");
    const auto sig = *handle->sign(message);
    CHECK(sig.size() == key_handle::kSignatureSize);
    CHECK(verify(key_algorithm::kEd25519, handle->public_key(), message, sig));
    CHECK(verify(key_algorithm::kEd25519, other.public_key(), message, sig).error().code == errc::kBadSignature);
    CHECK(verify(key_algorithm::kEd25519, handle->public_key(), text_bytes("rhp/device/host"), sig).error().code == errc::kBadSignature);
    auto tampered = sig;
    tampered[3] ^= std::byte{1};
    CHECK(verify(key_algorithm::kEd25519, handle->public_key(), message, tampered).error().code == errc::kBadSignature);
    CHECK(verify(key_algorithm::kEd25519, handle->public_key(), message, std::span{sig}.first(63)).error().code == errc::kBadSignature);
    CHECK(verify(key_algorithm::kP256, handle->public_key(), message, sig).error().code == errc::kBadSignature);

    CHECK(key_handle::from_private_key(key_algorithm::kEd25519, std::vector<std::byte>(31)).error().code == errc::kInvalidArgument);
    CHECK(key_handle{}.empty());
    CHECK(key_handle{}.sign(message).error().code == errc::kInvalidArgument);
}

TEST_CASE("fingerprints are short and stable and name the algorithm", "[security][key_handle]") {
    const auto handle = *key_handle::from_private_key(key_algorithm::kEd25519, from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
    const std::string fp = handle.fingerprint();
    CHECK(fp.size() == 22);
    CHECK(fp.find_first_of("+/=") == std::string::npos);
    CHECK(fp == key_fingerprint(key_algorithm::kEd25519, handle.public_key()));
    // The same bytes under another algorithm name are another key.
    std::vector<std::byte> pub65(65);
    pub65[0] = std::byte{4};
    CHECK(key_fingerprint(key_algorithm::kP256, pub65) != key_fingerprint(key_algorithm::kEd25519, std::span{pub65}.first(32)));
}

TEST_CASE("a P-256 key handle matches RFC 6979 A.2.5", "[security][key_handle][p256]") {
    if (!has_p256()) {
        CHECK(key_handle::from_private_key(key_algorithm::kP256, from_hex(kP256Private)).error().code == errc::kDisabled);
        CHECK(verify(key_algorithm::kP256, from_hex(kP256Public), text_bytes("sample"), from_hex(kP256SampleSig)).error().code == errc::kDisabled);
        SKIP("no TLS backend: P-256 reports kDisabled");
    }
    auto handle = key_handle::from_private_key(key_algorithm::kP256, from_hex(kP256Private));
    REQUIRE(handle);
    CHECK(handle->alg() == key_algorithm::kP256);
    CHECK(std::vector<std::byte>(handle->public_key().begin(), handle->public_key().end()) == from_hex(kP256Public));

    // The RFC's (deterministic) signatures verify; ours are randomized, so they verify without matching.
    CHECK(verify(key_algorithm::kP256, handle->public_key(), text_bytes("sample"), from_hex(kP256SampleSig)));
    CHECK(verify(key_algorithm::kP256, handle->public_key(), text_bytes("test"), from_hex(kP256TestSig)));
    CHECK(verify(key_algorithm::kP256, handle->public_key(), text_bytes("test"), from_hex(kP256SampleSig)).error().code == errc::kBadSignature);
    auto sig = handle->sign(text_bytes("sample"));
    REQUIRE(sig);
    CHECK(sig->size() == key_handle::kSignatureSize);
    CHECK(verify(key_algorithm::kP256, handle->public_key(), text_bytes("sample"), *sig));
}

TEST_CASE("P-256 key handles round-trip and refuse what isn't theirs", "[security][key_handle][p256]") {
    if (!has_p256()) {
        SKIP("no TLS backend: P-256 reports kDisabled");
    }
    auto secret = generate_private_key(key_algorithm::kP256);
    REQUIRE(secret);
    const auto handle = *key_handle::from_private_key(key_algorithm::kP256, secret->bytes());
    const auto other = *key_handle::from_private_key(key_algorithm::kP256, generate_private_key(key_algorithm::kP256)->bytes());
    CHECK(handle.public_key().size() == 65);
    CHECK(handle.fingerprint() != other.fingerprint());

    const auto message = text_bytes("rhp/device/host");
    const auto sig = *handle.sign(message);
    CHECK(verify(key_algorithm::kP256, handle.public_key(), message, sig));
    CHECK(verify(key_algorithm::kP256, other.public_key(), message, sig).error().code == errc::kBadSignature);
    CHECK(verify(key_algorithm::kP256, handle.public_key(), text_bytes("rhp/device/client"), sig).error().code == errc::kBadSignature);
    auto tampered = sig;
    tampered[40] ^= std::byte{0x80};
    CHECK(verify(key_algorithm::kP256, handle.public_key(), message, tampered).error().code == errc::kBadSignature);

    // Not a point on the curve; the group order and zero are no scalars.
    auto off_curve = std::vector<std::byte>(handle.public_key().begin(), handle.public_key().end());
    off_curve[64] ^= std::byte{1};
    CHECK(verify(key_algorithm::kP256, off_curve, message, sig).error().code == errc::kBadSignature);
    CHECK(key_handle::from_private_key(key_algorithm::kP256, from_hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")).error().code ==
          errc::kInvalidArgument);
    CHECK(key_handle::from_private_key(key_algorithm::kP256, std::vector<std::byte>(32)).error().code == errc::kInvalidArgument);
}

TEST_CASE("a callback key signs through its function", "[security][key_handle]") {
    // A "hardware" key: the test holds the private half, the handle only the public key and the function.
    const auto device = *ed25519_secret_key::generate();
    int calls = 0;
    const auto pub = device.public_key();
    auto handle = key_handle::from_callback(key_algorithm::kEd25519, pub.bytes(), [&](std::span<const std::byte> message) -> Rhp::result<std::vector<std::byte>> {
        ++calls;
        const auto sig = device.sign(message);
        return std::vector<std::byte>(sig.begin(), sig.end());
    });
    REQUIRE(handle);
    const auto message = text_bytes("rhp/device/client");
    const auto sig = handle->sign(message);
    REQUIRE(sig);
    CHECK(calls == 1);
    CHECK(verify(key_algorithm::kEd25519, handle->public_key(), message, *sig));
    CHECK(handle->fingerprint() == key_fingerprint(key_algorithm::kEd25519, pub.bytes()));

    // The callback's errors come through; what isn't a signature is refused.
    const auto failing = *key_handle::from_callback(key_algorithm::kEd25519, pub.bytes(),
                                                    [](std::span<const std::byte>) -> Rhp::result<std::vector<std::byte>> { return Rhp::fail(errc::kCancelled, "the user said no", "test"); });
    CHECK(failing.sign(message).error().code == errc::kCancelled);
    const auto short_sig = *key_handle::from_callback(key_algorithm::kEd25519, pub.bytes(),
                                                      [](std::span<const std::byte>) -> Rhp::result<std::vector<std::byte>> { return std::vector<std::byte>(10); });
    CHECK(short_sig.sign(message).error().code == errc::kInvalidArgument);

    // Malformed public keys and a missing function.
    CHECK(key_handle::from_callback(key_algorithm::kEd25519, std::vector<std::byte>(31), {}).error().code == errc::kInvalidArgument);
    CHECK(key_handle::from_callback(key_algorithm::kP256, std::vector<std::byte>(65), [](std::span<const std::byte>) { return Rhp::result<std::vector<std::byte>>{}; })
              .error()
              .code == errc::kInvalidArgument);
    CHECK(key_handle::from_callback(key_algorithm::kEd25519, pub.bytes(), {}).error().code == errc::kInvalidArgument);
}

TEST_CASE("a P-256 callback key may return DER", "[security][key_handle][p256]") {
    if (!has_p256()) {
        SKIP("no TLS backend: P-256 reports kDisabled");
    }
    // What a Secure Enclave or Android Keystore returns: SEQUENCE { INTEGER r, INTEGER s }, with a
    // leading 0 where the high bit is set (r of "sample" here), none where it isn't.
    const auto r = from_hex(kP256SampleSig.substr(0, 64));
    const auto s = from_hex(kP256SampleSig.substr(64));
    std::vector<std::byte> der{std::byte{0x30}, std::byte{0}, std::byte{0x02}, std::byte{33}, std::byte{0}};
    der.insert(der.end(), r.begin(), r.end());
    der.insert(der.end(), {std::byte{0x02}, std::byte{33}, std::byte{0}});
    der.insert(der.end(), s.begin(), s.end());
    der[1] = static_cast<std::byte>(der.size() - 2);

    const auto pub = from_hex(kP256Public);
    const auto handle = *key_handle::from_callback(key_algorithm::kP256, pub, [&](std::span<const std::byte>) -> Rhp::result<std::vector<std::byte>> { return der; });
    const auto sig = handle.sign(text_bytes("sample"));
    REQUIRE(sig);
    CHECK(*sig == from_hex(kP256SampleSig));
    CHECK(verify(key_algorithm::kP256, pub, text_bytes("sample"), *sig));

    auto broken = der;
    broken[2] = std::byte{0x04}; // not an INTEGER
    const auto bad = *key_handle::from_callback(key_algorithm::kP256, pub, [&](std::span<const std::byte>) -> Rhp::result<std::vector<std::byte>> { return broken; });
    CHECK(bad.sign(text_bytes("sample")).error().code == errc::kInvalidArgument);
}

// Key stores: passphrase sealing, files (plain, sealed, wrapped), DPAPI, app callbacks, private keys.
#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/platform/os.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/key_handle.hpp>
#include <rhp/security/key_store.hpp>
#include <rhp/security/tls/p256.hpp>

using Rhp::errc;
using namespace Rhp::security;
namespace fs = std::filesystem;

namespace key_store_fixtures {

// Cheap Argon2i for tests (the defaults take about a second).
constexpr passphrase_kdf kCheapKdf{.memory_kib = 64, .passes = 1};

struct store_folder {
    fs::path path;

    store_folder() {
        std::string suffix;
        for (const std::byte b : *Rhp::platform::random_array<6>()) {
            suffix += std::format("{:02x}", std::to_integer<unsigned>(b));
        }
        path = fs::temp_directory_path() / ("rhp_key_store_" + suffix);
    }
    ~store_folder() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    store_folder(const store_folder&) = delete;
    store_folder& operator=(const store_folder&) = delete;
};

std::string read_text(const fs::path& path) {
    std::ifstream in{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
}

void write_text(const fs::path& path, std::string_view text) {
    std::ofstream out{path, std::ios::binary | std::ios::trunc};
    out << text;
}

bool same_key(const key& a, const key& b) {
    return std::ranges::equal(a.bytes(), b.bytes());
}

} // namespace key_store_fixtures

using namespace key_store_fixtures;

TEST_CASE("passphrase sealing round-trips and refuses a wrong passphrase", "[security][key_store]") {
    const key secret = *key::generate();
    auto sealed = seal_with_passphrase(secret.bytes(), "correct horse", kCheapKdf);
    REQUIRE(sealed);
    CHECK(sealed->starts_with("argon2i:m=64,t=1:"));
    CHECK(is_passphrase_sealed(*sealed));
    CHECK_FALSE(is_passphrase_sealed(secret.to_base64()));
    CHECK(sealed->find(secret.to_base64()) == std::string::npos);
    auto opened = open_with_passphrase(*sealed, "correct horse");
    REQUIRE(opened);
    CHECK(same_key(*opened, secret));

    // A fresh salt and nonce every time.
    CHECK(*seal_with_passphrase(secret.bytes(), "correct horse", kCheapKdf) != *sealed);

    CHECK(open_with_passphrase(*sealed, "correct horse!").error().code == errc::kAuth);
    CHECK(open_with_passphrase(*sealed, "").error().code == errc::kAuth);
    // The header is authenticated: other parameters are another key and other associated data.
    std::string changed = *sealed;
    changed.replace(0, std::string_view{"argon2i:m=64,t=1:"}.size(), "argon2i:m=64,t=2:");
    CHECK(open_with_passphrase(changed, "correct horse").error().code == errc::kAuth);
    // A changed ciphertext byte: a character well before the padding, so all six of its bits are data
    // (next to "==" some bits are padding a decoder may ignore).
    changed = *sealed;
    changed[changed.size() - 10] = changed[changed.size() - 10] == 'A' ? 'B' : 'A';
    const auto tampered = open_with_passphrase(changed, "correct horse");
    REQUIRE_FALSE(tampered);
    CHECK(tampered.error().code == errc::kAuth);

    CHECK(open_with_passphrase("argon2i:m=64:AAAA", "x").error().code == errc::kInvalidArgument);
    CHECK(open_with_passphrase("argon2i:m=64,t=1:AAAA", "x").error().code == errc::kInvalidArgument);
    CHECK(open_with_passphrase("argon2i:m=4194304,t=1:" + sealed->substr(17), "x").error().code == errc::kInvalidArgument);
    CHECK(open_with_passphrase(secret.to_base64(), "x").error().code == errc::kInvalidArgument);
    CHECK(seal_with_passphrase(secret.bytes(), "x", passphrase_kdf{.memory_kib = 4, .passes = 1}).error().code == errc::kInvalidArgument);
    CHECK(seal_with_passphrase(secret.bytes(), "x", passphrase_kdf{.memory_kib = 64, .passes = 0}).error().code == errc::kInvalidArgument);
}

TEST_CASE("the default passphrase parameters are written into the sealed value", "[security][key_store]") {
    const key secret = *key::generate();
    auto sealed = seal_with_passphrase(secret.bytes(), "pw");
    REQUIRE(sealed);
    CHECK(sealed->starts_with("argon2i:m=65536,t=3:"));
    CHECK(same_key(*open_with_passphrase(*sealed, "pw"), secret));
}

TEST_CASE("a file key store keeps owner-only files", "[security][key_store]") {
    store_folder dir;
    file_key_store store{dir.path};
    const key secret = *key::generate();
    REQUIRE(store.store("dev.signing", secret));
    const fs::path file = store.path_of("dev.signing");
    CHECK(file == dir.path / "dev.signing.rhpkey");
    CHECK_FALSE(Rhp::platform::readable_by_others(file));
    CHECK(read_text(file).find("secret = \"" + secret.to_base64() + "\"") != std::string::npos);
    auto loaded = store.load("dev.signing");
    REQUIRE(loaded);
    CHECK(same_key(*loaded, secret));

    // Replacing, removing, and names that aren't names.
    const key other = *key::generate();
    REQUIRE(store.store("dev.signing", other));
    CHECK(same_key(*store.load("dev.signing"), other));
    REQUIRE(store.remove("dev.signing"));
    CHECK(store.load("dev.signing").error().code == errc::kNotFound);
    CHECK(store.remove("dev.signing").error().code == errc::kNotFound);
    for (const std::string_view bad : std::initializer_list<std::string_view>{"", "../x", ".hidden", "a/b", "a b", std::string_view{"a\0b", 3}}) {
        CHECK(store.store(bad, secret).error().code == errc::kInvalidArgument);
        CHECK(store.load(bad).error().code == errc::kInvalidArgument);
    }
    CHECK(store.store(std::string(65, 'k'), secret).error().code == errc::kInvalidArgument);

    write_text(dir.path / "broken.rhpkey", "nothing here\n");
    CHECK(store.load("broken").error().code == errc::kInvalidArgument);
}

TEST_CASE("a file key store seals with its passphrase", "[security][key_store]") {
    store_folder dir;
    file_key_store store{dir.path, {.passphrase = "hunter22", .kdf = kCheapKdf}};
    const key secret = *key::generate();
    REQUIRE(store.store("ci", secret));
    const std::string text = read_text(store.path_of("ci"));
    CHECK(text.find("secret = \"argon2i:m=64,t=1:") != std::string::npos);
    CHECK(text.find(secret.to_base64()) == std::string::npos);
    CHECK(same_key(*store.load("ci"), secret));

    // Without the passphrase, or with another one: kAuth.
    CHECK(file_key_store{dir.path}.load("ci").error().code == errc::kAuth);
    CHECK(file_key_store(dir.path, {.passphrase = "hunter2", .kdf = kCheapKdf}).load("ci").error().code == errc::kAuth);

    // A store with a passphrase still reads plain files.
    REQUIRE(file_key_store{dir.path}.store("plain", secret));
    CHECK(same_key(*store.load("plain"), secret));
}

TEST_CASE("a file key store can wrap through the app", "[security][key_store]") {
    store_folder dir;
    int wraps = 0;
    int unwraps = 0;
    // Stands in for an Android Keystore key: anything that turns bytes into other bytes and back.
    const auto flip = [](std::span<const std::byte> in) {
        std::vector<std::byte> out(in.rbegin(), in.rend());
        for (std::byte& b : out) {
            b ^= std::byte{0x5a};
        }
        return out;
    };
    file_key_store store{dir.path, key_wrapping{[&](std::span<const std::byte> plain) -> Rhp::result<std::vector<std::byte>> {
                                                    ++wraps;
                                                    return flip(plain);
                                                },
                                                [&](std::span<const std::byte> wrapped) -> Rhp::result<std::vector<std::byte>> {
                                                    ++unwraps;
                                                    return flip(wrapped);
                                                }}};
    const key secret = *key::generate();
    REQUIRE(store.store("app", secret));
    CHECK(read_text(store.path_of("app")).find("secret = \"wrapped:") != std::string::npos);
    CHECK(same_key(*store.load("app"), secret));
    CHECK(wraps == 1);
    CHECK(unwraps == 1);
    // A store without the wrapping can't read it.
    CHECK(file_key_store{dir.path}.load("app").error().code == errc::kInvalidArgument);
}

TEST_CASE("a DPAPI key store opens only for this user", "[security][key_store]") {
    store_folder dir;
    dpapi_key_store store{dir.path};
    const key secret = *key::generate();
    auto stored = store.store("dev", secret);
    if constexpr (Rhp::platform::kOs != Rhp::platform::os_kind::kWindows) {
        CHECK(stored.error().code == errc::kDisabled);
        return;
    }
    REQUIRE(stored);
    const std::string text = read_text(store.path_of("dev"));
    CHECK(text.find("secret = \"wrapped:") != std::string::npos);
    CHECK(text.find(secret.to_base64()) == std::string::npos);
    CHECK(same_key(*store.load("dev"), secret));

    // A changed blob is kAuth (DPAPI checks its own MAC).
    const auto start = text.find("wrapped:") + 8 + 40;
    std::string changed = text;
    changed[start] = changed[start] == 'A' ? 'B' : 'A';
    write_text(store.path_of("dev"), changed);
    CHECK(store.load("dev").error().code == errc::kAuth);
}

TEST_CASE("a callback key store uses the app's functions", "[security][key_store]") {
    std::map<std::string, key, std::less<>> kept;
    callback_key_store store{{
        .load = [&](std::string_view name) -> Rhp::result<key> {
            const auto it = kept.find(name);
            if (it == kept.end()) {
                return Rhp::fail(errc::kNotFound, "none");
            }
            return it->second;
        },
        .store = [&](std::string_view name, const key& secret) -> Rhp::result<void> {
            kept.insert_or_assign(std::string{name}, secret);
            return {};
        },
        .remove = {},
    }};
    const key secret = *key::generate();
    REQUIRE(store.store("phone", secret));
    CHECK(same_key(*store.load("phone"), secret));
    CHECK(store.load("other").error().code == errc::kNotFound);
    CHECK(store.remove("phone").error().code == errc::kDisabled);
    CHECK(store.store("../phone", secret).error().code == errc::kInvalidArgument);
    CHECK(kept.size() == 1);
}

TEST_CASE("the Keychain store is disabled off Apple targets", "[security][key_store]") {
    if constexpr (Rhp::platform::kOs == Rhp::platform::os_kind::kMacos || Rhp::platform::kOs == Rhp::platform::os_kind::kIos) {
        SKIP("Keychain items need a signed app or a login keychain; not run here");
    }
    keychain_key_store store;
    CHECK(store.load("dev").error().code == errc::kDisabled);
    CHECK(store.store("dev", *key::generate()).error().code == errc::kDisabled);
    CHECK(store.remove("dev").error().code == errc::kDisabled);
    CHECK(store.load("../dev").error().code == errc::kInvalidArgument);
}

TEST_CASE("private keys go into stores and come back as key handles", "[security][key_store]") {
    store_folder dir;
    file_key_store store{dir.path, {.passphrase = "pw", .kdf = kCheapKdf}};
    const key seed = *generate_private_key(key_algorithm::kEd25519);
    REQUIRE(store_key(store, "device", key_algorithm::kEd25519, seed.bytes()));
    auto handle = load_key(store, "device");
    REQUIRE(handle);
    CHECK(handle->alg() == key_algorithm::kEd25519);
    CHECK(std::ranges::equal(handle->public_key(), key_handle::from_private_key(key_algorithm::kEd25519, seed.bytes())->public_key()));

    if (!Rhp::security::tls::detail::p256_backend().empty()) {
        const key scalar = *generate_private_key(key_algorithm::kP256);
        REQUIRE(store_key(store, "device-p256", key_algorithm::kP256, scalar.bytes()));
        auto p256 = load_key(store, "device-p256");
        REQUIRE(p256);
        CHECK(p256->alg() == key_algorithm::kP256);
        const std::string_view message = "rhp/device/client";
        const auto bytes = std::as_bytes(std::span{message.data(), message.size()});
        CHECK(verify(key_algorithm::kP256, p256->public_key(), bytes, *p256->sign(bytes)));
    }

    // A plain secret isn't a private key; a private key has its size.
    REQUIRE(store.store("psk", *key::generate()));
    CHECK(load_key(store, "psk").error().code == errc::kInvalidArgument);
    CHECK(store_key(store, "short", key_algorithm::kEd25519, std::span{seed.bytes()}.first(16)).error().code == errc::kInvalidArgument);
}

// Split and tagged key files (decision AL11): connection identities, signing key files (plain and
// sealed), device-key identities, env tags on key lines, and the combined format from before.
#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/role.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/identity_file.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/key_handle.hpp>
#include <rhp/security/key_store.hpp>
#include <rhp/security/keyring.hpp>

using Rhp::errc;
using namespace Rhp::security;
namespace fs = std::filesystem;

namespace split_key_fixtures {

constexpr passphrase_kdf kSplitKdf{.memory_kib = 64, .passes = 1};

struct split_folder {
    fs::path path;

    split_folder() {
        std::string suffix;
        for (const std::byte b : *Rhp::platform::random_array<6>()) {
            suffix += std::format("{:02x}", std::to_integer<unsigned>(b));
        }
        path = fs::temp_directory_path() / ("rhp_split_keys_" + suffix);
        fs::create_directories(path);
    }
    ~split_folder() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    split_folder(const split_folder&) = delete;
    split_folder& operator=(const split_folder&) = delete;

    [[nodiscard]] std::string file(std::string_view name) const { return (path / name).string(); }
};

std::string split_text(const std::string& path) {
    std::ifstream in{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
}

// What keygen does: the identity without its signing key, and the signing key beside it.
void write_split(const split_folder& dir, identity_file id, std::optional<key_env> env, std::string_view passphrase = {}) {
    const signing_key_file signing{id.name, *id.signing, env, {}};
    id.signing.reset();
    id.env = env;
    REQUIRE(id.save(dir.file(id.name + ".rhpid")));
    REQUIRE(signing.save(signing_key_file::beside(dir.file(id.name + ".rhpid")), passphrase, kSplitKdf));
}

} // namespace split_key_fixtures

using namespace split_key_fixtures;

TEST_CASE("split key files load as one identity", "[security][files]") {
    split_folder dir;
    const identity_file original = *identity_file::generate("dev");
    write_split(dir, original, key_env::kProd);
    const std::string id_path = dir.file("dev.rhpid");
    CHECK(signing_key_file::beside(id_path) == dir.file("dev.rhpsign"));

    const std::string id_text = split_text(id_path);
    CHECK(id_text.find("signing_key") == std::string::npos);
    CHECK(id_text.find("env         = \"prod\"") != std::string::npos);
    const std::string signing_text = split_text(dir.file("dev.rhpsign"));
    CHECK(signing_text.find("psk") == std::string::npos);
    CHECK(signing_text.find("signer      = \"dev\"") != std::string::npos);
    CHECK_FALSE(Rhp::platform::readable_by_others(dir.file("dev.rhpsign")));

    auto loaded = identity_file::load(id_path);
    REQUIRE(loaded);
    CHECK(loaded->warnings.empty());
    CHECK(loaded->env == key_env::kProd);
    CHECK(loaded->signing_env == key_env::kProd);
    REQUIRE(loaded->signing);
    CHECK(loaded->signing->public_key() == original.signing->public_key());
    CHECK(loaded->keyring_line(Rhp::role::kPatch) == original.keyring_line(Rhp::role::kPatch) + " env=prod");
    CHECK(*loaded->signers_line() == *original.signers_line() + " env=prod");

    // The host's files take the tagged lines and keep the tags.
    auto ring = keyring::parse(loaded->keyring_line(Rhp::role::kPatch) + "\nold patch " + loaded->psk.to_base64() + "\n");
    REQUIRE(ring);
    CHECK(ring->env_of("dev") == key_env::kProd);
    CHECK_FALSE(ring->env_of("old"));
    auto trust = trusted_signers::parse(*loaded->signers_line());
    REQUIRE(trust);
    CHECK(trust->env_of("dev") == key_env::kProd);

    // Without its signing key file the identity still connects; it signs nothing.
    fs::remove(dir.file("dev.rhpsign"));
    auto psk_only = identity_file::load(id_path);
    REQUIRE(psk_only);
    CHECK_FALSE(psk_only->signer_key());
}

TEST_CASE("a sealed signing key file needs its passphrase", "[security][files]") {
    split_folder dir;
    write_split(dir, *identity_file::generate("ci"), key_env::kDev, "open sesame");
    const std::string id_path = dir.file("ci.rhpid");
    const std::string signing_path = dir.file("ci.rhpsign");
    CHECK(signing_key_file::sealed(signing_path));
    CHECK(split_text(signing_path).find("signing_key = \"argon2i:m=64,t=1:") != std::string::npos);

    // Without the passphrase: the identity loads, signs nothing, and says why.
    auto without = identity_file::load(id_path);
    REQUIRE(without);
    CHECK_FALSE(without->signing);
    REQUIRE(without->warnings.size() == 1);
    CHECK(without->warnings[0].find("sealed with a passphrase") != std::string::npos);
    CHECK(signing_key_file::load(signing_path).error().code == errc::kAuth);

    // A wrong one is an error; the right one opens it.
    CHECK(identity_file::load(id_path, "open sesame!").error().code == errc::kAuth);
    auto with = identity_file::load(id_path, "open sesame");
    REQUIRE(with);
    REQUIRE(with->signer_key());
    CHECK(with->signer_key()->name == "ci");
    auto file = signing_key_file::load(signing_path, "open sesame");
    REQUIRE(file);
    CHECK(file->env == key_env::kDev);
    CHECK(file->signers_line() == *with->signers_line());

    // A plain one isn't sealed; a sealed signing_key can't sit in an identity file.
    CHECK_FALSE(signing_key_file::sealed(id_path));
    CHECK_FALSE(signing_key_file::sealed(dir.file("none.rhpsign")));
    const std::string sealed_line = split_text(signing_path).substr(split_text(signing_path).find("signing_key"));
    CHECK(identity_file::parse("name = \"x\"\npsk = \"" + Rhp::security::key::generate()->to_base64() + "\"\n" + sealed_line).error().code == errc::kAuth);
}

TEST_CASE("signing key files refuse what they don't hold", "[security][files]") {
    const auto seed = ed25519_secret_key::generate()->to_base64();
    CHECK(signing_key_file::parse("signer = \"dev\"\nsigning_key = \"" + seed + "\"\nenv = \"prod\"\n")->env == key_env::kProd);
    CHECK(signing_key_file::parse("signing_key = \"" + seed + "\"\n").error().code == errc::kInvalidArgument);
    CHECK(signing_key_file::parse("signer = \"dev\"\n").error().code == errc::kInvalidArgument);
    CHECK(signing_key_file::parse("signer = \"dev\"\nsigning_key = \"" + seed + "\"\nenv = \"staging\"\n").error().code == errc::kInvalidArgument);
    CHECK(signing_key_file::parse("signer = \"dev\"\nsigning_key = \"" + seed + "\"\npsk = \"x\"\n").error().code == errc::kInvalidArgument);
    CHECK(signing_key_file::load("no/such/file.rhpsign").error().code == errc::kNotFound);
}

TEST_CASE("the combined identity format still loads", "[security][files]") {
    split_folder dir;
    const identity_file original = *identity_file::generate("legacy");
    // What rhp-cli keygen wrote before Stage 13b: name, psk and signing_key in one file, no env.
    const std::string text = std::format("# RHP identity\nname = \"legacy\"\npsk = \"{}\"\nsigning_key = \"{}\"\nsigner = \"lead\"\n", original.psk.to_base64(),
                                         original.signing->to_base64());
    REQUIRE(Rhp::platform::write_private_file(dir.file("legacy.rhpid"), std::as_bytes(std::span{text})));
    auto loaded = identity_file::load(dir.file("legacy.rhpid"));
    REQUIRE(loaded);
    CHECK_FALSE(loaded->env);
    REQUIRE(loaded->signer_key());
    CHECK(loaded->signer_key()->name == "lead");
    CHECK(*loaded->signers_line() == "lead " + original.signing->public_key().to_base64());
    CHECK(loaded->keyring_line(Rhp::role::kAdmin) == original.keyring_line(Rhp::role::kAdmin));
    // A combined file's env covers its signing key.
    auto tagged = identity_file::parse(text + "env = \"dev\"\n");
    REQUIRE(tagged);
    CHECK(tagged->signers_line()->ends_with(" env=dev"));
    CHECK(identity_file::parse(tagged->to_text())->env == key_env::kDev);
}

TEST_CASE("device-key identities hold a key pair instead of a PSK", "[security][files]") {
    split_folder dir;
    auto id = identity_file::generate_device("phone");
    REQUIRE(id);
    CHECK(id->psk.empty());
    REQUIRE(id->device);
    CHECK(id->device->alg == key_algorithm::kEd25519);
    id->env = key_env::kDev;
    REQUIRE(id->save(dir.file("phone.rhpid")));
    const std::string text = split_text(dir.file("phone.rhpid"));
    CHECK(text.find("alg         = \"ed25519\"") != std::string::npos);
    CHECK(text.find("device_key  = \"") != std::string::npos);
    CHECK(text.find("psk") == std::string::npos);

    auto loaded = identity_file::load(dir.file("phone.rhpid"));
    REQUIRE(loaded);
    REQUIRE(loaded->device);
    auto handle = loaded->device_key();
    REQUIRE(handle);
    CHECK(std::ranges::equal(handle->public_key(), id->device_key()->public_key()));
    auto line = loaded->device_line(Rhp::role::kObserve);
    REQUIRE(line);
    CHECK(*line == std::format("phone observe ed25519 {} env=dev", base64_encode(handle->public_key())));

    // A PSK identity has no device key; a device key needs its bytes; alg alone is no key.
    CHECK(identity_file::generate("dev")->device_key().error().code == errc::kNotFound);
    CHECK(identity_file::parse("name = \"x\"\nalg = \"ed25519\"\n").error().code == errc::kInvalidArgument);
    CHECK(identity_file::parse("name = \"x\"\nalg = \"rsa\"\ndevice_key = \"" + key::generate()->to_base64() + "\"\n").error().code == errc::kInvalidArgument);
    CHECK(identity_file::parse("name = \"x\"\ndevice_key = \"AAAA\"\n").error().code == errc::kInvalidArgument);
    CHECK(identity_file::parse("name = \"x\"\n").error().code == errc::kInvalidArgument);
}

TEST_CASE("env tags on key lines are parsed and kept", "[security][files]") {
    const auto psk = key::generate()->to_base64();
    const auto pub = ed25519_secret_key::generate()->public_key().to_base64();
    auto ring = keyring::parse("a patch " + psk + " env=dev\nb admin " + psk + " env=prod\nc observe " + psk + "\n");
    REQUIRE(ring);
    CHECK(ring->env_of("a") == key_env::kDev);
    CHECK(ring->env_of("b") == key_env::kProd);
    CHECK_FALSE(ring->env_of("c"));
    CHECK_FALSE(ring->env_of("nobody"));
    CHECK(ring->set_env("nobody", key_env::kDev).error().code == errc::kNotFound);
    REQUIRE(ring->set_env("c", key_env::kProd));
    CHECK(ring->env_of("c") == key_env::kProd);
    CHECK(keyring::parse("a patch " + psk + " env=staging\n").error().code == errc::kInvalidArgument);
    CHECK(keyring::parse("a patch " + psk + " extra\n").error().code == errc::kInvalidArgument);

    auto trust = trusted_signers::parse("dev " + pub + " env=dev\nci " + pub + "\n");
    REQUIRE(trust);
    CHECK(trust->env_of("dev") == key_env::kDev);
    CHECK_FALSE(trust->env_of("ci"));
    CHECK(trusted_signers::parse("dev " + pub + " env=\n").error().code == errc::kInvalidArgument);

    CHECK(parse_env_field("env=prod")->value() == key_env::kProd);
    CHECK_FALSE(parse_env_field("role=admin")->has_value());
    CHECK(parse_env_field("env=x").error().code == errc::kInvalidArgument);
}

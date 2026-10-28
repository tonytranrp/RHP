#include <array>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/platform/key_storage.hpp>
#include <rhp/platform/os.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/utils/scope_guard.hpp>

namespace fs = std::filesystem;

namespace platform_fixtures {

std::span<const std::byte> bytes_of(std::string_view text) {
    return std::as_bytes(std::span{text});
}

std::string read(const fs::path& path) {
    std::ifstream in{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
}

// Lets everyone read `path`: a file, or (Windows) a folder whose new files inherit that.
void let_everyone_read(const fs::path& path) {
#if defined(_WIN32)
    const std::string grant = std::format("icacls \"{}\" /grant *S-1-1-0:{} >nul", path.string(), fs::is_directory(path) ? "(OI)(R)" : "(R)");
    REQUIRE(std::system(grant.c_str()) == 0);
#else
    fs::permissions(path, fs::perms::group_read | fs::perms::others_read, fs::perm_options::add);
#endif
}

} // namespace platform_fixtures

using namespace platform_fixtures;

TEST_CASE("platform: the OS name is one of the five", "[platform][os]") {
    constexpr std::string_view name = Rhp::platform::kOsName;
    STATIC_REQUIRE(!name.empty());
    const std::set<std::string_view> known{"windows", "linux", "macos", "ios", "android"};
    CHECK(known.contains(name));
}

TEST_CASE("platform: random bytes differ between calls", "[platform][random]") {
    auto a = Rhp::platform::random_array<32>();
    auto b = Rhp::platform::random_array<32>();
    REQUIRE(a);
    REQUIRE(b);
    CHECK(*a != *b);
    // A large request is filled completely (the chance of a zero tail of 64 bytes is nil).
    std::array<std::byte, 4096> big{};
    REQUIRE(Rhp::platform::random_bytes(big));
    bool tail_nonzero = false;
    for (std::size_t i = big.size() - 64; i < big.size(); ++i) {
        tail_nonzero = tail_nonzero || big[i] != std::byte{0};
    }
    CHECK(tail_nonzero);
    CHECK(Rhp::platform::random_bytes(std::span<std::byte>{}));
}

TEST_CASE("platform: private files replace what was there and stay owner-only", "[platform][files]") {
    const auto tag = *Rhp::platform::random_array<6>();
    std::string suffix;
    for (const std::byte b : tag) {
        suffix += std::format("{:02x}", std::to_integer<unsigned>(b));
    }
    const fs::path dir = fs::temp_directory_path() / ("rhp_private_" + suffix);
    fs::create_directories(dir);
    const Rhp::utils::scope_guard cleanup{[&dir] {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }};

    const fs::path key = dir / "secret.key";
    REQUIRE(Rhp::platform::write_private_file(key, bytes_of("one")));
    CHECK(read(key) == "one");
    CHECK_FALSE(Rhp::platform::readable_by_others(key));

    // Someone widened it; writing it again replaces it with a private file.
    let_everyone_read(key);
    CHECK(Rhp::platform::readable_by_others(key));
    REQUIRE(Rhp::platform::write_private_file(key, bytes_of("two")));
    CHECK(read(key) == "two");
    CHECK_FALSE(Rhp::platform::readable_by_others(key));

#if defined(_WIN32)
    // In a folder that lets everyone read its files, a plain replace_file inherits that; a private
    // file doesn't (its DACL blocks inheritance).
    const fs::path shared = dir / "shared";
    fs::create_directories(shared);
    let_everyone_read(shared);
    REQUIRE(Rhp::platform::replace_file(shared / "plain.txt", bytes_of("plain")));
    CHECK(Rhp::platform::readable_by_others(shared / "plain.txt"));
    REQUIRE(Rhp::platform::write_private_file(shared / "secret.key", bytes_of("secret")));
    CHECK_FALSE(Rhp::platform::readable_by_others(shared / "secret.key"));
#endif

    // No temporaries are left behind, and a missing file isn't "readable".
    std::size_t files = 0;
    for (const auto& entry : fs::directory_iterator{dir}) {
        if (entry.is_regular_file()) {
            ++files;
        }
        CHECK(entry.path().extension() != ".tmp");
    }
    CHECK(files == 1);
    CHECK_FALSE(Rhp::platform::readable_by_others(dir / "missing.key"));
}

TEST_CASE("platform: the user configuration folder", "[platform][files]") {
    const auto dir = Rhp::platform::user_config_dir();
    if constexpr (Rhp::platform::kOs == Rhp::platform::os_kind::kIos || Rhp::platform::kOs == Rhp::platform::os_kind::kAndroid) {
        REQUIRE_FALSE(dir);
        CHECK(dir.error().code == Rhp::errc::kDisabled);
    } else {
        REQUIRE(dir);
        CHECK(dir->is_absolute());
    }
}

TEST_CASE("DPAPI seals for this user on Windows and is disabled elsewhere", "[platform][key_storage]") {
    const std::string_view secret = "a 32-byte secret, give or take..";
    auto sealed = Rhp::platform::protect(platform_fixtures::bytes_of(secret));
    if constexpr (Rhp::platform::kOs != Rhp::platform::os_kind::kWindows) {
        CHECK(sealed.error().code == Rhp::errc::kDisabled);
        CHECK(Rhp::platform::unprotect(platform_fixtures::bytes_of(secret)).error().code == Rhp::errc::kDisabled);
        return;
    }
    REQUIRE(sealed);
    CHECK(sealed->size() > secret.size());
    CHECK(std::string_view{reinterpret_cast<const char*>(sealed->data()), sealed->size()}.find(secret) == std::string_view::npos);
    auto opened = Rhp::platform::unprotect(*sealed);
    REQUIRE(opened);
    CHECK(std::string_view{reinterpret_cast<const char*>(opened->data()), opened->size()} == secret);
    // A changed blob doesn't open.
    std::vector<std::byte> changed = *sealed;
    changed[changed.size() / 2] ^= std::byte{1};
    CHECK(Rhp::platform::unprotect(changed).error().code == Rhp::errc::kAuth);
}

TEST_CASE("the Keychain is disabled off Apple targets", "[platform][key_storage]") {
    if constexpr (Rhp::platform::kOs == Rhp::platform::os_kind::kMacos || Rhp::platform::kOs == Rhp::platform::os_kind::kIos) {
        SKIP("Keychain items need a signed app or a login keychain; not run here");
    }
    CHECK(Rhp::platform::keychain_load("rhp-tests", "k").error().code == Rhp::errc::kDisabled);
    CHECK(Rhp::platform::keychain_store("rhp-tests", "k", platform_fixtures::bytes_of("x")).error().code == Rhp::errc::kDisabled);
    CHECK(Rhp::platform::keychain_remove("rhp-tests", "k").error().code == Rhp::errc::kDisabled);
}


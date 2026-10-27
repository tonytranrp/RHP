// Identity files on disk: owner-only, atomic, and the warnings their loader gives.
#include <array>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/security/identity_file.hpp>
#include <rhp/security/key.hpp>
#include <rhp/utils/scope_guard.hpp>

using Rhp::errc;
using namespace Rhp::security;
namespace fs = std::filesystem;

namespace key_file_fixtures {

// A fresh folder in the temp folder, removed afterwards.
struct temp_folder {
    fs::path path;

    temp_folder() {
        std::string suffix;
        for (const std::byte b : *Rhp::platform::random_array<6>()) {
            suffix += std::format("{:02x}", std::to_integer<unsigned>(b));
        }
        path = fs::temp_directory_path() / ("rhp_key_files_" + suffix);
        fs::create_directories(path);
    }
    ~temp_folder() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    temp_folder(const temp_folder&) = delete;
    temp_folder& operator=(const temp_folder&) = delete;
};

void let_everyone_read(const fs::path& file) {
#if defined(_WIN32)
    REQUIRE(std::system(std::format("icacls \"{}\" /grant *S-1-1-0:(R) >nul", file.string()).c_str()) == 0);
#else
    fs::permissions(file, fs::perms::group_read | fs::perms::others_read, fs::perm_options::add);
#endif
}

} // namespace key_file_fixtures

using namespace key_file_fixtures;

TEST_CASE("identity files are saved owner-only and warn when others can read them", "[security][files]") {
    temp_folder dir;
    const std::string path = (dir.path / "dev.rhpid").string();
    auto id = identity_file::generate("dev");
    REQUIRE(id);
    REQUIRE(id->save(path));
    CHECK_FALSE(Rhp::platform::readable_by_others(path));
    auto loaded = identity_file::load(path);
    REQUIRE(loaded);
    CHECK(loaded->warnings.empty());

    // A widened file loads with a warning; saving over it makes it private again.
    let_everyone_read(path);
    loaded = identity_file::load(path);
    REQUIRE(loaded);
    REQUIRE(loaded->warnings.size() == 1);
    CHECK(loaded->warnings.front().find("other users") != std::string::npos);
    auto other = identity_file::generate("other");
    REQUIRE(other->save(path));
    CHECK_FALSE(Rhp::platform::readable_by_others(path));
    loaded = identity_file::load(path);
    REQUIRE(loaded);
    CHECK(loaded->name == "other");
    CHECK(loaded->warnings.empty());
    CHECK(std::distance(fs::directory_iterator{dir.path}, fs::directory_iterator{}) == 1); // no temporaries left

    CHECK(identity_file::generate("x")->save((dir.path / "no" / "such" / "folder" / "x.rhpid").string()).error().code == errc::kInvalidArgument);
}

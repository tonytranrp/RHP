// Identity and dev session files on disk: owner-only, atomic, and the warnings their loaders give.
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
#include <rhp/security/dev_session.hpp>
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

TEST_CASE("dev session files round-trip owner-only", "[security][dev_session]") {
    temp_folder dir;
    dev_session s;
    s.app = "my_game";
    s.transport = "tcp";
    s.host = "127.0.0.1";
    s.port = 7777;
    s.identity = *identity_file::generate("dev");
    CHECK(s.endpoint() == "tcp://127.0.0.1:7777");

    const auto path = dev_session_path("my_game", dir.path / "rhp" / "dev");
    REQUIRE(path);
    CHECK(*path == dir.path / "rhp" / "dev" / "my_game.rhpdev");
    REQUIRE(write_dev_session(*path, s)); // makes the folders
    CHECK_FALSE(Rhp::platform::readable_by_others(*path));
    auto read = read_dev_session(*path);
    REQUIRE(read);
    CHECK(read->app == "my_game");
    CHECK(read->transport == "tcp");
    CHECK(read->host == "127.0.0.1");
    CHECK(read->port == 7777);
    CHECK(read->identity.name == "dev");
    REQUIRE(read->identity.signing);
    CHECK(read->identity.signing->public_key() == s.identity.signing->public_key());
    CHECK(read->identity.warnings.empty());
    CHECK(identity_file::parse(read->identity.to_text())); // the identity part is an identity file

    // Replaced in place; IPv6 in brackets; a local IPC name is the whole address.
    s.host = "::1";
    REQUIRE(write_dev_session(*path, s));
    CHECK(read_dev_session(*path)->endpoint() == "tcp://[::1]:7777");
    s.transport = "local_ipc";
    s.host = "my_game";
    s.port = 0;
    REQUIRE(write_dev_session(*path, s));
    read = read_dev_session(*path);
    REQUIRE(read);
    CHECK(read->endpoint() == "local_ipc://my_game");
    CHECK(read->port == 0);
    let_everyone_read(*path);
    CHECK(read_dev_session(*path)->identity.warnings.size() == 1);

    const std::string id = s.identity.to_text();
    CHECK(dev_session::parse("app = \"g\"\n" + id).error().code == errc::kInvalidArgument);                      // no endpoint
    CHECK(dev_session::parse("endpoint = \"tcp://127.0.0.1:1\"\n" + id).error().code == errc::kInvalidArgument); // no app
    for (const std::string_view bad : {"127.0.0.1:7777", "tcp://127.0.0.1", "tcp://127.0.0.1:0", "tcp://::1:7777", "tcp://:7777", "tcp://127.0.0.1:99999"}) {
        CHECK(dev_session::parse(std::format("app = \"g\"\nendpoint = \"{}\"\n{}", bad, id)).error().code == errc::kInvalidArgument);
    }
    CHECK(read_dev_session(dir.path / "missing.rhpdev").error().code == errc::kNotFound);
    s.app = "../escape";
    CHECK(write_dev_session(*path, s).error().code == errc::kInvalidArgument);
}

TEST_CASE("dev session paths take app names only", "[security][dev_session]") {
    for (const std::string_view good : {"my_game", "Game-2.dev", "a"}) {
        CHECK(dev_session_path(good, "dir"));
    }
    for (const std::string_view bad : {"", "../x", "a/b", "a\\b", ".hidden", "-flag", "c:x", "x y", "\xc3\xa9"}) {
        CHECK(dev_session_path(bad, "dir").error().code == errc::kInvalidArgument);
    }
    CHECK(dev_session_path(std::string(65, 'a'), "dir").error().code == errc::kInvalidArgument);

    // In the user's configuration folder where there is one.
    if (auto config = Rhp::platform::user_config_dir()) {
        CHECK(*dev_session_path("my_game") == *config / "rhp" / "dev" / "my_game.rhpdev");
        CHECK(*dev_session_directory() == *config / "rhp" / "dev");
    } else {
        CHECK(dev_session_path("my_game").error().code == config.error().code);
    }
}

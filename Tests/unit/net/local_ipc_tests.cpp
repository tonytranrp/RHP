#include <chrono>
#include <filesystem>
#include <string>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/stream_roundtrip.hpp>

#include <rhp/net/local/local.hpp>
#include <rhp/platform/os.hpp>

TEST_CASE("local_ipc: ordered stream over the platform endpoint", "[net][local_ipc]") {
    const auto id = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const auto name = Rhp::platform::kOs == Rhp::platform::os_kind::kWindows ? "tests.local_ipc." + id : Rhp::platform::kOs == Rhp::platform::os_kind::kAndroid ? "@tests.local_ipc." + id
                                                                                                                                                             : (std::filesystem::temp_directory_path() / ("rhp-" + id)).string();
    rhp_test::stream_roundtrip<Rhp::net::local_ipc>(Rhp::endpoint::listen(name, 0));
    if constexpr (Rhp::platform::kOs == Rhp::platform::os_kind::kLinux) {
        rhp_test::stream_roundtrip<Rhp::net::local_ipc>(Rhp::endpoint::listen("@tests.local_ipc." + id, 0));
    }
}


TEST_CASE("local_ipc: endpoints need a name and port zero", "[net][local_ipc]") {
    Rhp::net::io_context io;
    CHECK_FALSE(Rhp::net::local_ipc::listen(io, Rhp::endpoint::listen("", 0), [](auto) {}));
    CHECK_FALSE(Rhp::net::local_ipc::listen(io, Rhp::endpoint::listen("name", 1), [](auto) {}));
}

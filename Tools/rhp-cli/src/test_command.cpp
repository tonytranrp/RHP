// rhp-cli test: the offline Lua test runner (Rhp::test), a program's own test executable, or fakes
// of a running host's libs.
#include <algorithm>
#include <cstddef>
#include <format>
#include <iostream>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "commands.hpp"
#include "connection.hpp"

#include <rhp/core/value.hpp>
#include <rhp/platform/process.hpp>
#include <rhp/test/cli.hpp>

namespace rhp_cli {

// rhp-cli test [--exe PROGRAM] [--api-from HOST:PORT -i ID [--tls ...]] <test runner arguments>
//   --exe PROGRAM   run the program's own test executable (Rhp::test::main, its real libs) with the
//                   remaining arguments; its exit status is rhp-cli's
//   --api-from      fetch the API description of a running host (rhp.api()) and fake its libs
//   otherwise       run the tests here with the `rhp` API only, or the fakes of --api FILE.json
int test_command(std::vector<std::string> args) {
    std::string exe;
    connection_options conn;
    std::vector<std::string> rest;
    const auto take = [&](std::size_t& i, std::string& into) {
        if (i + 1 >= args.size()) {
            std::println(stderr, "rhp-cli test: {} expects a value", args[i]);
            return false;
        }
        into = args[++i];
        return true;
    };
    // rhp-cli's own options are named so they can't be mistaken for the runner's (--filter --tls).
    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string& a = args[i];
        bool ok = true;
        if (a == "--exe") {
            ok = take(i, exe);
        } else if (a == "--api-from") {
            ok = take(i, conn.address);
        } else if (a == "--api-identity") {
            ok = take(i, conn.identity);
        } else if (a == "--api-ca") {
            ok = take(i, conn.ca);
        } else if (a == "--api-server-name") {
            ok = take(i, conn.server_name);
        } else if (a == "--api-tls") {
            conn.tls = true;
        } else if (a == "--api-insecure-lan") {
            conn.insecure_lan = true;
        } else {
            rest.push_back(a);
        }
        if (!ok) {
            return 2;
        }
    }
    if (std::ranges::find(rest, "--help") != rest.end() || std::ranges::find(rest, "-h") != rest.end()) {
        std::print("rhp-cli test also takes:\n"
                   "      --exe PROGRAM          run a program's own test executable (its real libs) with the other arguments\n"
                   "      --api-from HOST:PORT   fake the libs of a running host, with --api-identity FILE (or RHP_IDENTITY),\n"
                   "                             --api-tls, --api-ca FILE, --api-server-name NAME, --api-insecure-lan\n\n");
    }
    if (!exe.empty()) {
        auto status = Rhp::platform::run_process(exe, rest);
        if (!status) {
            std::println(stderr, "rhp-cli test: {}", status.error());
            return 2;
        }
        return *status;
    }
    std::optional<Rhp::value> api;
    if (!conn.address.empty()) {
        if (conn.identity.empty()) {
            conn.identity = Rhp::platform::environment_variable("RHP_IDENTITY");
        }
        if (conn.identity.empty()) {
            std::println(stderr, "rhp-cli test: --api-from needs --api-identity FILE (or RHP_IDENTITY)");
            return 2;
        }
        auto c = open_connection(conn, nullptr, true);
        if (!c) {
            return 2;
        }
        auto described = c->client->exec("return rhp.api()", "rhp-cli test");
        if (!described || described->empty()) {
            std::println(stderr, "rhp-cli test: the host didn't describe its API: {}", described ? std::string{"no value"} : std::format("{}", described.error()));
            return 2;
        }
        api = std::move(described->front());
    }
    std::vector<std::string_view> views{rest.begin(), rest.end()};
    return Rhp::test::run_cli(views, {}, "rhp-cli test", std::cout, std::cerr, api ? &*api : nullptr);
}

} // namespace rhp_cli

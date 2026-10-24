// I: a whole request: client -> session -> host -> sandbox -> back, over the in-process loopback
// transport, on one thread (io<zero_threads> on both ends, so no scheduler noise): what one remote
// call costs in CPU, next to the same script run on the sandbox directly.
#include <chrono>
#include <utility>

#include "bench_support.hpp"
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include <rhp/rhp.hpp>

namespace bench_e2e_fixture {

int add(int a, int b) {
    return a + b;
}
using e2e_lib = Rhp::lib<"benche2e">::fn<"add", &add>;

using cfg = Rhp::config<>::transport<Rhp::net::loopback>::io<Rhp::exec::zero_threads>::logger<Rhp::core::null_logger>;

} // namespace bench_e2e_fixture

using namespace bench_e2e_fixture;

TEST_CASE("bench e2e: remote calls over loopback on one thread", "[bench][e2e]") {
    const auto admin = Rhp::security::key::generate();
    const auto developer = Rhp::security::ed25519_secret_key::generate();
    REQUIRE(admin);
    REQUIRE(developer);
    const auto at = Rhp::endpoint::listen("bench.e2e", 1);
    Rhp::host<cfg> host{at, Rhp::security::keyring{{"admin", *admin, Rhp::role::kAdmin}}, Rhp::security::trusted_signers{{"dev", developer->public_key()}}};
    REQUIRE(host.install<e2e_lib>());
    Rhp::client<cfg> client{at.reversed(), Rhp::security::psk_identity{"admin", *admin}, Rhp::security::signing_key{"dev", *developer}};

    // Drives both ends until `p` is ready.
    const auto finish = [&](auto& p) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
        while (!p.ready()) {
            host.pump();
            client.poll();
            if (std::chrono::steady_clock::now() > deadline) {
                FAIL("a benchmark request didn't finish");
            }
        }
        return std::move(p).get();
    };

    auto first = client.async().exec<int>("return benche2e.add(1, 2)");
    REQUIRE(finish(first) == 3);

    auto mod = client.async().load("bench.e2e.mod", "local M = {} function M.add(a, b) return benche2e.add(a, b) end return M");
    const auto loaded = finish(mod);
    REQUIRE(loaded);

    BENCHMARK("e2e rhp: signed exec of a one-line script") {
        auto p = client.async().exec<int>("return benche2e.add(1, 2)");
        return *finish(p);
    };
    BENCHMARK("e2e rhp: call of a module function") {
        auto p = client.async().call(*loaded, "add", 1, 2);
        return finish(p)->size();
    };

    Rhp::script::sandbox box{rhp_bench::quiet()};
    REQUIRE(box.install<e2e_lib>());
    BENCHMARK("e2e local: the same exec on a sandbox") {
        return *box.exec<int>("return benche2e.add(1, 2)");
    };
}

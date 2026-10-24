// An application of an installed RHP: one include, one target (Rhp::rhp). Exits non-zero when a
// check fails, so ctest reports it.
#include <chrono>
#include <cstdio>
#include <print>
#include <string>
#include <string_view>
#include <thread>

#include <rhp/rhp.hpp>

namespace {

int g_failures = 0;

void check(bool ok, std::string_view what) {
    if (!ok) {
        std::println(stderr, "FAILED: {}", what);
        ++g_failures;
    }
}

#if RHP_ENABLE

int g_counter = 0;
int bump(int by) {
    g_counter += by;
    return g_counter;
}
using consumer_lib = Rhp::lib<"consumer">::fn<"bump", &bump>;

using loopback_cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>;

void live() {
    Rhp::script::sandbox box;
    check(box.exec<int>("return 6 * 7") == 42, "sandbox exec");

    // Monocypher (BLAKE2b-256 of nothing).
    check(Rhp::security::to_hex(Rhp::security::blake2b_256(std::string_view{})) == "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8", "blake2b");

    // The TLS backend links (no certificate: it reports an error, which is fine here).
    (void)Rhp::security::tls::auto_backend::client(Rhp::security::tls::settings{});

    // A host (pumped by a "game thread") and a client over the in-process loopback transport; the
    // client signs its scripts with a developer key the host trusts.
    const auto admin = Rhp::security::key::generate();
    const auto developer = Rhp::security::ed25519_secret_key::generate();
    check(admin.has_value() && developer.has_value(), "key generation");
    if (!admin || !developer) {
        return;
    }
    const auto at = Rhp::endpoint::listen("package.consumer", 1);
    Rhp::host<loopback_cfg> host{at, Rhp::security::keyring{{"admin", *admin, Rhp::role::kAdmin}}, Rhp::security::trusted_signers{{"dev", developer->public_key()}}};
    check(host.install<consumer_lib>().has_value(), "host install");
    std::jthread game_thread{[&host](std::stop_token stop) {
        while (!stop.stop_requested()) {
            host.pump();
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
    }};
    Rhp::client<loopback_cfg> client{at.reversed(), Rhp::security::psk_identity{"admin", *admin}, Rhp::security::signing_key{"dev", *developer}};
    check(client.connect().has_value(), "client connect");
    check(client.exec<int>("return consumer.bump(2) + consumer.bump(3)") == 7, "client exec through the host");
}

#else

void live() {
    Rhp::script::sandbox box;
    const auto r = box.exec<int>("return 1");
    check(!r && r.error().code == Rhp::errc::kDisabled, "a sandbox compiled out reports kDisabled");
}

#endif

} // namespace

int main() {
#if defined(RHP_PACKAGE_PROTOCOL_REVISION)
    check(Rhp::wire::kProtocolRevision == RHP_PACKAGE_PROTOCOL_REVISION, "rhp_PROTOCOL_REVISION matches the headers");
#endif
    live();
    std::println("consumer: RHP_ENABLE={} protocol revision {} on {}: {}", RHP_ENABLE, Rhp::wire::kProtocolRevision, Rhp::platform::to_string(Rhp::platform::kOs),
                 g_failures == 0 ? "ok" : "FAILED");
    return g_failures == 0 ? 0 : 1;
}

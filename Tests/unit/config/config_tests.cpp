#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>
#include <type_traits>

#include <catch2/catch_test_macros.hpp>

#include <rhp/config/config.hpp>
#include <rhp/core/errors_mode.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/log.hpp>
#include <rhp/exec/executor.hpp>
#include <rhp/exec/io_runner.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/net/tcp/tcp.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/psk_keyring.hpp>
#include <rhp/security/signer.hpp>
#include <rhp/security/tls/auto_backend.hpp>
#include <rhp/security/tls/tls.hpp>
#include <rhp/wire/codec/msgpack.hpp>

namespace config_tests_fixtures {

// The smallest user transport the concept accepts.
struct my_transport {
    static constexpr std::string_view name = "mine";
    static Rhp::result<std::unique_ptr<Rhp::net::listener>> listen(Rhp::net::io_context&, const Rhp::endpoint&, Rhp::net::accept_fn) {
        return Rhp::fail(Rhp::errc::kDisabled);
    }
    static void dial(Rhp::net::io_context&, const Rhp::endpoint&, Rhp::net::connect_fn) {}
};

struct game_clock {
    [[nodiscard]] std::chrono::steady_clock::time_point now() const { return std::chrono::steady_clock::time_point{}; }
};

struct not_a_transport {};

} // namespace config_tests_fixtures

using namespace config_tests_fixtures;

TEST_CASE("config: Rhp::config<> is the documented default chain", "[config]") {
    using cfg = Rhp::config<>;
    STATIC_REQUIRE(std::is_same_v<cfg::transport_t, Rhp::net::tcp>);
    STATIC_REQUIRE(std::is_same_v<cfg::discovery_t, Rhp::net::mdns>);
    STATIC_REQUIRE(std::is_same_v<cfg::codec_t, Rhp::wire::msgpack>);
    STATIC_REQUIRE(std::is_same_v<cfg::auth_t, Rhp::security::psk_keyring>);
    STATIC_REQUIRE(std::is_same_v<cfg::credential_t, Rhp::security::psk_identity>);
    STATIC_REQUIRE(std::is_same_v<cfg::executor_t, Rhp::exec::pumped>);
    STATIC_REQUIRE(std::is_same_v<cfg::io_t, Rhp::exec::owned_io_thread>);
    STATIC_REQUIRE(std::is_same_v<cfg::errors_t, Rhp::errors::expected>);
    STATIC_REQUIRE(std::is_same_v<cfg::clock_t, Rhp::exec::steady_clock>);
    STATIC_REQUIRE(std::is_same_v<cfg::logger_t, Rhp::core::stderr_logger>);
    STATIC_REQUIRE(cfg::limits_v == Rhp::limits{});
    STATIC_REQUIRE(std::is_same_v<cfg::return_t<int>, Rhp::result<int>>);
    STATIC_REQUIRE(Rhp::configuration<cfg>);
    STATIC_REQUIRE_FALSE(Rhp::configuration<int>);
}

TEST_CASE("config: links set slots / later links win / the rest keeps defaults", "[config]") {
    using cfg = Rhp::config<>                   //
        ::transport<Rhp::net::loopback>         //
        ::io<Rhp::exec::zero_threads>           //
        ::limits<Rhp::limits{.wall_ms = 5'000}> //
        ::errors<Rhp::errors::throwing>         //
        ::clock<game_clock>                     //
        ::logger<Rhp::core::null_logger>        //
        ::transport<my_transport>;              // overrides loopback
    STATIC_REQUIRE(std::is_same_v<cfg::transport_t, my_transport>);
    STATIC_REQUIRE(std::is_same_v<cfg::io_t, Rhp::exec::zero_threads>);
    STATIC_REQUIRE(cfg::limits_v.wall_ms == 5'000);
    STATIC_REQUIRE(cfg::limits_v.max_frame == Rhp::limits{}.max_frame);
    STATIC_REQUIRE(std::is_same_v<cfg::return_t<int>, int>);
    STATIC_REQUIRE(std::is_same_v<cfg::clock_t, game_clock>);
    STATIC_REQUIRE(std::is_same_v<cfg::logger_t, Rhp::core::null_logger>);
    STATIC_REQUIRE(std::is_same_v<cfg::codec_t, Rhp::wire::msgpack>);
    // Order of links doesn't matter for the result.
    using a = Rhp::config<>::io<Rhp::exec::zero_threads>::transport<Rhp::net::loopback>;
    using b = Rhp::config<>::transport<Rhp::net::loopback>::io<Rhp::exec::zero_threads>;
    STATIC_REQUIRE(std::is_same_v<a::transport_t, b::transport_t>);
    STATIC_REQUIRE(std::is_same_v<a::io_t, b::io_t>);
}

template <class T>
concept transport_slot_accepts = requires { typename Rhp::config<>::template transport<T>; };

TEST_CASE("config: every slot is concept-checked", "[config]") {
    STATIC_REQUIRE(transport_slot_accepts<my_transport>);
    STATIC_REQUIRE_FALSE(transport_slot_accepts<not_a_transport>);
    STATIC_REQUIRE(Rhp::net::transport<Rhp::net::tcp>);
    STATIC_REQUIRE(Rhp::net::transport<Rhp::net::loopback>);
    STATIC_REQUIRE(Rhp::exec::clock_source<game_clock>);
}

TEST_CASE("config: the signer slot defaults to Ed25519 and can be switched off by type", "[config]") {
    using defaults = Rhp::config<>;
    STATIC_REQUIRE(std::is_same_v<defaults::signer_t, Rhp::security::ed25519>);
    STATIC_REQUIRE(std::is_same_v<defaults::signing_key_t, Rhp::security::signing_key>);
    STATIC_REQUIRE(std::is_same_v<defaults::trust_t, Rhp::security::trusted_signers>);
    using off = defaults::signer<Rhp::security::unsigned_scripts>::transport<Rhp::net::loopback>;
    STATIC_REQUIRE(std::is_same_v<off::signer_t, Rhp::security::unsigned_scripts>);
    STATIC_REQUIRE(std::is_same_v<off::transport_t, Rhp::net::loopback>);
    // The later link wins.
    using back = off::signer<Rhp::security::ed25519>;
    STATIC_REQUIRE(std::is_same_v<back::signer_t, Rhp::security::ed25519>);
}

TEST_CASE("config: the tls slot defaults to auto_backend and takes none", "[config]") {
    using base = Rhp::config<>;
    STATIC_REQUIRE(std::is_same_v<base::tls_t, Rhp::security::tls::auto_backend>);
    using plain = base::tls<Rhp::security::tls::none>;
    STATIC_REQUIRE(std::is_same_v<plain::tls_t, Rhp::security::tls::none>);
    STATIC_REQUIRE(std::is_same_v<plain::transport_t, base::transport_t>);
#if !RHP_ENABLE
    // RHP_ENABLE=OFF builds no TLS backend: the default is none.
    STATIC_REQUIRE(std::is_same_v<base::tls_t, Rhp::security::tls::none>);
#endif
    CHECK_FALSE(Rhp::security::tls::backend_ops_for<Rhp::security::tls::none>.available());
}

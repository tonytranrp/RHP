#include <cstddef>
#include <format>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <rhp_test/tls_fixtures.hpp>

#include <rhp/core/error.hpp>
#include <rhp/security/tls/auto_backend.hpp>
#include <rhp/security/tls/mbedtls.hpp>
#include <rhp/security/tls/openssl.hpp>
#include <rhp/security/tls/tls.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace tls = Rhp::security::tls;

namespace {

// The backends this build has (at least one whenever RHP_WITH_TLS is on).
std::vector<tls::backend_ops> backends() {
    std::vector<tls::backend_ops> out;
#if RHP_TLS_HAS_OPENSSL
    out.push_back(tls::backend_ops_for<tls::openssl>);
#endif
#if RHP_TLS_HAS_MBEDTLS
    out.push_back(tls::backend_ops_for<tls::mbedtls>);
#endif
    return out;
}

std::string text(const Rhp::utils::byte_buffer& b) {
    return {reinterpret_cast<const char*>(b.view().data()), b.size()};
}

// One client and one server engine, wired to each other in memory.
struct tls_pair {
    std::unique_ptr<tls::engine> client;
    std::unique_ptr<tls::engine> server;
    Rhp::utils::byte_buffer client_plain; // what the client received
    Rhp::utils::byte_buffer server_plain; // what the server received
    std::string error;

    // Moves ciphertext both ways until neither side has anything to say. False on a failure.
    bool shuttle(Rhp::utils::byte_buffer to_server, Rhp::utils::byte_buffer to_client = {}) {
        for (int round = 0; round < 50 && (!to_server.empty() || !to_client.empty()); ++round) {
            Rhp::utils::byte_buffer next_to_client;
            Rhp::utils::byte_buffer next_to_server;
            if (!to_server.empty()) {
                if (auto ok = server->receive(to_server.view(), server_plain, next_to_client); !ok) {
                    error = std::format("{}", ok.error());
                    return false;
                }
            }
            next_to_client.append(to_client.view());
            if (!next_to_client.empty()) {
                if (auto ok = client->receive(next_to_client.view(), client_plain, next_to_server); !ok) {
                    error = std::format("{}", ok.error());
                    return false;
                }
            }
            to_server = std::move(next_to_server);
            to_client = {};
        }
        return true;
    }

    bool handshake() {
        Rhp::utils::byte_buffer hello;
        if (auto ok = client->start(hello); !ok) {
            error = std::format("{}", ok.error());
            return false;
        }
        Rhp::utils::byte_buffer nothing;
        if (auto ok = server->start(nothing); !ok || !nothing.empty()) {
            error = "server start";
            return false;
        }
        return shuttle(std::move(hello)) && client->established() && server->established();
    }
};

tls_pair make_tls_pair(const tls::backend_ops& client_backend, const tls::backend_ops& server_backend, const tls::settings& client_settings = {},
                       const tls::settings& server_settings = {}) {
    auto server_ctx = server_backend.server(server_settings);
    REQUIRE(server_ctx);
    auto client_ctx = client_backend.client(client_settings);
    REQUIRE(client_ctx);
    auto c = (*client_ctx)->make_engine();
    auto s = (*server_ctx)->make_engine();
    REQUIRE(c);
    REQUIRE(s);
    return tls_pair{std::move(*c), std::move(*s), {}, {}, {}};
}

} // namespace

TEST_CASE("auto_backend is a backend this build has", "[tls]") {
    STATIC_REQUIRE(tls::backend<tls::auto_backend>);
#if RHP_TLS_HAS_OPENSSL || RHP_TLS_HAS_MBEDTLS
    CHECK(tls::backend_ops_for<tls::auto_backend>.available());
    CHECK_FALSE(backends().empty());
#endif
    CHECK_FALSE(tls::backend_ops_for<tls::none>.available());
}

#if RHP_TLS_HAS_OPENSSL || RHP_TLS_HAS_MBEDTLS

TEST_CASE("a TLS handshake with an ephemeral certificate carries data both ways", "[tls]") {
    const auto all = backends();
    const tls::backend_ops client_backend = GENERATE_REF(Catch::Generators::from_range(all));
    const tls::backend_ops server_backend = GENERATE_REF(Catch::Generators::from_range(all));
    CAPTURE(client_backend.name, server_backend.name);

    tls_pair p = make_tls_pair(client_backend, server_backend);
    const bool shook = p.handshake();
    INFO(p.error); // the TLS error, when the handshake fails
    REQUIRE(shook);

    Rhp::utils::byte_buffer wire;
    REQUIRE(p.client->send(Rhp::utils::as_bytes("hello host"), wire));
    CHECK(text(wire).find("hello host") == std::string::npos); // encrypted
    REQUIRE(p.shuttle(std::move(wire)));
    CHECK(text(p.server_plain) == "hello host");

    Rhp::utils::byte_buffer back;
    const std::string big(100'000, 'x'); // several records
    REQUIRE(p.server->send(Rhp::utils::as_bytes(big), back));
    REQUIRE(p.shuttle({}, std::move(back)));
    CHECK(text(p.client_plain) == big);

    auto a = p.client->binding();
    auto b = p.server->binding();
    REQUIRE(a);
    REQUIRE(b);
    CHECK(*a == *b);

    // A second connection exports a different binding.
    tls_pair q = make_tls_pair(client_backend, server_backend);
    REQUIRE(q.handshake());
    CHECK(*q.client->binding() != *a);
}

TEST_CASE("close_notify ends the peer's TLS", "[tls]") {
    const auto all = backends();
    const tls::backend_ops backend = GENERATE_REF(Catch::Generators::from_range(all));
    CAPTURE(backend.name);
    tls_pair p = make_tls_pair(backend, backend);
    const bool shook = p.handshake();
    INFO(p.error);
    REQUIRE(shook);
    Rhp::utils::byte_buffer bye;
    p.client->close(bye);
    CHECK_FALSE(bye.empty());
    CHECK_FALSE(p.shuttle(std::move(bye)));
    CHECK(p.error.find("closed") != std::string::npos);
}

TEST_CASE("sending before the handshake is refused and a binding needs one", "[tls]") {
    const auto all = backends();
    const tls::backend_ops backend = GENERATE_REF(Catch::Generators::from_range(all));
    tls_pair p = make_tls_pair(backend, backend);
    Rhp::utils::byte_buffer out;
    CHECK_FALSE(p.client->send(Rhp::utils::as_bytes("early"), out));
    CHECK_FALSE(p.client->binding());
}

TEST_CASE("garbage instead of TLS fails the handshake", "[tls]") {
    const auto all = backends();
    const tls::backend_ops backend = GENERATE_REF(Catch::Generators::from_range(all));
    auto ctx = backend.server({});
    REQUIRE(ctx);
    auto server = (*ctx)->make_engine();
    REQUIRE(server);
    Rhp::utils::byte_buffer plain;
    Rhp::utils::byte_buffer out;
    const std::string junk(64, 'R');
    CHECK_FALSE((*server)->receive(Rhp::utils::as_bytes(junk), plain, out));
}

TEST_CASE("a CA-signed host certificate verifies with and without the name", "[tls]") {
    const auto all = backends();
    const tls::backend_ops client_backend = GENERATE_REF(Catch::Generators::from_range(all));
    const tls::backend_ops server_backend = GENERATE_REF(Catch::Generators::from_range(all));
    CAPTURE(client_backend.name, server_backend.name);
    const tls::settings host{std::string{rhp_test::tls::kHostCertPem}, std::string{rhp_test::tls::kHostKeyPem}, {}, {}};

    {
        tls_pair p = make_tls_pair(client_backend, server_backend, tls::settings{{}, {}, std::string{rhp_test::tls::kCaPem}, "game.test"}, host);
        CHECK(p.handshake());
        INFO(p.error);
    }
    {
        tls_pair p = make_tls_pair(client_backend, server_backend, tls::settings{{}, {}, std::string{rhp_test::tls::kCaPem}, {}}, host);
        CHECK(p.handshake());
    }
    {
        tls_pair p = make_tls_pair(client_backend, server_backend, tls::settings{{}, {}, std::string{rhp_test::tls::kCaPem}, "other.test"}, host);
        CHECK_FALSE(p.handshake());
    }
    {
        tls_pair p = make_tls_pair(client_backend, server_backend, tls::settings{{}, {}, std::string{rhp_test::tls::kOtherCaPem}, {}}, host);
        CHECK_FALSE(p.handshake());
    }
    {
        // The ephemeral certificate fails a client that insists on a CA.
        tls_pair p = make_tls_pair(client_backend, server_backend, tls::settings{{}, {}, std::string{rhp_test::tls::kCaPem}, {}}, {});
        CHECK_FALSE(p.handshake());
    }
}

TEST_CASE("a server_name that is an IP address is checked against the certificate's IP addresses", "[tls]") {
    const auto all = backends();
    const tls::backend_ops client_backend = GENERATE_REF(Catch::Generators::from_range(all));
    const tls::backend_ops server_backend = GENERATE_REF(Catch::Generators::from_range(all));
    CAPTURE(client_backend.name, server_backend.name);
    const tls::settings ip_host{std::string{rhp_test::tls::kIpHostCertPem}, std::string{rhp_test::tls::kIpHostKeyPem}, {}, {}}; // 127.0.0.1, ::1
    const tls::settings name_host{std::string{rhp_test::tls::kHostCertPem}, std::string{rhp_test::tls::kHostKeyPem}, {}, {}};   // game.test
    const auto checked = [](std::string_view ca, std::string_view name) { return tls::settings{{}, {}, std::string{ca}, std::string{name}}; };

    for (const std::string_view address : {"127.0.0.1", "0:0:0:0:0:0:0:1", "::1"}) {
        INFO(address);
        tls_pair p = make_tls_pair(client_backend, server_backend, checked(rhp_test::tls::kIpCaPem, address), ip_host);
        CHECK(p.handshake());
        INFO(p.error);
    }
    for (const std::string_view other : {"127.0.0.2", "0:0:0:0:0:0:0:2", "game.test"}) {
        INFO(other);
        tls_pair p = make_tls_pair(client_backend, server_backend, checked(rhp_test::tls::kIpCaPem, other), ip_host);
        CHECK_FALSE(p.handshake());
    }
    {
        // A certificate for a name, however good its chain, isn't one for an address.
        tls_pair p = make_tls_pair(client_backend, server_backend, checked(rhp_test::tls::kCaPem, "127.0.0.1"), name_host);
        CHECK_FALSE(p.handshake());
    }
}

TEST_CASE("bad PEM is reported and not ignored", "[tls]") {
    const auto all = backends();
    const tls::backend_ops backend = GENERATE_REF(Catch::Generators::from_range(all));
    CHECK_FALSE(backend.server(tls::settings{"not a pem", "nor this", {}, {}}));
    CHECK_FALSE(backend.server(tls::settings{std::string{rhp_test::tls::kHostCertPem}, {}, {}, {}}));
    CHECK_FALSE(backend.client(tls::settings{{}, {}, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", {}}));
}

#endif

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/net_support.hpp>

#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/psk_keyring.hpp>
#include <rhp/session/session.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/utils/crc32c.hpp>
#include <rhp/wire/codec/msgpack.hpp>
#include <rhp/wire/frame.hpp>
#include <rhp/wire/messages.hpp>
#include <rhp/wire/ops.hpp>

using namespace std::chrono_literals;
using Rhp::errc;
using Rhp::value;
using Rhp::net::io_context;
// Not `using Rhp::net::link`: POSIX declares ::link().
using net_link = Rhp::net::link;
using Rhp::session::session;
using Rhp::wire::op;
using rhp_test::poll_until;

namespace {

// What the layer above a session sees.
struct events final : Rhp::session::handler {
    bool ready = false;
    bool closed = false;
    Rhp::error why;
    std::vector<std::pair<op, value>> messages;

    void on_ready(session&) override { ready = true; }
    void on_message(session&, op code, value body) override { messages.emplace_back(code, std::move(body)); }
    void on_closed(session&, const Rhp::error& e) override {
        closed = true;
        why = e;
    }
};

// Wraps a link and lets a test damage what goes out.
class tampering_link final : public Rhp::net::link_decorator {
public:
    // Called with every outgoing write (one whole frame per write from a session) and its index.
    using tamper_fn = std::function<void(Rhp::utils::byte_buffer&, int)>;

    tampering_link(std::unique_ptr<net_link> inner, tamper_fn fn) : link_decorator(std::move(inner)), fn_(std::move(fn)) {}

    void send(Rhp::utils::byte_buffer bytes) override {
        if (fn_) {
            fn_(bytes, writes_++);
        }
        link_decorator::send(std::move(bytes));
    }

private:
    tamper_fn fn_;
    int writes_ = 0;
};

[[nodiscard]] Rhp::wire::frame_header header_of(const Rhp::utils::byte_buffer& b) {
    return Rhp::wire::read_header(b.view().first<Rhp::wire::kHeaderSize>());
}

// Rewrites the CRC after a deliberate change, so only the MAC can notice.
void fix_crc(Rhp::utils::byte_buffer& b) {
    const auto h = header_of(b);
    const std::size_t sealed = Rhp::wire::kHeaderSize + h.length;
    const std::uint32_t crc = Rhp::utils::crc32c(b.view().first(sealed));
    Rhp::utils::store_le<std::uint32_t>(b.mutable_view().subspan(sealed).first<4>(), crc);
}

Rhp::limits test_limits() {
    Rhp::limits l;
    l.heartbeat_ms = 50;
    l.heartbeat_misses = 3;
    l.handshake_timeout_ms = 2'000;
    return l;
}

// A host-side and a client-side session over an in-process link, each on its own io_context,
// polled by the test thread.
struct duo {
    io_context host_io;
    io_context client_io;
    Rhp::security::key dev = *Rhp::security::key::generate();
    Rhp::security::psk_keyring keys{Rhp::security::keyring{{"dev", dev, Rhp::role::kPatch}}};
    events host_events;
    events client_events;
    std::unique_ptr<session> host;
    std::unique_ptr<session> client;
    std::unique_ptr<Rhp::net::listener> listener;

    duo(const std::string& channel, Rhp::limits limits, tampering_link::tamper_fn client_tamper = {}, tampering_link::tamper_fn host_tamper = {},
        std::optional<Rhp::security::psk_identity> who = std::nullopt) {
        Rhp::session::options opts;
        opts.limits = limits;
        opts.codec = Rhp::wire::codec_ops_for<Rhp::wire::msgpack>;
        opts.platform = "test";
        auto l = Rhp::net::loopback::listen(host_io, Rhp::endpoint::listen(channel, 1), [&, opts, host_tamper](std::unique_ptr<net_link> a) {
            host = std::make_unique<session>(host_io, std::make_unique<tampering_link>(std::move(a), host_tamper), keys.begin(), host_events, opts,
                                             Rhp::session_id{1});
            host->start();
        });
        REQUIRE(l);
        listener = std::move(*l);
        const Rhp::security::psk_identity identity = who.value_or(Rhp::security::psk_identity{"dev", dev});
        Rhp::net::loopback::dial(client_io, Rhp::endpoint::dial(channel, 1), [&, opts, client_tamper, identity](Rhp::result<std::unique_ptr<net_link>> d) {
            REQUIRE(d);
            client = std::make_unique<session>(client_io, std::make_unique<tampering_link>(std::move(*d), client_tamper), identity.begin(), client_events,
                                               opts);
            client->start();
        });
    }

    bool poll(const std::function<bool()>& done, std::chrono::milliseconds timeout = 10s) { return poll_until({&host_io, &client_io}, done, timeout); }

    bool handshake() {
        return poll([this] { return (host_events.ready && client_events.ready) || host_events.closed || client_events.closed; }) && host_events.ready &&
               client_events.ready;
    }
};

value envelope(std::uint64_t req, value body) {
    return Rhp::to_value(Rhp::wire::envelope{req, 0, std::move(body)});
}

} // namespace

TEST_CASE("session: handshake gives both sides the identity; role and session id", "[session]") {
    duo d{"session_tests.handshake", test_limits()};
    REQUIRE(d.handshake());
    CHECK(d.host->identity() == "dev");
    CHECK(d.host->granted() == Rhp::role::kPatch);
    CHECK(d.client->identity() == "dev");
    CHECK(d.client->granted() == Rhp::role::kPatch);
    CHECK(d.client->id() == Rhp::session_id{1});
    CHECK(d.client->peer_platform() == "test");
    CHECK(d.host->peer_platform() == "test");
}

TEST_CASE("session: messages arrive once and in order both ways", "[session]") {
    duo d{"session_tests.order", test_limits()};
    REQUIRE(d.handshake());
    for (int i = 1; i <= 50; ++i) {
        REQUIRE(d.client->send(op::kExec, envelope(static_cast<std::uint64_t>(i), value{i})));
    }
    REQUIRE(d.host->send(op::kResult, envelope(1, value{"done"})));
    REQUIRE(d.poll([&] { return d.host_events.messages.size() == 50 && d.client_events.messages.size() == 1; }));
    for (int i = 0; i < 50; ++i) {
        CHECK(d.host_events.messages[static_cast<std::size_t>(i)].second.find("body")->get_if<std::int64_t>() != nullptr);
        CHECK(*d.host_events.messages[static_cast<std::size_t>(i)].second.find("body")->get_if<std::int64_t>() == i + 1);
    }
    CHECK(d.client->stats().sent == 50);
    CHECK(d.host->stats().received == 50);
}

TEST_CASE("session: standalone acks wait for a frame to carry them", "[session]") {
    // The host acks a burst of 20 frames: at once for every 8th, the rest after ack_delay_ms (no
    // reply carries them here). Before delayed acks it sent one per read.
    int acks = 0;
    std::uint64_t acked = 0;
    auto count_acks = [&](Rhp::utils::byte_buffer& b, int) {
        const auto h = header_of(b);
        if (h.code == op::kAck) {
            ++acks;
        }
        acked = std::max<std::uint64_t>(acked, h.ack);
    };
    duo d{"session_tests.delayed_acks", test_limits(), {}, count_acks};
    REQUIRE(d.handshake());
    const int before = acks;
    for (int i = 1; i <= 20; ++i) {
        REQUIRE(d.client->send(op::kExec, envelope(static_cast<std::uint64_t>(i), value{i})));
    }
    REQUIRE(d.poll([&] { return d.host_events.messages.size() == 20 && acked >= 20; }));
    CHECK(acks - before <= 4);

    // A reply sent before the delay runs out carries the ack: no standalone one.
    const int quiet = acks;
    REQUIRE(d.client->send(op::kExec, envelope(21, value{21})));
    REQUIRE(d.poll([&] { return d.host_events.messages.size() == 21; }));
    REQUIRE(d.host->send(op::kResult, envelope(21, value{"ok"})));
    REQUIRE(d.poll([&] { return d.client_events.messages.size() == 1 && acked >= 21; }));
    CHECK(acks - quiet <= 1); // 0 unless the poll above took longer than the delay
}

TEST_CASE("session: only sequenced ops go through send; only when ready", "[session]") {
    duo d{"session_tests.send_rules", test_limits()};
    REQUIRE(d.poll([&] { return d.client != nullptr; }));
    CHECK(d.client->send(op::kExec, value{}).error().code == errc::kTransport); // still handshaking
    REQUIRE(d.handshake());
    CHECK(d.client->send(op::kPing, value{}).error().code == errc::kInvalidArgument);
}

TEST_CASE("session: a corrupt frame is nacked, resent and delivered exactly once", "[session]") {
    // The client's 3rd sequenced write (after hello and response: writes 0 and 1) loses a bit.
    int sequenced_seen = 0;
    auto corrupt_second_request = [&sequenced_seen](Rhp::utils::byte_buffer& b, int) {
        const auto h = header_of(b);
        if (h.seq != 0 && ++sequenced_seen == 2) {
            b.mutable_view()[Rhp::wire::kHeaderSize] ^= std::byte{0x40};
        }
    };
    duo d{"session_tests.nack", test_limits(), corrupt_second_request};
    REQUIRE(d.handshake());
    for (int i = 1; i <= 4; ++i) {
        REQUIRE(d.client->send(op::kExec, envelope(static_cast<std::uint64_t>(i), value{i})));
    }
    REQUIRE(d.poll([&] { return d.host_events.messages.size() == 4; }));
    rhp_test::poll_for({&d.host_io, &d.client_io}, 100ms); // let any late resend arrive
    REQUIRE(d.host_events.messages.size() == 4);
    for (int i = 0; i < 4; ++i) {
        CHECK(*d.host_events.messages[static_cast<std::size_t>(i)].second.find("req")->get_if<std::int64_t>() == i + 1);
    }
    CHECK(d.host->stats().crc_errors == 1);
    CHECK(d.host->stats().nacks_sent >= 1);
    CHECK(d.client->stats().resent >= 1);
    CHECK_FALSE(d.host_events.closed);
}

TEST_CASE("session: a forged frame (CRC fixed up, MAC wrong) ends the session", "[session]") {
    int sequenced_seen = 0;
    auto forge = [&sequenced_seen](Rhp::utils::byte_buffer& b, int) {
        const auto h = header_of(b);
        if (h.seq != 0 && ++sequenced_seen == 1) {
            b.mutable_view()[Rhp::wire::kHeaderSize] ^= std::byte{0x01};
            fix_crc(b);
        }
    };
    duo d{"session_tests.forge", test_limits(), forge};
    REQUIRE(d.handshake());
    REQUIRE(d.client->send(op::kExec, envelope(1, value{1})));
    REQUIRE(d.poll([&] { return d.host_events.closed && d.client_events.closed; }));
    CHECK(d.host_events.why.code == errc::kAuth);
    CHECK(d.client_events.why.code == errc::kAuth); // told why by the host's error frame
    CHECK(d.host_events.messages.empty());
}

TEST_CASE("session: a wrong key never becomes ready", "[session]") {
    auto other = Rhp::security::key::generate();
    duo d{"session_tests.wrong_key", test_limits(), {}, {}, Rhp::security::psk_identity{"dev", *other}};
    REQUIRE(d.poll([&] { return d.host_events.closed && d.client_events.closed; }));
    CHECK_FALSE(d.host_events.ready);
    CHECK_FALSE(d.client_events.ready);
    CHECK(d.client_events.why.code == errc::kAuth);
}

TEST_CASE("session: heartbeats keep an idle session alive; silence ends it", "[session]") {
    duo d{"session_tests.heartbeat", test_limits()};
    REQUIRE(d.handshake());
    rhp_test::poll_for({&d.host_io, &d.client_io}, 400ms); // 8 intervals of idle traffic
    CHECK_FALSE(d.host_events.closed);
    CHECK_FALSE(d.client_events.closed);

    // Stop polling the client: the host hears nothing for 3 intervals.
    REQUIRE(poll_until({&d.host_io}, [&] { return d.host_events.closed; }, 5s));
    CHECK(d.host_events.why.code == errc::kTimeout);
}

TEST_CASE("session: no handshake within the timeout ends the connection", "[session]") {
    io_context io;
    events host_events;
    std::unique_ptr<session> host;
    Rhp::security::psk_keyring keys{Rhp::security::keyring{{"dev", *Rhp::security::key::generate(), Rhp::role::kObserve}}};
    Rhp::limits l = test_limits();
    l.handshake_timeout_ms = 100;
    Rhp::session::options opts;
    opts.limits = l;
    opts.codec = Rhp::wire::codec_ops_for<Rhp::wire::msgpack>;
    auto listener = Rhp::net::loopback::listen(io, Rhp::endpoint::listen("session_tests.silent", 1), [&](std::unique_ptr<net_link> a) {
        host = std::make_unique<session>(io, std::move(a), keys.begin(), host_events, opts, Rhp::session_id{1});
        host->start();
    });
    REQUIRE(listener);
    std::unique_ptr<net_link> silent;
    Rhp::net::loopback::dial(io, Rhp::endpoint::dial("session_tests.silent", 1), [&](Rhp::result<std::unique_ptr<net_link>> r) { silent = std::move(*r); });
    REQUIRE(poll_until({&io}, [&] { return host_events.closed; }, 5s));
    CHECK(host_events.why.code == errc::kTimeout);
    CHECK_FALSE(host_events.ready);
}

TEST_CASE("session: garbage and other protocol revisions are refused", "[session]") {
    io_context io;
    events host_events;
    std::unique_ptr<session> host;
    Rhp::security::psk_keyring keys{Rhp::security::keyring{{"dev", *Rhp::security::key::generate(), Rhp::role::kObserve}}};
    Rhp::session::options opts;
    opts.limits = test_limits();
    opts.codec = Rhp::wire::codec_ops_for<Rhp::wire::msgpack>;
    auto listener = Rhp::net::loopback::listen(io, Rhp::endpoint::listen("session_tests.garbage", 1), [&](std::unique_ptr<net_link> a) {
        host = std::make_unique<session>(io, std::move(a), keys.begin(), host_events, opts, Rhp::session_id{1});
        host->start();
    });
    REQUIRE(listener);
    std::unique_ptr<net_link> raw;
    rhp_test::recorder raw_events;
    Rhp::net::loopback::dial(io, Rhp::endpoint::dial("session_tests.garbage", 1), [&](Rhp::result<std::unique_ptr<net_link>> r) { raw = std::move(*r); });
    REQUIRE(poll_until({&io}, [&] { return raw != nullptr && host != nullptr; }));
    raw->start(raw_events);

    SECTION("a frame of another revision") {
        Rhp::wire::frame_header h;
        h.revision = Rhp::wire::kProtocolRevision + 1;
        h.code = op::kHello;
        Rhp::utils::byte_buffer b;
        REQUIRE(Rhp::wire::encode_frame(h, {}, b, nullptr, 1024));
        raw->send(std::move(b));
        REQUIRE(poll_until({&io}, [&] { return host_events.closed; }));
        CHECK(host_events.why.code == errc::kProtocolRevisionMismatch);
        // The refusal reached the client as a kError frame.
        REQUIRE(poll_until({&io}, [&] { return raw_events.received.size() >= Rhp::wire::kHeaderSize; }));
        CHECK(header_of(raw_events.received).code == op::kError);
    }
    SECTION("a frame too big for an anonymous peer") {
        Rhp::wire::frame_header h;
        h.code = op::kHello;
        const std::string big(20'000, 'x');
        Rhp::utils::byte_buffer b;
        REQUIRE(Rhp::wire::encode_frame(h, Rhp::utils::as_bytes(big), b, nullptr, 1u << 20));
        raw->send(std::move(b));
        REQUIRE(poll_until({&io}, [&] { return host_events.closed; }));
        CHECK(host_events.why.code == errc::kLimitExceeded);
    }
    SECTION("not RHP at all") {
        raw->send(rhp_test::buffer_of("GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        REQUIRE(poll_until({&io}, [&] { return host_events.closed; }));
        CHECK(host_events.why.code == errc::kProtocol);
    }
}

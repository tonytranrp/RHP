#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/net_support.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/net/address.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/session/admission.hpp>

using namespace std::chrono_literals;
using Rhp::errc;
using Rhp::net::ip_address;

namespace admission_fixtures {

// A link that only says where it comes from; the test makes it "send" bytes.
class fake_link final : public Rhp::net::link {
public:
    explicit fake_link(std::optional<ip_address> from) : from_(from) {}

    void start(Rhp::net::link_handler& handler) override { handler_ = &handler; }
    void send(Rhp::utils::byte_buffer) override {}
    void close() noexcept override {}
    [[nodiscard]] std::string peer() const override { return "fake"; }
    [[nodiscard]] std::optional<ip_address> address() const noexcept override { return from_; }

    // The peer sends a byte.
    void speak() {
        const std::byte one{1};
        handler_->on_bytes(Rhp::utils::bytes_view{&one, 1});
    }

private:
    std::optional<ip_address> from_;
    Rhp::net::link_handler* handler_ = nullptr;
};

// One admitted connection: its (watched) link, its ticket, whether the admission closed it and why.
struct conn {
    std::unique_ptr<Rhp::net::link> link;
    fake_link* raw = nullptr;
    Rhp::session::admission::ticket ticket = 0;
    bool closed = false;
    Rhp::error why;
    rhp_test::recorder seen;
};

struct bench {
    Rhp::net::io_context io;
    Rhp::session::admission admission;
    std::vector<std::unique_ptr<conn>> conns;

    explicit bench(const Rhp::limits& limits) : admission(io, limits) {}

    // Admits a connection from `from`; nullptr when it was refused (the error goes to `refused`).
    conn* open(std::optional<ip_address> from, Rhp::error* refused = nullptr) {
        auto c = std::make_unique<conn>();
        auto fake = std::make_unique<fake_link>(from);
        c->raw = fake.get();
        c->link = std::move(fake);
        conn* raw = c.get();
        auto ticket = admission.admit(c->link, [raw](const Rhp::error& why) {
            raw->closed = true;
            raw->why = why;
        });
        if (!ticket) {
            if (refused != nullptr) {
                *refused = ticket.error();
            }
            return nullptr;
        }
        c->ticket = *ticket;
        c->link->start(c->seen);
        conns.push_back(std::move(c));
        return raw;
    }
};

constexpr ip_address kHome = ip_address::v4(192, 168, 1, 2);
constexpr ip_address kAway = ip_address::v4(203, 0, 113, 9);

} // namespace admission_fixtures

using namespace admission_fixtures;

TEST_CASE("admission: a full cap gives the slot of the oldest silent connection to a new one", "[session][admission]") {
    bench b{Rhp::limits{.pending_handshakes = 3, .handshakes_per_source = 0, .first_byte_ms = 0}};
    conn* first = b.open(std::nullopt);
    conn* second = b.open(std::nullopt);
    conn* third = b.open(std::nullopt);
    REQUIRE(first);
    REQUIRE(second);
    REQUIRE(third);
    first->raw->speak(); // it is talking: the silent second goes first
    CHECK(first->seen.received.size() == 1);
    conn* fourth = b.open(std::nullopt);
    REQUIRE(fourth);
    CHECK(second->closed);
    CHECK(second->why.code == errc::kLimitExceeded);
    CHECK_FALSE(first->closed);
    CHECK_FALSE(third->closed);
    CHECK(b.admission.pending() == 3);
    // Every one has spoken: the next is refused.
    third->raw->speak();
    fourth->raw->speak();
    Rhp::error why;
    CHECK(b.open(std::nullopt, &why) == nullptr);
    CHECK(why.code == errc::kLimitExceeded);
    // A slot that is released (authenticated, closed) is free again.
    b.admission.release(first->ticket);
    b.admission.release(first->ticket); // twice is harmless
    CHECK(b.admission.pending() == 2);
    CHECK(b.open(std::nullopt) != nullptr);
}

TEST_CASE("admission: a full cap gives the slot of a stalled handshake to a new one", "[session][admission]") {
    // A quarter of the handshake deadline: 50 ms.
    bench b{Rhp::limits{.pending_handshakes = 2, .handshakes_per_source = 0, .handshake_timeout_ms = 200, .first_byte_ms = 0}};
    conn* first = b.open(kHome);
    conn* second = b.open(kAway);
    REQUIRE(first);
    REQUIRE(second);
    first->raw->speak();
    second->raw->speak();
    // Both are talking and young: handshakes under way keep their slots.
    Rhp::error why;
    CHECK(b.open(kHome, &why) == nullptr);
    CHECK(why.code == errc::kLimitExceeded);
    std::this_thread::sleep_for(80ms);
    // Still pending after a quarter of the deadline: stalled. The oldest goes.
    conn* third = b.open(std::nullopt);
    REQUIRE(third);
    CHECK(first->closed);
    CHECK(first->why.code == errc::kLimitExceeded);
    CHECK_FALSE(second->closed);
    // A silent one still goes before a stalled one; then the stalled one, never the young third.
    conn* fourth = b.open(std::nullopt);
    REQUIRE(fourth);
    CHECK(third->closed);
    CHECK_FALSE(second->closed);
    fourth->raw->speak();
    conn* fifth = b.open(kAway);
    REQUIRE(fifth);
    CHECK(second->closed);
    CHECK_FALSE(fourth->closed);
    CHECK(b.admission.pending() == 2);
}

TEST_CASE("admission: each source has its own cap", "[session][admission]") {
    bench b{Rhp::limits{.pending_handshakes = 10, .handshakes_per_source = 2, .first_byte_ms = 0}};
    conn* a1 = b.open(kAway);
    conn* a2 = b.open(kAway);
    REQUIRE(a1);
    REQUIRE(a2);
    conn* home = b.open(kHome);
    REQUIRE(home);
    // A third from the same source takes the place of its own oldest silent one, nobody else's.
    conn* a3 = b.open(kAway);
    REQUIRE(a3);
    CHECK(a1->closed);
    CHECK_FALSE(home->closed);
    a2->raw->speak();
    a3->raw->speak();
    Rhp::error why;
    CHECK(b.open(kAway, &why) == nullptr);
    CHECK(why.code == errc::kLimitExceeded);
    CHECK(b.open(kHome) != nullptr);
    // Links without an IP address (in-process, IPC) only count toward the total.
    for (int i = 0; i < 5; ++i) {
        CHECK(b.open(std::nullopt) != nullptr);
    }
}

TEST_CASE("admission: an IPv6 /64 is one source", "[session][admission]") {
    bench b{Rhp::limits{.pending_handshakes = 10, .handshakes_per_source = 1, .first_byte_ms = 0}};
    conn* one = b.open(ip_address::parse("2001:db8:1:2::10"));
    REQUIRE(one);
    one->raw->speak();
    CHECK(b.open(ip_address::parse("2001:db8:1:2:ffff::20")) == nullptr);
    CHECK(b.open(ip_address::parse("2001:db8:1:3::10")) != nullptr);
}

TEST_CASE("admission: a connection that sends nothing in time is closed", "[session][admission]") {
    bench b{Rhp::limits{.pending_handshakes = 10, .first_byte_ms = 60}};
    conn* silent = b.open(kHome);
    conn* talker = b.open(kHome);
    REQUIRE(silent);
    REQUIRE(talker);
    talker->raw->speak();
    REQUIRE(rhp_test::poll_until({&b.io}, [&] { return silent->closed; }, 5s));
    CHECK(silent->why.code == errc::kTimeout);
    CHECK(b.admission.pending() == 1);
    rhp_test::poll_for({&b.io}, 100ms);
    CHECK_FALSE(talker->closed); // it spoke: the handshake's own deadline is the session's business
    // Later ones get their own deadline.
    conn* late = b.open(kAway);
    REQUIRE(late);
    REQUIRE(rhp_test::poll_until({&b.io}, [&] { return late->closed; }, 5s));
}

TEST_CASE("admission: a cap of zero refuses everyone", "[session][admission]") {
    bench b{Rhp::limits{.pending_handshakes = 0}};
    Rhp::error why;
    CHECK(b.open(kHome, &why) == nullptr);
    CHECK(why.code == errc::kLimitExceeded);
}

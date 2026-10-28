// custom_transport: plugging your own transport into Rhp::config<>. This one wraps the in-process
// loopback transport and meters every byte each way — the same shape a Steam P2P socket, a USB
// serial link or an in-house relay would have. RHP adds framing, CRC, MAC, acks and heartbeats on
// top of whatever ordered byte stream the transport provides.
#include <atomic>
#include <cstddef>
#include <memory>
#include <print>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <rhp/rhp.hpp>

namespace metered {

std::atomic<std::size_t> g_bytes_sent{0};
std::atomic<std::size_t> g_links{0};

// A link that forwards to another link and counts what goes out. link_decorator forwards the rest,
// including what the session's security depends on (loopback, encrypted, channel_binding).
class counting_link final : public Rhp::net::link_decorator {
public:
    explicit counting_link(std::unique_ptr<Rhp::net::link> inner) : link_decorator(std::move(inner)) { ++g_links; }

    void send(Rhp::utils::byte_buffer bytes) override {
        g_bytes_sent += bytes.size();
        link_decorator::send(std::move(bytes));
    }
    [[nodiscard]] std::string peer() const override { return "metered:" + inner().peer(); }
};

// The transport policy: a name, whether it crosses a network, listen() and dial(). Checked by
// Rhp::net::transport where the config names it. `network` decides the TLS rules: true for anything
// another machine can reach (a game network's sockets, a relay), false for in-process, IPC or a cable.
struct transport {
    static constexpr std::string_view name = "metered";
    static constexpr bool network = false; // it wraps the in-process loopback transport

    static Rhp::result<std::unique_ptr<Rhp::net::listener>> listen(Rhp::net::io_context& io, const Rhp::endpoint& ep, Rhp::net::accept_fn on_accept) {
        return Rhp::net::loopback::listen(io, ep, [on_accept = std::move(on_accept)](std::unique_ptr<Rhp::net::link> link) {
            on_accept(std::make_unique<counting_link>(std::move(link)));
        });
    }

    static void dial(Rhp::net::io_context& io, const Rhp::endpoint& ep, Rhp::net::connect_fn on_connect) {
        Rhp::net::loopback::dial(io, ep, [on_connect = std::move(on_connect)](Rhp::result<std::unique_ptr<Rhp::net::link>> link) {
            if (!link) {
                on_connect(std::unexpected{std::move(link).error()});
                return;
            }
            on_connect(std::unique_ptr<Rhp::net::link>{std::make_unique<counting_link>(std::move(*link))});
        });
    }
};

} // namespace metered

using metered_cfg = Rhp::config<>::transport<metered::transport>::logger<Rhp::core::null_logger>;

int main() {
    // The session's key, and a key that signs this run's scripts (the default config runs only signed
    // code from patch and admin sessions).
    auto secret = Rhp::security::key::generate();
    auto signing = Rhp::security::ed25519_secret_key::generate();
    if (!secret || !signing) {
        std::println(stderr, "no OS randomness");
        return 1;
    }
    Rhp::host<metered_cfg> host{Rhp::endpoint::listen("custom_transport", 1), Rhp::security::keyring{{"dev", *secret, Rhp::role::kPatch}},
                                Rhp::security::trusted_signers{{"dev", signing->public_key()}}};
    std::jthread frame_loop{[&host](std::stop_token stop) {
        while (!stop.stop_requested()) {
            host.pump();
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
    }};

    Rhp::client<metered_cfg> client{Rhp::endpoint::dial("custom_transport", 1), Rhp::security::psk_identity{"dev", *secret}, Rhp::security::signing_key{"dev", *signing}};
    auto answer = client.exec<int>("local t = 0 for i = 1, 10 do t = t + i end return t");
    if (!answer) {
        std::println(stderr, "exec failed: {}", answer.error());
        return 1;
    }
    std::println("sum 1..10 = {} over {} metered links, {} bytes sent so far", *answer, metered::g_links.load(), metered::g_bytes_sent.load());
    return *answer == 55 && metered::g_links.load() == 2 ? 0 : 1;
}

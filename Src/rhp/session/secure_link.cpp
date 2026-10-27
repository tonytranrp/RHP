#include <cstddef>
#include <cstdint>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>

#include <rhp/core/error.hpp>
#include <rhp/net/link.hpp>
#include <rhp/security/tls/tls.hpp>
#include <rhp/session/secure_link.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace Rhp::session {

namespace {

// The first byte of every TLS record that starts a handshake (ContentType handshake = 22).
constexpr std::byte kTlsHandshake{0x16};

class secure_link final : public net::link, private net::link_handler {
public:
    enum class mode : std::uint8_t {
        kClient, // TLS, we connected
        kSniff,  // accepted: waiting for the first byte
        kTls,    // accepted: TLS
        kPlain   // accepted: plaintext
    };

    secure_link(std::unique_ptr<net::link> inner, std::unique_ptr<security::tls::engine> engine)
        : inner_(std::move(inner)),
          engine_(std::move(engine)),
          mode_(mode::kClient) {}

    secure_link(std::unique_ptr<net::link> inner, std::shared_ptr<security::tls::context> tls, bool plaintext_ok)
        : inner_(std::move(inner)),
          tls_(std::move(tls)),
          mode_(mode::kSniff),
          plaintext_ok_(plaintext_ok) {}

    void start(net::link_handler& handler) override {
        handler_ = &handler;
        inner_->start(*this);
        if (mode_ == mode::kClient) {
            utils::byte_buffer hello;
            if (auto ok = engine_->start(hello); !ok) {
                fail(std::move(ok).error());
                return;
            }
            inner_->send(std::move(hello));
        }
    }

    void send(utils::byte_buffer bytes) override {
        if (closed_) {
            return;
        }
        if (mode_ == mode::kPlain) {
            inner_->send(std::move(bytes));
            return;
        }
        if (!ready()) {
            held_.append(bytes.view()); // sent once the handshake (or the first byte) decides
            return;
        }
        encrypt(bytes.view());
    }

    void close() noexcept override {
        if (closed_) {
            return;
        }
        closed_ = true;
        if (ready() && mode_ != mode::kPlain) {
            utils::byte_buffer bye;
            engine_->close(bye);
            if (!bye.empty()) {
                try {
                    inner_->send(std::move(bye));
                } catch (...) { // out of memory: the peer misses the close_notify
                }
            }
        }
        inner_->close();
    }

    [[nodiscard]] std::string peer() const override { return inner_->peer(); }
    [[nodiscard]] bool loopback() const noexcept override { return inner_->loopback(); }
    [[nodiscard]] bool encrypted() const noexcept override { return mode_ != mode::kPlain && mode_ != mode::kSniff; }
    [[nodiscard]] std::span<const std::byte> channel_binding() const noexcept override {
        return binding_ ? std::span<const std::byte>{*binding_} : std::span<const std::byte>{};
    }

private:
    [[nodiscard]] bool ready() const noexcept { return mode_ == mode::kPlain || (engine_ != nullptr && engine_->established() && binding_.has_value()); }

    // net::link_handler (the inner link)
    void on_bytes(utils::bytes_view data) override {
        if (closed_ || data.empty()) {
            return;
        }
        if (mode_ == mode::kSniff && !decide(data.front())) {
            return;
        }
        if (mode_ == mode::kPlain) {
            handler_->on_bytes(data);
            return;
        }
        const bool was_ready = ready();
        utils::byte_buffer plain;
        utils::byte_buffer reply;
        auto ok = engine_->receive(data, plain, reply);
        if (!reply.empty()) {
            inner_->send(std::move(reply));
        }
        if (!ok) {
            // What arrived with the close_notify or alert still counts (a goodbye, a refusal).
            if (!plain.empty() && !closed_) {
                handler_->on_bytes(plain.view());
            }
            fail(std::move(ok).error());
            return;
        }
        bool became_ready = false;
        if (!was_ready && engine_->established()) {
            auto b = engine_->binding();
            if (!b) {
                fail(std::move(b).error());
                return;
            }
            binding_ = *b;
            became_ready = true;
            if (!held_.empty()) {
                utils::byte_buffer held = std::exchange(held_, {});
                encrypt(held.view());
            }
        }
        if ((!plain.empty() || became_ready) && !closed_) {
            handler_->on_bytes(plain.view()); // empty: "ready" (the binding is known now)
        }
    }

    void on_closed(const error& why) override { handler_->on_closed(failure_ ? *failure_ : why); }

    // The accepted peer's first byte: TLS or plaintext. False when the link is refused.
    bool decide(std::byte first) {
        if (first == kTlsHandshake) {
            if (tls_ == nullptr) {
                fail(make_error(errc::kForbidden, "the peer started TLS, which this side doesn't have", inner_->peer()));
                return false;
            }
            auto e = tls_->make_engine();
            if (!e) {
                fail(std::move(e).error());
                return false;
            }
            engine_ = std::move(*e);
            mode_ = mode::kTls;
            return true;
        }
        if (!plaintext_ok_) {
            fail(make_error(errc::kForbidden, "plaintext connection refused: this endpoint requires TLS", inner_->peer()));
            return false;
        }
        mode_ = mode::kPlain;
        if (!held_.empty()) {
            inner_->send(std::exchange(held_, {}));
        }
        return true;
    }

    void encrypt(utils::bytes_view plain) {
        utils::byte_buffer out;
        if (auto ok = engine_->send(plain, out); !ok) {
            fail(std::move(ok).error());
            return;
        }
        inner_->send(std::move(out));
    }

    // Closes the inner link; its on_closed then reports `why`.
    void fail(error why) {
        if (closed_) {
            return;
        }
        if (why.where.empty()) {
            why.where = inner_->peer();
        }
        failure_ = std::move(why);
        closed_ = true;
        inner_->close();
    }

    std::unique_ptr<net::link> inner_; // destroying it aborts it: no callbacks after this
    std::unique_ptr<security::tls::engine> engine_;
    std::shared_ptr<security::tls::context> tls_;
    mode mode_;
    bool plaintext_ok_ = false;
    net::link_handler* handler_ = nullptr;
    utils::byte_buffer held_;
    std::optional<security::tls::channel_binding> binding_;
    std::optional<error> failure_;
    bool closed_ = false;
};

} // namespace

result<channel_policy> channel_policy::make(const net::endpoint& ep, bool network_transport, const security::tls::backend_ops& backend,
                                            const security::tls::settings& settings) {
    channel_policy p;
    p.transport_ep_ = ep;
    p.backend_ = backend.name;
    const bool required = ep.tls == net::tls_mode::kRequire;
    const bool remote = network_transport && !ep.insecure_lan && !net::is_loopback_host(ep.host);
    const bool dialing = ep.direction == net::endpoint::mode::kDial;
    p.dialing_ = dialing;
    p.plaintext_from_loopback_ = !required;
    p.plaintext_from_anyone_ = !required && (ep.insecure_lan || !network_transport || net::is_loopback_host(ep.host));
    if (required || remote) {
        p.transport_ep_.tls = net::tls_mode::kRequire; // TLS goes on top of what the transport carries
    }
    if (!backend.available()) {
        if (required || remote) {
            return fail(errc::kForbidden,
                        std::format("{} needs TLS, and RHP was built without it (RHP_WITH_TLS=OFF, or config<>::tls<none>); use Rhp::net::insecure_lan for plaintext", ep),
                        "tls");
        }
        return p;
    }
    if (dialing) {
        p.dial_tls_ = required || remote;
        if (!p.dial_tls_) {
            return p;
        }
        security::tls::settings client = settings;
        // With a CA, check the name too: by default the one dialed (unless it is an IP address).
        const bool ip = ep.host.find_first_not_of("0123456789.:[]abcdefABCDEF") == std::string::npos &&
                        ep.host.find_first_of("0123456789") != std::string::npos;
        if (!client.ca_pem.empty() && client.server_name.empty() && !ip) {
            client.server_name = ep.host;
        }
        auto ctx = backend.client(client);
        if (!ctx) {
            return std::unexpected{std::move(ctx).error()};
        }
        p.context_ = std::move(*ctx);
        return p;
    }
    auto ctx = backend.server(settings);
    if (!ctx) {
        if (required || remote) {
            return std::unexpected{std::move(ctx).error()};
        }
        return p; // a loopback listener works without TLS
    }
    p.context_ = std::move(*ctx);
    return p;
}

result<std::unique_ptr<net::link>> channel_policy::wrap(std::unique_ptr<net::link> link) const {
    if (dialing_) {
        if (!dial_tls_) {
            return link;
        }
        auto engine = context_->make_engine();
        if (!engine) {
            return std::unexpected{std::move(engine).error()};
        }
        return tls_client(std::move(link), std::move(*engine));
    }
    const bool plaintext_ok = plaintext_from_anyone_ || (plaintext_from_loopback_ && link->loopback());
    if (context_ == nullptr && plaintext_ok) {
        return link;
    }
    return tls_server(std::move(link), context_, plaintext_ok);
}

result<std::unique_ptr<net::link>> channel_policy::wrap(result<std::unique_ptr<net::link>> dialed) const {
    if (!dialed) {
        return dialed;
    }
    return wrap(std::move(*dialed));
}

std::unique_ptr<net::link> tls_client(std::unique_ptr<net::link> inner, std::unique_ptr<security::tls::engine> engine) {
    return std::make_unique<secure_link>(std::move(inner), std::move(engine));
}

std::unique_ptr<net::link> tls_server(std::unique_ptr<net::link> inner, std::shared_ptr<security::tls::context> tls, bool plaintext_ok) {
    return std::make_unique<secure_link>(std::move(inner), std::move(tls), plaintext_ok);
}

} // namespace Rhp::session

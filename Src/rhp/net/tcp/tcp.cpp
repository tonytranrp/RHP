#include <format>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <asio/connect.hpp>
#include <asio/error.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/tcp.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/net/detail/asio_support.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/net/tcp/tcp.hpp>
#include <rhp/platform/os.hpp>

namespace Rhp::net {

namespace {

using atcp = asio::ip::tcp;
using detail::address_allowed;
using detail::address_text;
using detail::context_of;

[[nodiscard]] std::string describe(const atcp::endpoint& ep) {
    return address_text(ep.address(), ep.port());
}

// ---- link ----------------------------------------------------------------------------------------

struct tcp_traits {
    static error read_error(const std::error_code& ec, const std::string& peer) {
        return make_error(errc::kTransport, ec == asio::error::eof ? std::string{"the peer closed the connection"} : ec.message(), peer);
    }
    // close() shuts the connection down first (the destructor's abort doesn't).
    static void before_close(atcp::socket& socket) noexcept {
        std::error_code ignored;
        socket.shutdown(atcp::socket::shutdown_both, ignored);
    }
};

using tcp_link = detail::stream_link<atcp::socket, tcp_traits>;

[[nodiscard]] std::unique_ptr<link> make_link(atcp::socket socket) {
    std::error_code ec;
    socket.set_option(atcp::no_delay{true}, ec);
    const auto remote = socket.remote_endpoint(ec);
    std::string name = ec ? std::string{"tcp:?"} : describe(remote);
    const bool on_this_machine = !ec && detail::is_loopback(remote.address());
    return std::make_unique<tcp_link>(std::move(socket), std::move(name), on_this_machine);
}

// ---- addresses -------------------------------------------------------------------------------------

[[nodiscard]] std::unexpected<error> forbidden(const endpoint& ep) {
    return fail(errc::kForbidden,
                std::format("{} is not a loopback address: plain TCP there needs Rhp::net::insecure_lan on the endpoint (hosts and clients add TLS themselves)", ep.host),
                "net.tcp");
}

// Synchronous resolution for listen (binding happens at construction, errors return at once).
[[nodiscard]] result<std::vector<atcp::endpoint>> resolve_now(asio::io_context& ctx, const endpoint& ep) {
    std::error_code ec;
    const auto literal = asio::ip::make_address(ep.host, ec);
    if (!ec) {
        return std::vector<atcp::endpoint>{atcp::endpoint{literal, ep.port}};
    }
    atcp::resolver resolver{ctx};
    const auto found = resolver.resolve(ep.host, std::to_string(ep.port), atcp::resolver::passive | atcp::resolver::numeric_service, ec);
    if (ec || found.empty()) {
        return fail(errc::kTransport, std::format("can't resolve {}: {}", ep.host, ec ? ec.message() : "no addresses"), "net.tcp");
    }
    std::vector<atcp::endpoint> out;
    for (const auto& entry : found) {
        out.push_back(entry.endpoint());
    }
    return out;
}

// ---- listener ------------------------------------------------------------------------------------

struct listener_state : std::enable_shared_from_this<listener_state> {
    explicit listener_state(asio::io_context& ctx) : acceptor(ctx) {}

    atcp::acceptor acceptor;
    accept_fn on_accept;
    bool open = true;

    void accept() {
        acceptor.async_accept([self = shared_from_this()](const std::error_code& ec, atcp::socket socket) {
            if (!self->open) {
                return;
            }
            if (!ec) {
                self->on_accept(make_link(std::move(socket)));
            }
            // A failed accept (the peer reset before we got to it, out of descriptors) doesn't stop listening.
            if (self->open) {
                self->accept();
            }
        });
    }
};

class tcp_listener final : public listener {
public:
    explicit tcp_listener(std::shared_ptr<listener_state> state) : state_(std::move(state)) {}

    ~tcp_listener() override {
        state_->open = false;
        std::error_code ignored;
        state_->acceptor.close(ignored);
    }

    tcp_listener(const tcp_listener&) = delete;
    tcp_listener& operator=(const tcp_listener&) = delete;

    [[nodiscard]] unsigned short port() const noexcept override {
        std::error_code ec;
        const auto local = state_->acceptor.local_endpoint(ec);
        return ec ? static_cast<unsigned short>(0) : local.port();
    }

private:
    std::shared_ptr<listener_state> state_;
};

// ---- dial ------------------------------------------------------------------------------------------

// Resolves, keeps the addresses the rules allow, connects to the first that answers.
struct dial_state : std::enable_shared_from_this<dial_state> {
    dial_state(asio::io_context& ctx, endpoint ep, connect_fn fn) : resolver(ctx), socket(ctx), target(std::move(ep)), on_connect(std::move(fn)) {}

    atcp::resolver resolver;
    atcp::socket socket;
    endpoint target;
    connect_fn on_connect;

    void start() {
        resolver.async_resolve(target.host, std::to_string(target.port), atcp::resolver::numeric_service,
                               [self = shared_from_this()](const std::error_code& ec, const atcp::resolver::results_type& found) { self->resolved(ec, found); });
    }

    void resolved(const std::error_code& ec, const atcp::resolver::results_type& found) {
        if (ec) {
            fail_with(make_error(errc::kTransport, std::format("can't resolve {}: {}", target.host, ec.message()), "net.tcp"));
            return;
        }
        std::vector<atcp::endpoint> allowed;
        for (const auto& entry : found) {
            if (address_allowed(target, entry.endpoint().address())) {
                allowed.push_back(entry.endpoint());
            }
        }
        if (allowed.empty()) {
            fail_with(forbidden(target).error());
            return;
        }
        asio::async_connect(socket, allowed, [self = shared_from_this()](const std::error_code& connect_ec, const atcp::endpoint&) { self->connected(connect_ec); });
    }

    void connected(const std::error_code& ec) {
        if (ec) {
            fail_with(make_error(errc::kTransport, std::format("can't connect to {}:{}: {}", target.host, target.port, ec.message()), "net.tcp"));
            return;
        }
        auto fn = std::move(on_connect);
        fn(make_link(std::move(socket)));
    }

    void fail_with(error err) {
        auto fn = std::move(on_connect);
        fn(std::unexpected{std::move(err)});
    }
};

} // namespace

result<std::unique_ptr<listener>> tcp::listen(io_context& io, const endpoint& ep, accept_fn on_accept) {
    auto& ctx = context_of(io);
    auto addresses = resolve_now(ctx, ep);
    if (!addresses) {
        return std::unexpected{std::move(addresses).error()};
    }
    // Bind the first address the rules allow.
    const atcp::endpoint* chosen = nullptr;
    for (const auto& a : *addresses) {
        if (address_allowed(ep, a.address())) {
            chosen = &a;
            break;
        }
    }
    if (chosen == nullptr) {
        return forbidden(ep);
    }

    auto state = std::make_shared<listener_state>(ctx);
    state->on_accept = std::move(on_accept);
    std::error_code ec;
    state->acceptor.open(chosen->protocol(), ec);
    // SO_REUSEADDR lets a restarted host rebind at once on POSIX; on Windows it would let another
    // process steal the port, so Windows keeps the default (exclusive) binding.
    if (!ec && platform::kOs != platform::os_kind::kWindows) {
        state->acceptor.set_option(atcp::acceptor::reuse_address{true}, ec);
    }
    if (!ec) {
        state->acceptor.bind(*chosen, ec);
    }
    if (!ec) {
        state->acceptor.listen(asio::socket_base::max_listen_connections, ec);
    }
    if (ec) {
        return fail(errc::kTransport, std::format("can't listen on {}: {}", describe(*chosen), ec.message()), "net.tcp");
    }
    state->accept();
    return std::unique_ptr<listener>{std::make_unique<tcp_listener>(std::move(state))};
}

void tcp::dial(io_context& io, const endpoint& ep, connect_fn on_connect) {
    std::make_shared<dial_state>(context_of(io), ep, std::move(on_connect))->start();
}

} // namespace Rhp::net

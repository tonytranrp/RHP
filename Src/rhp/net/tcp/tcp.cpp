#include <array>
#include <cstddef>
#include <deque>
#include <format>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <asio/connect.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/post.hpp>
#include <asio/write.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/net/tcp/tcp.hpp>
#include <rhp/platform/os.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace Rhp::net {

namespace {

using atcp = asio::ip::tcp;

[[nodiscard]] asio::io_context& context_of(io_context& io) {
    return *static_cast<asio::io_context*>(io.native_handle());
}

[[nodiscard]] bool is_loopback(const asio::ip::address& a) noexcept {
    if (a.is_v4()) {
        return a.to_v4().is_loopback();
    }
    const auto v6 = a.to_v6();
    return v6.is_loopback() || (v6.is_v4_mapped() && asio::ip::make_address_v4(asio::ip::v4_mapped, v6).is_loopback());
}

[[nodiscard]] std::string describe(const atcp::endpoint& ep) {
    const auto addr = ep.address();
    return addr.is_v6() ? std::format("[{}]:{}", addr.to_string(), ep.port()) : std::format("{}:{}", addr.to_string(), ep.port());
}

[[nodiscard]] error transport_error(const std::error_code& ec, std::string where) {
    return make_error(errc::kTransport, ec.message(), std::move(where));
}

// ---- link ----------------------------------------------------------------------------------------

// Shared with in-flight Asio operations, so a completion after the link died finds `closed`.
struct link_state : std::enable_shared_from_this<link_state> {
    explicit link_state(atcp::socket s) : socket(std::move(s)) {}

    atcp::socket socket;
    std::string peer;
    link_handler* handler = nullptr;
    std::array<std::byte, 64 * 1024> buffer{};
    std::deque<utils::byte_buffer> writes;
    bool writing = false;
    bool closing = false; // close() asked: finish once the queue is written
    bool closed = false;

    void read() {
        socket.async_read_some(asio::buffer(buffer), [self = shared_from_this()](const std::error_code& ec, std::size_t n) {
            if (self->closed) {
                return;
            }
            if (ec) {
                self->finish(ec == asio::error::eof ? make_error(errc::kTransport, "the peer closed the connection", self->peer)
                                                    : transport_error(ec, self->peer));
                return;
            }
            if (self->handler != nullptr) {
                self->handler->on_bytes(utils::bytes_view{self->buffer.data(), n});
            }
            if (!self->closed) {
                self->read();
            }
        });
    }

    void write_next() {
        writing = true;
        const utils::bytes_view front = writes.front().view();
        asio::async_write(socket, asio::buffer(front.data(), front.size()), [self = shared_from_this()](const std::error_code& ec, std::size_t) {
            self->writing = false;
            if (self->closed) {
                return;
            }
            if (ec) {
                self->finish(transport_error(ec, self->peer));
                return;
            }
            self->writes.pop_front();
            if (!self->writes.empty()) {
                self->write_next();
            } else if (self->closing) {
                self->finish({});
            }
        });
    }

    // Closes the socket and reports `why` once, from a posted handler (never re-entrantly).
    void finish(error why) {
        if (closed) {
            return;
        }
        closed = true;
        std::error_code ignored;
        socket.shutdown(atcp::socket::shutdown_both, ignored);
        socket.close(ignored);
        // `writes` is kept: an async_write in flight may still read its front buffer (the state
        // lives until that completion runs, and frees it then).
        asio::post(socket.get_executor(), [self = shared_from_this(), why = std::move(why)] {
            if (link_handler* h = std::exchange(self->handler, nullptr)) {
                h->on_closed(why);
            }
        });
    }
};

class tcp_link final : public link {
public:
    explicit tcp_link(atcp::socket socket) : state_(std::make_shared<link_state>(std::move(socket))) {
        std::error_code ec;
        state_->socket.set_option(atcp::no_delay{true}, ec);
        const auto remote = state_->socket.remote_endpoint(ec);
        state_->peer = ec ? std::string{"tcp:?"} : describe(remote);
        loopback_ = !ec && is_loopback(remote.address());
    }

    ~tcp_link() override {
        state_->handler = nullptr;
        if (state_->closed) {
            return;
        }
        if (state_->closing && state_->writing) {
            // close() asked for the queue to be written first (a session's last error frame):
            // the pending write completes on the shared state, which closes the socket after it.
            return;
        }
        state_->closed = true;
        std::error_code ignored;
        state_->socket.close(ignored);
    }

    tcp_link(const tcp_link&) = delete;
    tcp_link& operator=(const tcp_link&) = delete;

    void start(link_handler& handler) override {
        state_->handler = &handler;
        if (!state_->closed) {
            state_->read();
        }
    }

    void send(utils::byte_buffer bytes) override {
        if (state_->closed || state_->closing || bytes.empty()) {
            return;
        }
        state_->writes.push_back(std::move(bytes));
        if (!state_->writing) {
            state_->write_next();
        }
    }

    void close() noexcept override {
        try {
            if (state_->closed || state_->closing) {
                return;
            }
            state_->closing = true;
            if (!state_->writing) {
                state_->finish({});
            }
        } catch (...) { // finish() failed to post: the destructor still closes the socket
        }
    }

    [[nodiscard]] std::string peer() const override { return state_->peer; }
    [[nodiscard]] bool loopback() const noexcept override { return loopback_; }

private:
    std::shared_ptr<link_state> state_;
    bool loopback_ = false;
};

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
                self->on_accept(std::make_unique<tcp_link>(std::move(socket)));
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

struct dial_state : std::enable_shared_from_this<dial_state> {
    explicit dial_state(asio::io_context& ctx) : resolver(ctx), socket(ctx) {}

    atcp::resolver resolver;
    atcp::socket socket;
    endpoint target;
    connect_fn on_connect;

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
        if (ep.insecure_lan || ep.tls == tls_mode::kRequire || is_loopback(a.address())) {
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
    auto state = std::make_shared<dial_state>(context_of(io));
    state->target = ep;
    state->on_connect = std::move(on_connect);
    state->resolver.async_resolve(ep.host, std::to_string(ep.port), atcp::resolver::numeric_service,
                                  [state](const std::error_code& ec, const atcp::resolver::results_type& found) {
                                      if (ec) {
                                          state->fail_with(make_error(errc::kTransport, std::format("can't resolve {}: {}", state->target.host, ec.message()), "net.tcp"));
                                          return;
                                      }
                                      std::vector<atcp::endpoint> allowed;
                                      for (const auto& entry : found) {
                                          if (state->target.insecure_lan || state->target.tls == tls_mode::kRequire || is_loopback(entry.endpoint().address())) {
                                              allowed.push_back(entry.endpoint());
                                          }
                                      }
                                      if (allowed.empty()) {
                                          state->fail_with(forbidden(state->target).error());
                                          return;
                                      }
                                      asio::async_connect(state->socket, allowed, [state](const std::error_code& connect_ec, const atcp::endpoint&) {
                                          if (connect_ec) {
                                              state->fail_with(make_error(errc::kTransport,
                                                                          std::format("can't connect to {}:{}: {}", state->target.host, state->target.port, connect_ec.message()),
                                                                          "net.tcp"));
                                              return;
                                          }
                                          auto fn = std::move(state->on_connect);
                                          fn(std::unique_ptr<link>{std::make_unique<tcp_link>(std::move(state->socket))});
                                      });
                                  });
}

} // namespace Rhp::net

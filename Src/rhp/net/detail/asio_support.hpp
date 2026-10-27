#pragma once

// PRIVATE to Rhp::net's Asio backends (the rhp_net_asio translation units): helpers the TCP, IPC,
// reliable-UDP and multicast DNS backends share. It includes Asio, so it is not in the module's
// installed header set and no public header may include it.

#include <array>
#include <concepts>
#include <cstddef>
#include <deque>
#include <format>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/address.hpp>
#include <asio/post.hpp>
#include <asio/write.hpp>

#include <rhp/core/error.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace Rhp::net::detail {

[[nodiscard]] inline asio::io_context& context_of(io_context& io) {
    return *static_cast<asio::io_context*>(io.native_handle());
}

// 127.0.0.0/8, ::1 and their v4-mapped forms.
[[nodiscard]] inline bool is_loopback(const asio::ip::address& address) noexcept {
    if (address.is_v4()) {
        return address.to_v4().is_loopback();
    }
    const auto v6 = address.to_v6();
    return v6.is_loopback() || (v6.is_v4_mapped() && asio::ip::make_address_v4(asio::ip::v4_mapped, v6).is_loopback());
}

// "127.0.0.1:7777" or "[::1]:7777".
[[nodiscard]] inline std::string address_text(const asio::ip::address& address, unsigned short port) {
    return address.is_v6() ? std::format("[{}]:{}", address.to_string(), port) : std::format("{}:{}", address.to_string(), port);
}

// The plaintext rule of the network transports: an address off loopback only with insecure_lan, or
// when the endpoint asks for TLS (hosts and clients layer it on top).
[[nodiscard]] inline bool address_allowed(const endpoint& ep, const asio::ip::address& address) noexcept {
    return ep.insecure_lan || ep.tls == tls_mode::kRequire || is_loopback(address);
}

// ---- stream links --------------------------------------------------------------------------------

// A connected Asio stream: a TCP socket, an AF_UNIX socket, a Windows pipe handle.
template <class Socket>
concept stream_socket = requires(Socket& socket, std::error_code& ec) {
    socket.get_executor();
    socket.close(ec);
};

// What one stream transport does its own way: the error a failed read reports, and what happens to
// the socket right before close() closes it (TCP shuts it down).
template <class Traits, class Socket>
concept stream_traits = requires(Socket& socket, const std::error_code& ec, const std::string& peer) {
    { Traits::read_error(ec, peer) } -> std::same_as<error>;
    { Traits::before_close(socket) } noexcept;
};

// Shared with in-flight Asio operations, so a completion after the link died finds `closed`.
template <stream_socket Socket, stream_traits<Socket> Traits>
struct stream_state : std::enable_shared_from_this<stream_state<Socket, Traits>> {
    stream_state(Socket s, std::string name) : socket(std::move(s)), peer(std::move(name)) {}

    Socket socket;
    std::string peer;
    link_handler* handler = nullptr;
    std::array<std::byte, 64 * 1024> buffer{};
    std::deque<utils::byte_buffer> writes;
    // The front buffers one gathered write sends: frames queued behind a write in flight go out
    // together in the next one (one system call instead of one each).
    std::vector<asio::const_buffer> gather;
    bool writing = false;
    bool closing = false; // close() asked: finish once the queue is written
    bool closed = false;

    void read() {
        socket.async_read_some(asio::buffer(buffer), [self = this->shared_from_this()](const std::error_code& ec, std::size_t n) {
            if (self->closed) {
                return;
            }
            if (ec) {
                self->finish(Traits::read_error(ec, self->peer));
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
        constexpr std::size_t kMaxGather = 16;
        writing = true;
        gather.clear();
        for (const auto& b : writes) {
            gather.emplace_back(b.view().data(), b.size());
            if (gather.size() == kMaxGather) {
                break;
            }
        }
        asio::async_write(socket, gather, [self = this->shared_from_this()](const std::error_code& ec, std::size_t) {
            self->writing = false;
            if (self->closed) {
                return;
            }
            if (ec) {
                self->finish(make_error(errc::kTransport, ec.message(), self->peer));
                return;
            }
            self->writes.erase(self->writes.begin(), self->writes.begin() + static_cast<std::ptrdiff_t>(self->gather.size()));
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
        Traits::before_close(socket);
        std::error_code ignored;
        socket.close(ignored);
        // `writes` is kept: an async_write in flight may still read its front buffer (the state
        // lives until that completion runs, and frees it then).
        asio::post(socket.get_executor(), [self = this->shared_from_this(), why = std::move(why)] {
            if (link_handler* h = std::exchange(self->handler, nullptr)) {
                h->on_closed(why);
            }
        });
    }
};

// A link over one connected stream. `name` is what peer() reports; `on_this_machine` is loopback().
template <stream_socket Socket, stream_traits<Socket> Traits>
class stream_link final : public link {
public:
    stream_link(Socket s, std::string name, bool on_this_machine)
        : state_(std::make_shared<stream_state<Socket, Traits>>(std::move(s), std::move(name))), loopback_(on_this_machine) {}

    ~stream_link() override {
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

    stream_link(const stream_link&) = delete;
    stream_link& operator=(const stream_link&) = delete;

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
    std::shared_ptr<stream_state<Socket, Traits>> state_;
    bool loopback_ = false;
};

} // namespace Rhp::net::detail

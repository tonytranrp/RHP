#pragma once

#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <utility>

#include <rhp/core/error.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace Rhp::net {

// Receives what a link reads. Called on the link's io_context thread, never after the link was
// closed or destroyed.
class link_handler {
public:
    // May be empty: the link became ready (a TLS link finished its handshake, channel_binding() is set).
    virtual void on_bytes(utils::bytes_view data) = 0;
    // The peer closed, the link failed, or close() finished. Called at most once.
    virtual void on_closed(const error& why) = 0;

protected:
    link_handler() = default;
    ~link_handler() = default;
    link_handler(const link_handler&) = default;
    link_handler& operator=(const link_handler&) = default;
};

// A connected, ordered, reliable byte stream (a TCP socket, an in-memory loopback pipe, ...).
// Every member is called on the link's io_context thread. Destroying a link aborts it without
// calling the handler.
class link {
public:
    virtual ~link() = default;

    // Starts reading into `handler` (which must outlive the link or its close()).
    virtual void start(link_handler& handler) = 0;
    // Queues bytes; they are written in order.
    virtual void send(utils::byte_buffer bytes) = 0;
    // Writes what is queued, then closes; the handler gets on_closed once.
    virtual void close() noexcept = 0;
    // "127.0.0.1:51234", "loopback:game"
    [[nodiscard]] virtual std::string peer() const = 0;
    // True when the peer is on this machine (a loopback address, an in-process pipe): such a peer
    // may speak plaintext to a host that otherwise wants TLS.
    [[nodiscard]] virtual bool loopback() const noexcept { return false; }
    // True when the stream is encrypted and integrity-protected (TLS): frames then skip their CRC.
    [[nodiscard]] virtual bool encrypted() const noexcept { return false; }
    // Bytes both ends of this connection, and only they, can compute (RFC 9266 tls-exporter under
    // TLS); empty without. Valid once the first bytes arrived. Authenticators mix it into their
    // proofs, so a relay that terminates the channel on both sides can't pass the handshake.
    [[nodiscard]] virtual std::span<const std::byte> channel_binding() const noexcept { return {}; }

protected:
    link() = default;
    link(const link&) = default;
    link& operator=(const link&) = default;
};

// A link that wraps another (metering, logging, fault injection). It forwards everything, including
// the properties the session's security depends on (loopback, encrypted, channel_binding); override
// only what you change. A wrapper that derives from `link` directly must forward those three itself,
// or the session sees a plaintext, remote, unbound stream.
class link_decorator : public link {
public:
    explicit link_decorator(std::unique_ptr<link> inner) noexcept : inner_(std::move(inner)) {}

    void start(link_handler& handler) override { inner_->start(handler); }
    void send(utils::byte_buffer bytes) override { inner_->send(std::move(bytes)); }
    void close() noexcept override { inner_->close(); }
    [[nodiscard]] std::string peer() const override { return inner_->peer(); }
    [[nodiscard]] bool loopback() const noexcept override { return inner_->loopback(); }
    [[nodiscard]] bool encrypted() const noexcept override { return inner_->encrypted(); }
    [[nodiscard]] std::span<const std::byte> channel_binding() const noexcept override { return inner_->channel_binding(); }

protected:
    [[nodiscard]] link& inner() noexcept { return *inner_; }
    [[nodiscard]] const link& inner() const noexcept { return *inner_; }

private:
    std::unique_ptr<link> inner_;
};

// Accepts links for a listening endpoint until destroyed.
class listener {
public:
    virtual ~listener() = default;

    // The bound port (useful after listening on port 0); 0 for transports without ports.
    [[nodiscard]] virtual unsigned short port() const noexcept = 0;

protected:
    listener() = default;
    listener(const listener&) = default;
    listener& operator=(const listener&) = default;
};

} // namespace Rhp::net

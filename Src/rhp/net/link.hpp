#pragma once

#include <memory>
#include <string>

#include <rhp/core/error.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace Rhp::net {

// Receives what a link reads. Called on the link's io_context thread, never after the link was
// closed or destroyed.
class link_handler {
public:
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

protected:
    link() = default;
    link(const link&) = default;
    link& operator=(const link&) = default;
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

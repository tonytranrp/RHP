#pragma once

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <rhp/net/detail/http.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/utils/byte_buffer.hpp>

// One HTTP/1.1 exchange over an already secured link, for the host's HTTP frontend. Routing,
// authentication and identities live in the host; this file knows only bytes and headers.
namespace Rhp::net::detail {

struct http_request {
    std::string method;
    std::string target;
    http_head head;
    utils::byte_buffer body;
    std::string peer;
    bool encrypted = false;
};

struct http_response {
    unsigned status = 200;
    std::string content_type = "application/msgpack";
    std::vector<std::pair<std::string, std::string>> headers; // extra fields
    utils::byte_buffer body;
};

using http_reply = std::function<void(http_response)>;
using http_handler = std::function<void(http_request, http_reply)>;

struct http_connection_options {
    std::size_t max_body = 0;                 // request and response bodies
    std::chrono::milliseconds head_timeout{}; // the whole request must arrive by then (0 = no limit)
};

// One request per connection, explicit Content-Length, no pipelining, `Expect: 100-continue`
// answered. The reply closes the connection. `closed` runs once when the link is gone (also
// before a pending reply was sent).
class http_connection {
public:
    http_connection(io_context& io, std::unique_ptr<link> stream, http_connection_options options, http_handler handle, std::function<void()> closed);
    ~http_connection();

    http_connection(const http_connection&) = delete;
    http_connection& operator=(const http_connection&) = delete;

    void start();

private:
    struct impl;
    std::shared_ptr<impl> impl_;
};

} // namespace Rhp::net::detail

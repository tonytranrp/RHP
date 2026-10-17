#include <cstdint>
#include <format>
#include <utility>

#include <rhp/net/detail/http_connection.hpp>

namespace Rhp::net::detail {

struct http_connection::impl final : link_handler, std::enable_shared_from_this<impl> {
    impl(io_context& io, std::unique_ptr<link> connection, http_connection_options o) : stream(std::move(connection)), timer(io), options(o) {}

    std::unique_ptr<link> stream;
    io_context::timer timer;
    http_connection_options options;
    http_handler handle;
    std::function<void()> closed;
    std::string input;
    bool continued = false;  // "100 Continue" sent
    bool dispatched = false; // the request went to the handler
    bool replied = false;

    void reply(http_response response) {
        if (std::exchange(replied, true)) {
            return;
        }
        timer.cancel();
        if (response.body.size() > options.max_body) {
            response = {500, "text/plain", {}, {}};
            response.body.append("response exceeds the host's frame limit");
        }
        std::string head = std::format("HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n", response.status,
                                       reason_phrase(response.status), response.content_type, response.body.size());
        for (const auto& [name, value] : response.headers) {
            head += std::format("{}: {}\r\n", name, value);
        }
        head += "\r\n";
        utils::byte_buffer bytes;
        bytes.reserve(head.size() + response.body.size());
        bytes.append(head);
        bytes.append(response.body.view());
        stream->send(std::move(bytes));
        stream->close();
    }

    void refuse(unsigned status) { reply({status, "text/plain", {}, {}}); }

    void on_bytes(utils::bytes_view bytes) override {
        const auto keep_alive = shared_from_this();
        if (dispatched || replied || bytes.empty()) {
            return;
        }
        // Headers (kMaxHttpHead) plus the body may be buffered, nothing more (saturating on 32-bit).
        const std::size_t room = options.max_body > SIZE_MAX - kMaxHttpHead ? SIZE_MAX : kMaxHttpHead + options.max_body;
        if (bytes.size() > room || input.size() > room - bytes.size()) {
            refuse(413);
            return;
        }
        input.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        auto parsed = parse_http_head(input, options.max_body);
        if (!parsed) {
            refuse(parsed.error().code == errc::kLimitExceeded ? 413 : 400);
            return;
        }
        if (!*parsed) {
            return;
        }
        auto& head = **parsed;
        const auto first = head.first_line.find(' ');
        const auto last = head.first_line.rfind(' ');
        if (first == std::string::npos || last == first || head.first_line.substr(last + 1) != "HTTP/1.1" || head.header("host").empty()) {
            refuse(400);
            return;
        }
        const auto complete = head.bytes + head.content_length;
        if (input.size() < complete) {
            if (!continued && http_token(head.header("expect"), "100-continue")) {
                continued = true; // curl waits a second for this before sending a body
                utils::byte_buffer go;
                go.append(std::string_view{"HTTP/1.1 100 Continue\r\n\r\n"});
                stream->send(std::move(go));
            }
            return;
        }
        if (input.size() != complete) {
            refuse(400); // pipelined or trailing bytes
            return;
        }
        http_request request;
        request.method = head.first_line.substr(0, first);
        request.target = head.first_line.substr(first + 1, last - first - 1);
        request.body.append(std::string_view{input}.substr(head.bytes, head.content_length));
        request.head = std::move(head);
        request.peer = stream->peer();
        request.encrypted = stream->encrypted();
        const auto binding = stream->channel_binding();
        request.binding.assign(binding.begin(), binding.end());
        input.clear();
        dispatched = true;
        timer.cancel();
        handle(std::move(request), [weak = weak_from_this()](http_response response) {
            if (auto self = weak.lock()) {
                self->reply(std::move(response));
            }
        });
    }

    void on_closed(const error&) override {
        const auto keep_alive = shared_from_this();
        timer.cancel();
        replied = true;
        if (auto fn = std::exchange(closed, nullptr)) {
            fn();
        }
    }
};

http_connection::http_connection(io_context& io, std::unique_ptr<link> stream, http_connection_options options, http_handler handle, std::function<void()> closed)
    : impl_(std::make_shared<impl>(io, std::move(stream), options)) {
    impl_->handle = std::move(handle);
    impl_->closed = std::move(closed);
}

http_connection::~http_connection() {
    impl_->closed = nullptr;
    impl_->handle = nullptr;
}

void http_connection::start() {
    impl_->stream->start(*impl_);
    if (impl_->options.head_timeout.count() != 0) {
        impl_->timer.start(impl_->options.head_timeout, [weak = std::weak_ptr<impl>{impl_}] {
            if (auto self = weak.lock(); self && !self->dispatched) {
                self->refuse(408);
            }
        });
    }
}

} // namespace Rhp::net::detail

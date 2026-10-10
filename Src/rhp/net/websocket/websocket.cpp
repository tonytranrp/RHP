#include <algorithm>
#include <chrono>
#include <deque>
#include <format>
#include <optional>
#include <utility>
#include <vector>

#include <rhp/net/detail/http.hpp>
#include <rhp/net/tcp/tcp.hpp>
#include <rhp/net/websocket/detail/protocol.hpp>
#include <rhp/net/websocket/websocket.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/utils/base64.hpp>

namespace Rhp::net {

namespace {

namespace ws = detail::ws;

constexpr const char* kWhere = "net.websocket";
constexpr std::chrono::seconds kCloseGrace{5};

// One WebSocket connection over an owned TCP link. `Self` fixes which side we are at compile time:
// the client masks what it sends and opens with the upgrade request; the server answers it.
//
//   kUpgrading ── upgrade done ──> kOpen ── close() ──> kClosing ── peer Close / grace timer ──> kDone
//        └────────────── a protocol error, a peer Close, or close() before kOpen ─────────────────┘
template <ws::role Self>
class websocket_state final : public link_handler, public std::enable_shared_from_this<websocket_state<Self>> {
public:
    websocket_state(io_context& io, std::unique_ptr<link> stream, std::string host)
        : stream_(std::move(stream)), host_(std::move(host)), grace_(io) {}

    // The owning websocket_link is going away: no more callbacks. A link that was closing still
    // flushes its last bytes (TCP drains after close()); anything else is aborted with the stream.
    void detach() noexcept {
        handler_ = nullptr;
        if (phase_ >= phase::kClosing || close_requested_) {
            stream_->close();
        }
    }

    void start(link_handler& handler) {
        handler_ = &handler;
        stream_->start(*this);
        if constexpr (Self == ws::role::kClient) {
            auto nonce = platform::random_array<16>();
            if (!nonce) {
                fail(std::move(nonce).error(), ws::close_code::kProtocolError);
                return;
            }
            key_ = utils::base64_encode(*nonce);
            send_raw(ws::upgrade_request(host_, key_));
        }
    }

    void send(utils::byte_buffer bytes) {
        if (bytes.empty() || phase_ >= phase::kClosing || close_requested_) {
            return;
        }
        if (phase_ == phase::kOpen) {
            send_data(bytes.view());
            return;
        }
        if (bytes.size() > ws::kMaxMessage - queued_bytes_) {
            fail(make_error(errc::kLimitExceeded, "WebSocket pre-upgrade queue exceeds 16 MiB", kWhere), ws::close_code::kMessageTooBig);
            return;
        }
        queued_bytes_ += bytes.size();
        queued_.push_back(std::move(bytes));
    }

    void close() noexcept {
        try {
            if (phase_ == phase::kUpgrading && !close_requested_) {
                // Finish the upgrade first so queued bytes and the Close frame still go out.
                close_requested_ = true;
                arm_grace();
            } else if (phase_ == phase::kOpen) {
                begin_close();
            }
        } catch (...) {
            stream_->close();
        }
    }

    [[nodiscard]] std::string peer() const { return stream_->peer(); }
    [[nodiscard]] bool loopback() const noexcept { return stream_->loopback(); }

private:
    enum class phase : std::uint8_t {
        kUpgrading,
        kOpen,
        kClosing,
        kDone
    };

    void on_bytes(utils::bytes_view data) override {
        const auto keep_alive = this->shared_from_this();
        if (phase_ == phase::kDone) {
            return;
        }
        input_.insert(input_.end(), data.begin(), data.end());
        if (phase_ == phase::kUpgrading && !finish_upgrade()) {
            return;
        }
        read_frames();
        compact();
        // Data payloads stream through; what stays is a partial frame header or control frame.
        if (phase_ != phase::kDone && input_.size() - read_ > ws::kMaxHeaderBytes + ws::kMaxControlPayload) {
            fail(make_error(errc::kLimitExceeded, "WebSocket buffered input exceeds one control frame", kWhere), ws::close_code::kProtocolError);
        }
    }

    void on_closed(const error& why) override {
        const auto keep_alive = this->shared_from_this();
        phase_ = phase::kDone;
        grace_.cancel();
        if (auto* handler = std::exchange(handler_, nullptr)) {
            handler->on_closed(failure_ ? *failure_ : why);
        }
    }

    // Returns true once the stream is open (more bytes may follow the HTTP head).
    bool finish_upgrade() {
        const std::string_view text{reinterpret_cast<const char*>(input_.data() + read_), input_.size() - read_};
        auto head = detail::parse_http_head(text, 0);
        if (!head) {
            fail(std::move(head).error(), ws::close_code::kProtocolError);
            return false;
        }
        if (!*head) {
            return false; // incomplete
        }
        if constexpr (Self == ws::role::kServer) {
            auto key = ws::accept_upgrade(**head);
            if (!key) {
                fail(std::move(key).error(), ws::close_code::kProtocolError);
                return false;
            }
            send_raw(ws::upgrade_response(*key));
        } else {
            if (auto ok = ws::check_upgrade_response(**head, key_); !ok) {
                fail(std::move(ok).error(), ws::close_code::kProtocolError);
                return false;
            }
        }
        read_ += (*head)->bytes;
        phase_ = phase::kOpen;
        for (const auto& bytes : queued_) {
            send_data(bytes.view());
        }
        queued_.clear();
        queued_bytes_ = 0;
        if (close_requested_) {
            begin_close();
        }
        return true;
    }

    void read_frames() {
        while (phase_ != phase::kDone && read_ < input_.size()) {
            if (payload_left_ != 0) {
                stream_payload();
                continue;
            }
            const auto available = std::span{input_}.subspan(read_);
            auto decoded = ws::decode_header(available, ws::peer_of(Self));
            if (!decoded) {
                const auto code = decoded.error().code == errc::kLimitExceeded ? ws::close_code::kMessageTooBig : ws::close_code::kProtocolError;
                fail(std::move(decoded).error(), code);
                return;
            }
            if (!*decoded) {
                return; // header incomplete
            }
            const auto& header = **decoded;
            if (ws::is_control(header.op)) {
                if (available.size() < header.bytes + header.payload) {
                    return; // control payloads (<= 125 bytes) are handled whole
                }
                const auto payload = available.subspan(header.bytes, static_cast<std::size_t>(header.payload));
                if (header.mask) {
                    ws::apply_mask(payload, *header.mask);
                }
                read_ += header.bytes + payload.size();
                on_control(header.op, payload);
                continue;
            }
            if ((header.op == ws::opcode::kContinuation) != in_message_) {
                fail(make_error(errc::kProtocol, "WebSocket continuation outside a fragmented message", kWhere), ws::close_code::kProtocolError);
                return;
            }
            if (header.payload > ws::kMaxMessage - message_bytes_) {
                fail(make_error(errc::kLimitExceeded, "WebSocket message exceeds 16 MiB", kWhere), ws::close_code::kMessageTooBig);
                return;
            }
            read_ += header.bytes;
            message_bytes_ += header.payload;
            payload_left_ = header.payload;
            payload_offset_ = 0;
            mask_ = header.mask;
            final_ = header.fin;
            in_message_ = !header.fin;
            if (payload_left_ == 0) {
                end_frame();
            }
        }
    }

    // Hands the available part of the current data frame to the handler (the link is a byte stream).
    void stream_payload() {
        const auto n = static_cast<std::size_t>(std::min<std::uint64_t>(payload_left_, input_.size() - read_));
        const auto chunk = std::span{input_}.subspan(read_, n);
        if (mask_) {
            ws::apply_mask(chunk, *mask_, payload_offset_);
        }
        read_ += n;
        payload_left_ -= n;
        payload_offset_ += n;
        if (handler_ != nullptr && phase_ == phase::kOpen) {
            handler_->on_bytes(chunk);
        }
        if (payload_left_ == 0) {
            end_frame();
        }
    }

    void end_frame() {
        if (final_) {
            message_bytes_ = 0;
        }
    }

    void on_control(ws::opcode op, utils::bytes_view payload) {
        switch (op) {
        case ws::opcode::kPing:
            if (phase_ == phase::kOpen) {
                send_frame(ws::opcode::kPong, payload);
            }
            break;
        case ws::opcode::kPong:
            break;
        case ws::opcode::kClose:
            if (!ws::valid_close_payload(payload)) {
                fail(make_error(errc::kProtocol, "invalid WebSocket close payload", kWhere), ws::close_code::kProtocolError);
                return;
            }
            if (phase_ == phase::kOpen) {
                send_frame(ws::opcode::kClose, payload); // echo the status (RFC 6455 §5.5.1)
            }
            finish();
            break;
        default:
            break;
        }
    }

    void begin_close() {
        send_frame(ws::opcode::kClose, ws::close_payload(ws::close_code::kNormal));
        phase_ = phase::kClosing;
        arm_grace();
    }

    void arm_grace() {
        grace_.start(kCloseGrace, [weak = this->weak_from_this()] {
            if (auto self = weak.lock()) {
                self->finish();
            }
        });
    }

    void finish() {
        phase_ = phase::kDone;
        grace_.cancel();
        stream_->close();
    }

    void fail(error why, ws::close_code code) {
        if (failure_) {
            return;
        }
        failure_ = std::move(why);
        if (phase_ == phase::kOpen) {
            send_frame(ws::opcode::kClose, ws::close_payload(code));
        }
        finish();
    }

    // The stream has no message boundaries, so a send larger than the peer's limit becomes several messages.
    void send_data(utils::bytes_view bytes) {
        while (!bytes.empty() && phase_ == phase::kOpen) {
            const auto n = std::min(bytes.size(), ws::kMaxMessage);
            send_frame(ws::opcode::kBinary, bytes.first(n));
            bytes = bytes.subspan(n);
        }
    }

    void send_frame(ws::opcode op, utils::bytes_view payload) {
        std::optional<ws::masking_key> mask;
        if constexpr (Self == ws::role::kClient) {
            auto random = platform::random_array<4>();
            if (!random) {
                failure_ = std::move(random).error();
                finish();
                return;
            }
            mask = *random;
        }
        utils::byte_buffer frame;
        ws::encode_frame(frame, op, payload, mask);
        stream_->send(std::move(frame));
    }

    void send_raw(std::string_view text) {
        utils::byte_buffer bytes;
        bytes.append(text);
        stream_->send(std::move(bytes));
    }

    void compact() {
        if (read_ == input_.size()) {
            input_.clear();
            read_ = 0;
        } else if (read_ > input_.size() / 2) {
            input_.erase(input_.begin(), input_.begin() + static_cast<std::ptrdiff_t>(read_));
            read_ = 0;
        }
    }

    std::unique_ptr<link> stream_;
    link_handler* handler_ = nullptr;
    std::string host_;
    std::string key_;
    io_context::timer grace_;
    phase phase_ = phase::kUpgrading;
    bool close_requested_ = false;
    std::optional<error> failure_;

    std::vector<std::byte> input_;
    std::size_t read_ = 0;
    std::deque<utils::byte_buffer> queued_;
    std::size_t queued_bytes_ = 0;

    // The data frame being streamed.
    std::uint64_t payload_left_ = 0;
    std::uint64_t payload_offset_ = 0;
    std::uint64_t message_bytes_ = 0;
    std::optional<ws::masking_key> mask_;
    bool final_ = true;
    bool in_message_ = false;
};

template <ws::role Self>
class websocket_link final : public link {
public:
    websocket_link(io_context& io, std::unique_ptr<link> stream, std::string host = {})
        : state_(std::make_shared<websocket_state<Self>>(io, std::move(stream), std::move(host))) {}
    ~websocket_link() override { state_->detach(); }

    websocket_link(const websocket_link&) = delete;
    websocket_link& operator=(const websocket_link&) = delete;

    void start(link_handler& handler) override { state_->start(handler); }
    void send(utils::byte_buffer bytes) override { state_->send(std::move(bytes)); }
    void close() noexcept override { state_->close(); }
    [[nodiscard]] std::string peer() const override { return state_->peer(); }
    [[nodiscard]] bool loopback() const noexcept override { return state_->loopback(); }

private:
    std::shared_ptr<websocket_state<Self>> state_;
};

// The Host header for a dialed endpoint ("[::1]:7777" for IPv6 literals).
std::string host_field(const endpoint& ep) {
    const bool ipv6 = ep.host.find(':') != std::string::npos && !ep.host.starts_with('[');
    return ipv6 ? std::format("[{}]:{}", ep.host, ep.port) : std::format("{}:{}", ep.host, ep.port);
}

} // namespace

result<std::unique_ptr<listener>> websocket::listen(io_context& io, const endpoint& ep, accept_fn on_accept) {
    return tcp::listen(io, ep, [&io, accept = std::move(on_accept)](std::unique_ptr<link> stream) {
        accept(std::make_unique<websocket_link<ws::role::kServer>>(io, std::move(stream)));
    });
}

void websocket::dial(io_context& io, const endpoint& ep, connect_fn on_connect) {
    tcp::dial(io, ep, [&io, connect = std::move(on_connect), host = host_field(ep)](result<std::unique_ptr<link>> stream) mutable {
        if (!stream) {
            connect(std::unexpected{std::move(stream).error()});
            return;
        }
        connect(std::make_unique<websocket_link<ws::role::kClient>>(io, std::move(*stream), std::move(host)));
    });
}

} // namespace Rhp::net

#include <array>
#include <optional>

#include <asio/ip/udp.hpp>
#include <rhp_test/datagram_relay.hpp>

#include <rhp/net/udp_reliable/detail/packet.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace rhp_test {

struct datagram_relay::impl : std::enable_shared_from_this<impl> {
    using udp = asio::ip::udp;
    impl(Rhp::net::io_context& io, unsigned short port, datagram_faults f)
        : socket(*static_cast<asio::io_context*>(io.native_handle()), udp::endpoint{asio::ip::make_address("127.0.0.1"), 0}),
          server(asio::ip::make_address("127.0.0.1"), port), faults(f) {}
    udp::socket socket;
    udp::endpoint server;
    std::optional<udp::endpoint> client;
    datagram_faults faults;
    unsigned packets = 0;
    std::uint64_t fin = 0;
    bool fin_from_server = false;
    bool dropped_fin_ack = false;
    std::optional<std::pair<Rhp::utils::byte_buffer, udp::endpoint>> held;

    void send(Rhp::utils::byte_buffer bytes, const udp::endpoint& to) {
        auto data = std::make_shared<Rhp::utils::byte_buffer>(std::move(bytes));
        socket.async_send_to(asio::buffer(data->view().data(), data->size()), to, [data](const std::error_code&, std::size_t) {});
    }

    void receive() {
        struct buffer {
            std::array<std::byte, 65536> data{};
            udp::endpoint from;
        };
        auto data = std::make_shared<buffer>();
        socket.async_receive_from(asio::buffer(data->data), data->from, [weak = weak_from_this(), data](const std::error_code& ec, std::size_t n) {
            auto self = weak.lock();
            if (!self || ec) {
                return;
            }
            const bool from_server = data->from == self->server;
            if (!from_server) {
                self->client = data->from;
            }
            if (self->client) {
                const auto to = from_server ? *self->client : self->server;
                Rhp::utils::byte_buffer packet;
                packet.append({data->data.data(), n});
                using Rhp::net::detail::rudp::packet_kind;
                const auto decoded = Rhp::net::detail::rudp::decode_packet(packet.view());
                const auto header = decoded ? decoded->header : Rhp::net::detail::rudp::packet_header{};
                const auto kind = decoded ? header.kind : packet_kind{};
                bool drop = false;
                if (kind == packet_kind::kFin) {
                    self->fin = header.seq;
                    self->fin_from_server = from_server;
                }
                if (kind == packet_kind::kAck && self->faults.drop_fin_ack && !self->dropped_fin_ack && self->fin != 0 && header.ack >= self->fin &&
                    from_server != self->fin_from_server) {
                    drop = true;
                    self->dropped_fin_ack = true;
                }
                if (kind == packet_kind::kData) {
                    const auto index = ++self->packets;
                    drop = self->faults.drop_data && index % 7 == 0;
                    if (!drop && self->faults.corrupt && index % 11 == 0 && n > Rhp::net::detail::rudp::kHeaderBytes + Rhp::net::detail::rudp::kTrailerBytes) {
                        packet.mutable_view()[Rhp::net::detail::rudp::kHeaderBytes] ^= std::byte{1}; // first payload byte: the CRC must catch it
                    }
                    if (!drop && self->faults.reorder && index % 5 == 0 && !self->held) {
                        self->held.emplace(std::move(packet), to);
                        self->receive();
                        return;
                    }
                    if (!drop && self->faults.duplicate && index % 3 == 0) {
                        self->send(packet, to);
                    }
                }
                if (!drop) {
                    self->send(std::move(packet), to);
                }
                if (self->held) {
                    self->send(std::move(self->held->first), self->held->second);
                    self->held.reset();
                }
            }
            self->receive();
        });
    }
};

datagram_relay::datagram_relay(Rhp::net::io_context& io, unsigned short server_port, datagram_faults faults)
    : impl_(std::make_shared<impl>(io, server_port, faults)) {
    impl_->receive();
}
datagram_relay::~datagram_relay() {
    std::error_code ignored;
    impl_->socket.close(ignored);
}
unsigned short datagram_relay::port() const {
    return impl_->socket.local_endpoint().port();
}

} // namespace rhp_test

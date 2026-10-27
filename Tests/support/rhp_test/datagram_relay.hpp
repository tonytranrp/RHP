#pragma once

#include <memory>
#include <vector>

#include <rhp/net/io_context.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace rhp_test {

// A bare UDP socket on 127.0.0.1 (native test backend): sends datagrams to a port on 127.0.0.1 and
// keeps every datagram that comes back.
class datagram_probe {
public:
    explicit datagram_probe(Rhp::net::io_context& io);
    ~datagram_probe();
    void send(unsigned short port, Rhp::utils::bytes_view datagram);
    [[nodiscard]] const std::vector<Rhp::utils::byte_buffer>& received() const;

private:
    struct impl;
    std::shared_ptr<impl> impl_;
};

struct datagram_faults {
    bool drop_data = false;
    bool duplicate = false;
    bool reorder = false;
    bool corrupt = false;
    bool drop_fin_ack = false;
};

// Native test backend; Asio stays in the implementation file.
class datagram_relay {
public:
    datagram_relay(Rhp::net::io_context& io, unsigned short server_port, datagram_faults faults);
    ~datagram_relay();
    [[nodiscard]] unsigned short port() const;

private:
    struct impl;
    std::shared_ptr<impl> impl_;
};

} // namespace rhp_test

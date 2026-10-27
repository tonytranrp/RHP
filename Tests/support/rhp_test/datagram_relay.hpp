#pragma once

#include <memory>

#include <rhp/net/io_context.hpp>

namespace rhp_test {

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

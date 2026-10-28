#pragma once

// A relay over loopback channels between a client and a host, for the tests that prove a relay
// can't authenticate: with `terminate` it accepts the client's TLS (with its own certificate) and
// opens its own TLS to the host, passing the plaintext along - what a man in the middle with a
// certificate the client doesn't check would do; without it, it passes the bytes as they are.

#include <memory>
#include <stop_token>
#include <thread>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/security/tls/auto_backend.hpp>
#include <rhp/security/tls/tls.hpp>
#include <rhp/session/secure_link.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace rhp_test {

class tls_relay final {
public:
    tls_relay(const Rhp::endpoint& front, const Rhp::endpoint& back, bool terminate) : back_(back), terminate_(terminate) {
        auto server = Rhp::security::tls::auto_backend::server({});
        auto client = Rhp::security::tls::auto_backend::client({});
        REQUIRE(server);
        REQUIRE(client);
        server_ = *server;
        client_ = *client;
        auto l = Rhp::net::loopback::listen(io_, front, [this](std::unique_ptr<Rhp::net::link> l) { accept(std::move(l)); });
        REQUIRE(l);
        listener_ = std::move(*l);
        thread_ = std::jthread{[this](std::stop_token stop) { io_.run(std::move(stop)); }};
    }

    ~tls_relay() {
        thread_.request_stop();
        thread_.join();
        pipes_.clear();
        listener_.reset();
    }

    tls_relay(const tls_relay&) = delete;
    tls_relay& operator=(const tls_relay&) = delete;

private:
    struct side final : Rhp::net::link_handler {
        std::unique_ptr<Rhp::net::link> link;
        side* other = nullptr;
        std::vector<Rhp::utils::byte_buffer> held; // until the other side exists

        void on_bytes(Rhp::utils::bytes_view data) override {
            Rhp::utils::byte_buffer b;
            b.append(data);
            if (other != nullptr && other->link != nullptr) {
                other->link->send(std::move(b));
            } else {
                held.push_back(std::move(b));
            }
        }
        void on_closed(const Rhp::error&) override {
            if (other != nullptr && other->link != nullptr) {
                other->link->close();
            }
        }
    };

    struct pipe {
        side front;
        side back;
    };

    void accept(std::unique_ptr<Rhp::net::link> l) {
        auto p = std::make_unique<pipe>();
        pipe& ref = *p;
        pipes_.push_back(std::move(p));
        ref.front.other = &ref.back;
        ref.back.other = &ref.front;
        ref.front.link = terminate_ ? Rhp::session::tls_server(std::move(l), server_, false) : std::move(l);
        ref.front.link->start(ref.front);
        Rhp::net::loopback::dial(io_, back_, [this, &ref](Rhp::result<std::unique_ptr<Rhp::net::link>> b) {
            if (!b) {
                ref.front.link->close();
                return;
            }
            if (terminate_) {
                auto engine = client_->make_engine();
                if (!engine) {
                    ref.front.link->close();
                    return;
                }
                ref.back.link = Rhp::session::tls_client(std::move(*b), std::move(*engine));
            } else {
                ref.back.link = std::move(*b);
            }
            ref.back.link->start(ref.back);
            for (auto& held : ref.front.held) {
                ref.back.link->send(std::move(held));
            }
            ref.front.held.clear();
        });
    }

    Rhp::net::io_context io_;
    Rhp::endpoint back_;
    bool terminate_;
    std::shared_ptr<Rhp::security::tls::context> server_;
    std::shared_ptr<Rhp::security::tls::context> client_;
    std::unique_ptr<Rhp::net::listener> listener_;
    std::vector<std::unique_ptr<pipe>> pipes_;
    std::jthread thread_;
};

} // namespace rhp_test

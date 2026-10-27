#pragma once

// Helpers for tests that drive io_contexts by hand (no threads): poll until something happens.

#include <chrono>
#include <cstddef>
#include <functional>
#include <initializer_list>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace rhp_test {

// Polls every context until `done()` or `timeout` (generous: sanitizer builds are slow).
inline bool poll_until(std::initializer_list<Rhp::net::io_context*> contexts, const std::function<bool()>& done,
                       std::chrono::milliseconds timeout = std::chrono::seconds{10}) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!done()) {
        if (std::chrono::steady_clock::now() > deadline) {
            return false;
        }
        std::size_t ran = 0;
        for (auto* io : contexts) {
            ran += io->poll();
        }
        if (ran == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
    }
    return true;
}

// Polls for a while regardless (to let timers fire).
inline void poll_for(std::initializer_list<Rhp::net::io_context*> contexts, std::chrono::milliseconds duration) {
    const auto deadline = std::chrono::steady_clock::now() + duration;
    while (std::chrono::steady_clock::now() < deadline) {
        std::size_t ran = 0;
        for (auto* io : contexts) {
            ran += io->poll();
        }
        if (ran == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
    }
}

// Records what a link delivers.
class recorder final : public Rhp::net::link_handler {
public:
    void on_bytes(Rhp::utils::bytes_view data) override { received.append(data); }
    void on_closed(const Rhp::error& why) override {
        closed = true;
        reason = why;
    }

    [[nodiscard]] std::string text() const { return {reinterpret_cast<const char*>(received.view().data()), received.size()}; }

    Rhp::utils::byte_buffer received;
    bool closed = false;
    Rhp::error reason;
};

inline Rhp::utils::byte_buffer buffer_of(std::string_view text) {
    Rhp::utils::byte_buffer b;
    b.append(text);
    return b;
}

} // namespace rhp_test

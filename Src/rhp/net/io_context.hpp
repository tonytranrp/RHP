#pragma once

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <stop_token>

namespace Rhp::net {

// The network reactor (Asio's io_context behind a wall: asio.hpp is only in Rhp::net's .cpp files).
// Every link, listener, timer and session lives on it and is only touched from the thread that is
// running it; other threads hand it work with post().
class io_context {
public:
    io_context();
    ~io_context();

    io_context(const io_context&) = delete;
    io_context& operator=(const io_context&) = delete;

    // Thread-safe: runs `fn` on the thread running the context (FIFO with other posts).
    void post(std::function<void()> fn);

    // Runs ready handlers without blocking; returns how many ran.
    std::size_t poll();
    // Runs at most one handler, waiting up to `timeout` for one.
    std::size_t run_one_for(std::chrono::milliseconds timeout);
    // Runs until `stop` is requested (an RHP-owned I/O thread's body).
    void run(std::stop_token stop);

    // asio::io_context*, for transports implemented on Asio inside Rhp::net.
    [[nodiscard]] void* native_handle() noexcept;

    // A one-shot timer: `fn` runs on the context after `delay` unless cancelled first (or the
    // timer is destroyed). Re-arming cancels the previous wait.
    class timer {
    public:
        explicit timer(io_context& io);
        ~timer();

        timer(const timer&) = delete;
        timer& operator=(const timer&) = delete;

        void start(std::chrono::milliseconds delay, std::function<void()> fn);
        void cancel() noexcept;

    private:
        struct impl;
        std::shared_ptr<impl> impl_;
    };

private:
    struct impl;
    std::unique_ptr<impl> impl_;
};

} // namespace Rhp::net

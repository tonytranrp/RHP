#pragma once

#include <concepts>
#include <functional>
#include <stop_token>
#include <thread>
#include <utility>

namespace Rhp::exec {

// I/O threading policy for Rhp::config<>::io<...>: who runs the network.
//   start(body) runs `body` (the network loop, which returns once its stop_token is signalled) on
//   the runner's thread, or not at all when kOwnsThread is false — then host.pump() and the
//   client's blocking calls poll the network themselves. stop() signals and joins.
template <class R>
concept io_runner = std::default_initializable<R> && requires(R& r, std::function<void(std::stop_token)> body) {
    { R::kOwnsThread } -> std::convertible_to<bool>;
    r.start(std::move(body));
    r.stop();
};

// The default: RHP owns one std::jthread running the network. Requests are read, acknowledged and
// cancelled even while pump() is stuck in a script — the only way a cancel can stop a runaway
// loop on the pump thread.
class owned_io_thread {
public:
    static constexpr bool kOwnsThread = true;

    owned_io_thread() = default;
    ~owned_io_thread() { stop(); }

    owned_io_thread(const owned_io_thread&) = delete;
    owned_io_thread& operator=(const owned_io_thread&) = delete;

    void start(std::function<void(std::stop_token)> body) {
        stop();
        thread_ = std::jthread{[body = std::move(body)](std::stop_token token) mutable { body(std::move(token)); }};
    }

    void stop() {
        if (thread_.joinable()) {
            thread_.request_stop();
            thread_.join();
        }
    }

private:
    std::jthread thread_;
};

// No threads at all: host.pump() polls the network, a client's blocking call runs it while it
// waits. Single-threaded and deterministic (tests, engines that own every thread) — but a script
// stuck in pump() also stops the network, so a cancel can't reach it and heartbeats lapse.
struct zero_threads {
    static constexpr bool kOwnsThread = false;

    void start(std::function<void(std::stop_token)>) noexcept {}
    void stop() noexcept {}
};

static_assert(io_runner<owned_io_thread>);
static_assert(io_runner<zero_threads>);

} // namespace Rhp::exec

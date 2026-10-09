#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <stop_token>
#include <system_error>
#include <utility>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>

#include <rhp/net/io_context.hpp>

namespace Rhp::net {

struct io_context::impl {
    asio::io_context ctx{1}; // one thread runs it: no internal locking needed beyond post()
    std::optional<asio::executor_work_guard<asio::io_context::executor_type>> work{ctx.get_executor()};

    // poll() / run_one_for() after a stop() or an earlier run out of work need a restart.
    void ready() {
        if (ctx.stopped()) {
            ctx.restart();
        }
    }
};

io_context::io_context() : impl_(std::make_unique<impl>()) {}

io_context::~io_context() {
    impl_->work.reset();
    impl_->ctx.stop();
}

void io_context::post(std::function<void()> fn) {
    asio::post(impl_->ctx, std::move(fn));
}

std::size_t io_context::poll() {
    impl_->ready();
    return impl_->ctx.poll();
}

std::size_t io_context::run_one_for(std::chrono::milliseconds timeout) {
    impl_->ready();
    return impl_->ctx.run_one_for(timeout);
}

void io_context::run(std::stop_token stop) {
    impl_->ready();
    const std::stop_callback on_stop{stop, [this] { impl_->ctx.stop(); }};
    while (!stop.stop_requested()) {
        impl_->ctx.run();
        // run() also returns after a stop() that wasn't ours (none today); go on unless asked to stop.
        if (!stop.stop_requested()) {
            impl_->ctx.restart();
        }
    }
}

void* io_context::native_handle() noexcept {
    return &impl_->ctx;
}

// ---- timer ---------------------------------------------------------------------------------------

struct io_context::timer::impl {
    explicit impl(asio::io_context& ctx) : t(ctx) {}

    asio::steady_timer t;
    std::function<void()> fn;
    std::uint64_t generation = 0; // a wait that completes after a re-arm or cancel is stale
};

io_context::timer::timer(io_context& io) : impl_(std::make_shared<impl>(*static_cast<asio::io_context*>(io.native_handle()))) {}

io_context::timer::~timer() {
    cancel();
}

void io_context::timer::start(std::chrono::milliseconds delay, std::function<void()> fn) {
    const std::uint64_t generation = ++impl_->generation;
    impl_->fn = std::move(fn);
    impl_->t.expires_after(delay);
    impl_->t.async_wait([weak = std::weak_ptr<impl>{impl_}, generation](const std::error_code& ec) {
        const auto self = weak.lock();
        if (ec || self == nullptr || self->generation != generation) {
            return;
        }
        // Copied: fn may re-arm (replace itself) while running.
        const auto fn = self->fn;
        if (fn) {
            fn();
        }
    });
}

void io_context::timer::cancel() noexcept {
    ++impl_->generation;
    impl_->fn = nullptr;
    try {
        impl_->t.cancel();
    } catch (const std::system_error&) { // the stale wait is ignored through `generation` anyway
    }
}

} // namespace Rhp::net

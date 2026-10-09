#include <deque>
#include <format>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace Rhp::net {

namespace {

// One end of an in-memory pipe. `io` and the queue are shared with the other end's thread (under
// the pipe's mutex); `handler` is only called on this end's io thread.
struct pipe_end {
    std::shared_ptr<io_context::poster> io; // null once this end's link is gone: nobody posts to it any more
    link_handler* handler = nullptr;
    std::deque<utils::byte_buffer> inbox; // bytes the other end sent
    bool scheduled = false;               // a pump of this end is posted
    bool closed = false;                  // this end closed (or is gone)
    bool peer_closed = false;             // the other end closed (or is gone)
};

// Buffers delivered per turn before pump_end lets the context run other handlers.
constexpr int kBatch = 64;

struct pipe {
    std::mutex mutex;
    pipe_end ends[2];
    std::string name;
};

void pump_end(const std::shared_ptr<pipe>& p, int me);

// Under p->mutex.
void schedule(const std::shared_ptr<pipe>& p, int me) {
    pipe_end& e = p->ends[me];
    if (e.scheduled || e.io == nullptr) {
        return;
    }
    // A context that is shutting down refuses the post; this end is going away with it.
    e.scheduled = e.io->post([p, me] { pump_end(p, me); });
}

// On end `me`'s io thread: hand queued bytes to the handler, then report a close.
void pump_end(const std::shared_ptr<pipe>& p, int me) {
    for (int delivered = 0;; ++delivered) {
        std::unique_lock lock{p->mutex};
        pipe_end& e = p->ends[me];
        e.scheduled = false;
        link_handler* h = e.handler;
        if (h == nullptr) {
            return;
        }
        if (delivered == kBatch && !e.inbox.empty()) {
            // A busy peer must not starve this thread's timers and other handlers: yield.
            schedule(p, me);
            return;
        }
        if (!e.closed && !e.inbox.empty()) {
            utils::byte_buffer bytes = std::move(e.inbox.front());
            e.inbox.pop_front();
            lock.unlock();
            h->on_bytes(bytes.view());
            continue;
        }
        if (e.closed || e.peer_closed) {
            e.handler = nullptr;
            const error why = e.closed ? error{} : make_error(errc::kTransport, "the loopback peer closed the link", p->name);
            lock.unlock();
            h->on_closed(why);
        }
        return;
    }
}

class loopback_link final : public link {
public:
    loopback_link(std::shared_ptr<pipe> p, int me) : pipe_(std::move(p)), me_(me) {}

    ~loopback_link() override {
        const std::scoped_lock lock{pipe_->mutex};
        pipe_end& e = pipe_->ends[me_];
        if (!e.closed) {
            pipe_->ends[1 - me_].peer_closed = true;
            schedule(pipe_, 1 - me_);
        }
        e.closed = true;
        e.handler = nullptr;
        e.io.reset();
        e.inbox.clear();
    }

    loopback_link(const loopback_link&) = delete;
    loopback_link& operator=(const loopback_link&) = delete;

    void start(link_handler& handler) override {
        const std::scoped_lock lock{pipe_->mutex};
        pipe_->ends[me_].handler = &handler;
        schedule(pipe_, me_);
    }

    void send(utils::byte_buffer bytes) override {
        const std::scoped_lock lock{pipe_->mutex};
        pipe_end& other = pipe_->ends[1 - me_];
        if (pipe_->ends[me_].closed || other.closed || other.io == nullptr) {
            return;
        }
        other.inbox.push_back(std::move(bytes));
        schedule(pipe_, 1 - me_);
    }

    void close() noexcept override {
        try {
            const std::scoped_lock lock{pipe_->mutex};
            pipe_end& e = pipe_->ends[me_];
            if (e.closed) {
                return;
            }
            e.closed = true;
            e.inbox.clear();
            schedule(pipe_, me_);
            pipe_->ends[1 - me_].peer_closed = true;
            schedule(pipe_, 1 - me_);
        } catch (...) { // a failed post (out of memory): the destructor still tells the peer
        }
    }

    [[nodiscard]] std::string peer() const override { return std::format("loopback:{}", pipe_->name); }

private:
    std::shared_ptr<pipe> pipe_;
    int me_;
};

// A listening channel. `io` is cleared when the listener dies, so late dials see it closed.
struct channel {
    std::mutex mutex;
    std::shared_ptr<io_context::poster> io;
    accept_fn on_accept;
};

struct registry {
    std::mutex mutex;
    std::map<std::string, std::shared_ptr<channel>, std::less<>> channels;
};

registry& channels() {
    static registry r;
    return r;
}

[[nodiscard]] std::string channel_name(const endpoint& ep) {
    return std::format("{}:{}", ep.host, ep.port);
}

class loopback_listener final : public listener {
public:
    loopback_listener(std::string name, std::shared_ptr<channel> ch) : name_(std::move(name)), channel_(std::move(ch)) {}

    ~loopback_listener() override {
        {
            auto& r = channels();
            const std::scoped_lock lock{r.mutex};
            if (const auto it = r.channels.find(name_); it != r.channels.end() && it->second == channel_) {
                r.channels.erase(it);
            }
        }
        const std::scoped_lock lock{channel_->mutex};
        channel_->io.reset();
        channel_->on_accept = nullptr;
    }

    loopback_listener(const loopback_listener&) = delete;
    loopback_listener& operator=(const loopback_listener&) = delete;

    [[nodiscard]] unsigned short port() const noexcept override { return 0; }

private:
    std::string name_;
    std::shared_ptr<channel> channel_;
};

} // namespace

result<std::unique_ptr<listener>> loopback::listen(io_context& io, const endpoint& ep, accept_fn on_accept) {
    std::string key = channel_name(ep);
    auto ch = std::make_shared<channel>();
    ch->io = io.shared_poster();
    ch->on_accept = std::move(on_accept);
    auto& r = channels();
    const std::scoped_lock lock{r.mutex};
    if (r.channels.contains(key)) {
        return fail(errc::kAlreadyLoaded, std::format("loopback channel {} is already listening", key), "net.loopback");
    }
    r.channels.emplace(key, ch);
    return std::unique_ptr<listener>{std::make_unique<loopback_listener>(std::move(key), std::move(ch))};
}

void loopback::dial(io_context& io, const endpoint& ep, connect_fn on_connect) {
    const std::string key = channel_name(ep);
    std::shared_ptr<channel> ch;
    {
        auto& r = channels();
        const std::scoped_lock lock{r.mutex};
        if (const auto it = r.channels.find(key); it != r.channels.end()) {
            ch = it->second;
        }
    }
    if (ch == nullptr) {
        io.post([on_connect = std::move(on_connect), key] { on_connect(fail(errc::kNotFound, std::format("no loopback channel {}", key), "net.loopback")); });
        return;
    }

    auto p = std::make_shared<pipe>();
    p->name = key;
    p->ends[0].io = io.shared_poster();
    // Links travel through std::function (copyable) in shared holders.
    auto dialer = std::make_shared<std::unique_ptr<link>>(std::make_unique<loopback_link>(p, 0));
    auto acceptor = std::make_shared<std::unique_ptr<link>>(std::make_unique<loopback_link>(p, 1));
    {
        const std::scoped_lock lock{ch->mutex};
        if (ch->io == nullptr) {
            io.post([on_connect = std::move(on_connect), key] { on_connect(fail(errc::kNotFound, std::format("no loopback channel {}", key), "net.loopback")); });
            return;
        }
        {
            const std::scoped_lock pipe_lock{p->mutex};
            p->ends[1].io = ch->io;
        }
        ch->io->post([ch, acceptor] {
            accept_fn fn;
            {
                const std::scoped_lock lock{ch->mutex};
                fn = ch->on_accept;
            }
            if (fn) {
                fn(std::move(*acceptor));
            }
            // Not accepted: the holder dies with this lambda and the dialer sees the link close.
        });
    }
    io.post([on_connect = std::move(on_connect), dialer] { on_connect(std::move(*dialer)); });
}

} // namespace Rhp::net

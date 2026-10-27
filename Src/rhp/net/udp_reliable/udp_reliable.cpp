#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <deque>
#include <format>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

#include <asio/ip/udp.hpp>
#include <asio/steady_timer.hpp>

#include <rhp/net/detail/asio_support.hpp>
#include <rhp/net/udp_reliable/detail/cookie.hpp>
#include <rhp/net/udp_reliable/detail/packet.hpp>
#include <rhp/net/udp_reliable/udp_reliable.hpp>
#include <rhp/platform/random.hpp>

namespace Rhp::net {

namespace {

namespace rudp = detail::rudp;
using udp = asio::ip::udp;
using clock = std::chrono::steady_clock;
using detail::context_of;
using std::chrono::milliseconds;

constexpr const char* kWhere = "net.udp_reliable";
constexpr std::size_t kMaxQueue = 16u << 20; // unacknowledged application bytes per link
constexpr std::size_t kInitialWindow = 4;    // packets in flight before the first ACK
constexpr std::size_t kMinWindow = 2;
constexpr std::uint64_t kReorderThreshold = 3; // later packets acknowledged before a hole counts as lost
constexpr std::size_t kMaxPeers = 1024;        // live links (accepted or half-open) per socket
constexpr std::size_t kMaxClosedPeers = 4096;  // FIN tombstones per socket
constexpr milliseconds kInitialRto{100};
constexpr milliseconds kMinRto{25};
constexpr milliseconds kMaxRto{2000};
constexpr std::chrono::seconds kNoProgress{10}; // outstanding work without an ACK closes the link
constexpr std::chrono::seconds kFinLinger{12};  // a lost final ACK can still be answered

struct peer_state;
using peer_key = std::pair<udp::endpoint, std::uint64_t>;

// ---- socket ----------------------------------------------------------------------------------------

// One UDP socket: a listener's (many peers) or a dialer's (one). Peers keep it alive; it holds them
// weakly and demultiplexes datagrams by (source, token).
struct udp_service : std::enable_shared_from_this<udp_service> {
    explicit udp_service(io_context& context) : io(context), socket(context_of(context)), linger(context_of(context)) {}
    ~udp_service() {
        std::error_code ignored;
        socket.close(ignored);
    }

    struct tombstone {
        std::uint64_t fin_seq;
        clock::time_point expires;
    };

    io_context& io;
    udp::socket socket;
    asio::steady_timer linger;
    accept_fn accept;
    std::optional<rudp::cookie_jar> cookies; // a listener's: a Hello makes a peer only with one of its cookies
    std::map<peer_key, std::weak_ptr<peer_state>> peers;
    std::map<peer_key, tombstone> closed_peers;
    std::array<std::byte, rudp::kMaxPacket + 1> buffer{}; // one receive is outstanding at a time
    udp::endpoint from;
    utils::byte_buffer scratch;
    // While a receive drains the socket, peers that got packets owe their ACK until the drain ends:
    // one ACK then covers them all (cumulative + selective), unless a packet sent meanwhile carried it.
    bool draining = false;
    std::vector<std::shared_ptr<peer_state>> owing;

    void receive();
    void process(std::size_t n);
    void flush_acks();
    void dispatch(const rudp::packet& in, const udp::endpoint& source);

    void send(const udp::endpoint& to, const rudp::packet_header& header, utils::bytes_view payload = {}) {
        scratch.clear();
        rudp::encode_packet(scratch, header, payload);
        // Nonblocking: a full kernel queue is packet loss, recovered by retransmission.
        std::error_code ignored;
        socket.send_to(asio::buffer(scratch.view().data(), scratch.size()), to, 0, ignored);
    }

    // Remembers a peer whose FIN we acknowledged, so a retransmitted FIN still gets its ACK after
    // the link is gone. The socket itself is kept alive for kFinLinger by the linger timer.
    void remember_closed(const peer_key& key, std::uint64_t fin_seq) {
        const auto now = clock::now();
        std::erase_if(closed_peers, [&](const auto& item) { return item.second.expires <= now; });
        if (closed_peers.size() >= kMaxClosedPeers) {
            closed_peers.erase(std::ranges::min_element(closed_peers, {}, [](const auto& item) { return item.second.expires; }));
        }
        closed_peers[key] = {fin_seq, now + kFinLinger};
        linger.expires_after(kFinLinger);
        linger.async_wait([retained = shared_from_this()](const std::error_code&) {});
    }
};

// ---- peer --------------------------------------------------------------------------------------

struct queued_packet {
    rudp::packet_kind kind = rudp::packet_kind::kData;
    utils::byte_buffer payload;
    clock::time_point sent{};
    unsigned attempts = 0;
};

// One reliable stream. Shared by its udp_link and its timer, so a closing link keeps
// retransmitting its last bytes and FIN after the owner released it.
struct peer_state : std::enable_shared_from_this<peer_state> {
    peer_state(std::shared_ptr<udp_service> owner, udp::endpoint to, std::uint64_t connection, bool accepted)
        : service(std::move(owner)), remote(std::move(to)), token(connection), ready(accepted), timer(context_of(service->io)) {}

    std::shared_ptr<udp_service> service;
    udp::endpoint remote;
    std::uint64_t token;
    std::uint64_t cookie = 0; // a dialer's: the listener's cookie, echoed in every Hello once known
    bool ready;               // handshake finished (always true for accepted peers)
    bool closing = false;     // close() asked: FIN follows the queued bytes
    bool closed = false;
    bool fin_sent = false;
    bool ack_owed = false; // packets received this drain that no sent packet has acknowledged yet
    link_handler* handler = nullptr;
    connect_fn connected; // the dialer's pending callback
    asio::steady_timer timer;
    std::optional<clock::time_point> armed;

    // Sending: whole sends waiting for the window, then fragments in flight.
    std::deque<utils::byte_buffer> queue;
    std::size_t queue_offset = 0;
    std::size_t queued_bytes = 0; // not yet acknowledged
    std::map<std::uint64_t, queued_packet> pending;
    std::uint64_t send_seq = 1;
    std::size_t window = kInitialWindow;
    std::uint64_t recovery_point = 0; // fast retransmit halves the window once until send_seq passes this

    // Receiving: fragments past a gap, kept until it fills.
    std::map<std::uint64_t, queued_packet> received;
    std::uint64_t recv_seq = 1;

    // Retransmission timeout (RFC 6298 estimator, Karn's rule: only first transmissions are timed).
    milliseconds rto = kInitialRto;
    std::optional<clock::duration> srtt;
    clock::duration rttvar{};
    clock::time_point progress = clock::now();
    clock::time_point hello_sent{};

    [[nodiscard]] rudp::packet_header header(rudp::packet_kind kind, std::uint64_t seq = 0) const {
        if (kind == rudp::packet_kind::kHello) {
            return {kind, token, 0, cookie, 0};
        }
        std::uint64_t sack = 0;
        for (auto it = received.lower_bound(recv_seq); it != received.end() && it->first - recv_seq < rudp::kWindow; ++it) {
            sack |= std::uint64_t{1} << (it->first - recv_seq);
        }
        return {kind, token, seq, recv_seq - 1, sack};
    }

    // Every packet's header carries the latest ACK, so any send settles what is owed.
    void send(rudp::packet_kind kind, std::uint64_t seq = 0, utils::bytes_view payload = {}) {
        ack_owed = false;
        service->send(remote, header(kind, seq), payload);
    }

    // Acknowledges received packets: at the end of the socket drain in progress, else now.
    void owe_ack() {
        if (!service->draining) {
            send(rudp::packet_kind::kAck);
        } else if (!std::exchange(ack_owed, true)) {
            service->owing.push_back(shared_from_this());
        }
    }

    void finish(error why) {
        if (std::exchange(closed, true)) {
            return;
        }
        timer.cancel();
        armed.reset();
        if (auto fn = std::exchange(connected, nullptr)) {
            fn(std::unexpected{why.code == errc::kOk ? make_error(errc::kTransport, "UDP connection closed", kWhere) : why});
        }
        service->io.post([self = shared_from_this(), why = std::move(why)] {
            if (auto* h = std::exchange(self->handler, nullptr)) {
                h->on_closed(why);
            }
        });
    }

    // Moves queued bytes into the window, then the FIN once everything was acknowledged.
    void transmit() {
        if (closed) {
            return;
        }
        if (!ready) {
            schedule(); // the Hello retry also keeps a half-open dialer alive
            return;
        }
        while (pending.size() < window && !queue.empty()) {
            if (send_seq == std::numeric_limits<std::uint64_t>::max()) {
                finish(make_error(errc::kLimitExceeded, "UDP sequence exhausted", kWhere));
                return;
            }
            // The payload is a byte stream: a packet takes bytes from as many queued sends as fit, so
            // sends queued behind a full window (pipelined calls) share packets.
            queued_packet entry{rudp::packet_kind::kData, {}, clock::now(), 1};
            while (entry.payload.size() < rudp::kMaxPayload && !queue.empty()) {
                const auto& front = queue.front();
                const auto n = std::min(rudp::kMaxPayload - entry.payload.size(), front.size() - queue_offset);
                entry.payload.append(front.view().subspan(queue_offset, n));
                if ((queue_offset += n) == front.size()) {
                    queue.pop_front();
                    queue_offset = 0;
                }
            }
            const auto seq = send_seq++;
            send(entry.kind, seq, entry.payload.view());
            pending.emplace(seq, std::move(entry));
        }
        if (closing && queue.empty() && pending.empty() && !fin_sent) {
            const auto seq = send_seq++;
            fin_sent = true;
            send(rudp::packet_kind::kFin, seq);
            pending.emplace(seq, queued_packet{rudp::packet_kind::kFin, {}, clock::now(), 1});
        }
        schedule();
    }

    [[nodiscard]] bool has_work() const noexcept { return !ready || !pending.empty() || !queue.empty(); }

    // The timer only runs while something can time out: an idle link costs no wakeups.
    void schedule() {
        if (closed || !has_work()) {
            return;
        }
        auto due = progress + kNoProgress;
        if (!ready) {
            due = std::min(due, hello_sent + rto);
        }
        for (const auto& [seq, entry] : pending) {
            due = std::min(due, entry.sent + rto);
        }
        if (armed && *armed <= due) {
            return;
        }
        armed = due;
        timer.expires_at(due);
        timer.async_wait([self = shared_from_this()](const std::error_code& ec) {
            if (!ec) {
                self->armed.reset();
                self->on_timer();
            }
        });
    }

    void on_timer() {
        if (closed) {
            return;
        }
        const auto now = clock::now();
        if (has_work() && now - progress >= kNoProgress) {
            finish(make_error(errc::kTimeout, "UDP peer made no progress for 10 seconds", kWhere));
            return;
        }
        if (!ready && now - hello_sent >= rto) {
            send(rudp::packet_kind::kHello);
            hello_sent = now;
        }
        // Retransmission timeout: resend what expired, coalescing what is about to (one backoff per batch).
        bool lost = false;
        for (auto& [seq, entry] : pending) {
            if (now + rto / 4 - entry.sent >= rto) {
                resend(seq, entry, now);
                lost = true;
            }
        }
        if (lost) {
            window = std::max(kMinWindow, window / 2);
            rto = std::min(rto * 2, kMaxRto);
        }
        transmit();
    }

    void resend(std::uint64_t seq, queued_packet& entry, clock::time_point now) {
        send(entry.kind, seq, entry.payload.view());
        entry.sent = now;
        ++entry.attempts;
    }

    // The timeout without backoff: the RFC 6298 estimate once there is a sample.
    [[nodiscard]] milliseconds base_rto() const {
        if (!srtt) {
            return kInitialRto;
        }
        return std::clamp(std::chrono::duration_cast<milliseconds>(*srtt + std::max<clock::duration>(milliseconds{1}, rttvar * 4)), kMinRto, kMaxRto);
    }

    // Fast retransmit: a hole with kReorderThreshold later packets acknowledged is lost, not late.
    // Resent at most once per round trip; the window is halved once per recovery.
    void repair_holes(std::uint64_t highest_acked, clock::time_point now) {
        const auto gap = srtt ? *srtt : clock::duration{kMinRto};
        bool repaired = false;
        for (auto& [seq, entry] : pending) {
            if (seq + kReorderThreshold > highest_acked) {
                break;
            }
            if (now - entry.sent >= gap) {
                resend(seq, entry, now);
                repaired = true;
            }
        }
        if (repaired && send_seq > recovery_point) {
            window = std::max(kMinWindow, window / 2);
            recovery_point = send_seq;
        }
    }

    void sample_rtt(clock::duration rtt) {
        if (!srtt) {
            srtt = rtt;
            rttvar = rtt / 2;
        } else {
            const auto delta = *srtt > rtt ? *srtt - rtt : rtt - *srtt;
            rttvar = (rttvar * 3 + delta) / 4;
            srtt = (*srtt * 7 + rtt) / 8;
        }
    }

    void acknowledge(std::uint64_t ack, std::uint64_t sack) {
        if (ack >= send_seq) {
            return; // acknowledges something never sent
        }
        const auto now = clock::now();
        const auto highest_acked = sack == 0 ? ack : ack + static_cast<std::uint64_t>(std::bit_width(sack));
        bool advanced = false;
        bool fin_acked = false;
        for (auto it = pending.begin(); it != pending.end();) {
            const auto seq = it->first;
            const bool selected = seq > ack && seq - ack <= rudp::kWindow && (sack & (std::uint64_t{1} << (seq - ack - 1))) != 0;
            if (seq > ack && !selected) {
                ++it;
                continue;
            }
            if (it->second.attempts == 1) {
                sample_rtt(now - it->second.sent); // Karn's rule: retransmissions are ambiguous
            }
            queued_bytes -= it->second.payload.size();
            fin_acked = fin_acked || it->second.kind == rudp::packet_kind::kFin;
            it = pending.erase(it);
            advanced = true;
        }
        if (advanced) {
            progress = now;
            rto = base_rto(); // progress ends the backoff
            window = std::min(rudp::kWindow, window + 1);
        }
        if (fin_acked) {
            finish({});
            return;
        }
        repair_holes(highest_acked, now);
        transmit();
    }

    void ingest(const rudp::packet& in);
    void deliver();
};

class udp_link final : public link {
public:
    explicit udp_link(std::shared_ptr<peer_state> state) : state_(std::move(state)) {}
    ~udp_link() override {
        // A started link that close()d still owes its data and FIN: the timer keeps retransmitting
        // them (bounded by kNoProgress). A link nobody started, with nothing queued, just stops.
        const bool draining = state_->closing && !state_->closed && (state_->handler != nullptr || state_->queued_bytes != 0);
        state_->handler = nullptr;
        if (draining) {
            return;
        }
        state_->closed = true;
        try {
            state_->timer.cancel();
        } catch (const std::system_error&) { // a timer whose context is gone: nothing left to cancel
        }
    }

    udp_link(const udp_link&) = delete;
    udp_link& operator=(const udp_link&) = delete;

    void start(link_handler& handler) override {
        state_->handler = &handler;
        state_->deliver();
    }

    void send(utils::byte_buffer bytes) override {
        auto& s = *state_;
        if (s.closed || s.closing || bytes.empty()) {
            return;
        }
        if (bytes.size() > kMaxQueue - s.queued_bytes) {
            s.finish(make_error(errc::kLimitExceeded, "UDP send queue exceeds 16 MiB", kWhere));
            return;
        }
        if (!s.has_work()) {
            s.progress = clock::now(); // the no-progress clock starts with the first outstanding byte
        }
        s.queued_bytes += bytes.size();
        s.queue.push_back(std::move(bytes));
        s.transmit();
    }

    void close() noexcept override {
        try {
            if (!state_->closed && !state_->closing) {
                state_->closing = true;
                state_->progress = clock::now();
                state_->transmit();
            }
        } catch (...) {
        }
    }

    [[nodiscard]] std::string peer() const override { return detail::address_text(state_->remote.address(), state_->remote.port()); }
    [[nodiscard]] bool loopback() const noexcept override { return detail::is_loopback(state_->remote.address()); }
    [[nodiscard]] std::optional<ip_address> address() const noexcept override { return detail::to_ip_address(state_->remote.address()); }

private:
    std::shared_ptr<peer_state> state_;
};

void peer_state::ingest(const rudp::packet& in) {
    const auto& h = in.header;
    if (closed) {
        if (h.kind == rudp::packet_kind::kFin && h.seq < recv_seq) {
            send(rudp::packet_kind::kAck); // our ACK of their FIN was lost
        }
        return;
    }
    switch (h.kind) {
    case rudp::packet_kind::kHello:
        if (ready) {
            send(rudp::packet_kind::kWelcome); // our welcome was lost
        }
        return;
    case rudp::packet_kind::kCookie:
        if (!ready && h.ack != 0) {
            // The listener's answer to our Hello: the same Hello again, with the cookie it made.
            cookie = h.ack;
            hello_sent = clock::now();
            send(rudp::packet_kind::kHello);
        }
        return;
    case rudp::packet_kind::kWelcome:
        if (!ready) {
            ready = true;
            progress = clock::now();
            if (auto fn = std::exchange(connected, nullptr)) {
                fn(std::make_unique<udp_link>(shared_from_this()));
            }
            transmit();
        }
        return;
    default:
        break;
    }
    if (!ready) {
        return;
    }
    acknowledge(h.ack, h.sack);
    if (closed || h.kind == rudp::packet_kind::kAck) {
        return;
    }
    if (h.seq == recv_seq && h.kind == rudp::packet_kind::kData && received.empty() && handler != nullptr) {
        ++recv_seq; // in order with nothing buffered: straight to the handler, no copy
        handler->on_bytes(in.payload);
    } else if (h.seq >= recv_seq && h.seq - recv_seq < rudp::kWindow) {
        queued_packet entry{h.kind, {}, {}, 0};
        entry.payload.append(in.payload);
        received.try_emplace(h.seq, std::move(entry));
        deliver();
    }
    if (!closed) {
        owe_ack(); // duplicates and out-of-window packets are re-acknowledged too
    }
}

void peer_state::deliver() {
    while (!closed && handler != nullptr) {
        const auto it = received.find(recv_seq);
        if (it == received.end()) {
            return;
        }
        auto entry = std::move(it->second);
        received.erase(it);
        ++recv_seq;
        if (entry.kind == rudp::packet_kind::kFin) {
            service->remember_closed({remote, token}, recv_seq - 1);
            send(rudp::packet_kind::kAck);
            finish(make_error(errc::kTransport, "UDP peer closed the stream", kWhere));
            return;
        }
        handler->on_bytes(entry.payload.view());
    }
}

void udp_service::receive() {
    socket.async_receive_from(asio::buffer(buffer), from, [weak = weak_from_this()](const std::error_code& ec, std::size_t n) {
        const auto self = weak.lock();
        if (!self || ec == asio::error::operation_aborted || !self->socket.is_open()) {
            return;
        }
        // Other errors (ICMP port unreachable reported on Windows, oversized datagrams) are per packet.
        if (!ec) {
            // Then the datagrams already waiting (a bounded number, so one busy socket can't hold the
            // thread), and one ACK per peer for all of them.
            constexpr int kMaxDrain = 64;
            self->draining = true;
            self->process(n);
            for (int i = 0; i < kMaxDrain && self->socket.is_open(); ++i) {
                std::error_code more;
                const std::size_t m = self->socket.receive_from(asio::buffer(self->buffer), self->from, 0, more);
                if (more == asio::error::would_block || more == asio::error::try_again) {
                    break;
                }
                if (!more) {
                    self->process(m);
                }
            }
            self->draining = false;
            self->flush_acks();
        }
        if (self->socket.is_open()) {
            self->receive();
        }
    });
}

void udp_service::process(std::size_t n) {
    if (const auto in = rudp::decode_packet({buffer.data(), n})) {
        dispatch(*in, from);
    }
}

// Sending only writes to the socket (no peer re-enters `owing`), so the list is walked in place and
// keeps its capacity for the next drain.
void udp_service::flush_acks() {
    for (const auto& peer : owing) {
        if (peer->ack_owed && !peer->closed) {
            peer->send(rudp::packet_kind::kAck);
        }
        peer->ack_owed = false;
    }
    owing.clear();
}

void udp_service::dispatch(const rudp::packet& in, const udp::endpoint& source) {
    const peer_key key{source, in.header.token};
    if (const auto found = peers.find(key); found != peers.end()) {
        if (auto peer = found->second.lock()) {
            peer->ingest(in);
            return;
        }
        peers.erase(found);
    }
    if (in.header.kind == rudp::packet_kind::kFin) {
        // A retransmitted FIN for a link that already went away: acknowledge it from the tombstone.
        if (const auto closed = closed_peers.find(key); closed != closed_peers.end() && closed->second.expires > clock::now()) {
            send(source, {rudp::packet_kind::kAck, in.header.token, 0, closed->second.fin_seq, 0});
        }
        return;
    }
    if (in.header.kind != rudp::packet_kind::kHello || in.header.seq != 0 || !accept || !cookies) {
        return;
    }
    // Nothing is kept for a Hello until it echoes a cookie made for its source, so a spoofed source
    // (which never sees the cookie) costs one reply the size of its Hello.
    const rudp::hello_source sender{detail::to_ip_address(source.address()).bytes(), source.port(), in.header.token};
    const auto now = clock::now();
    if (!cookies->valid(now, sender, in.header.ack)) {
        send(source, {rudp::packet_kind::kCookie, in.header.token, 0, cookies->issue(now, sender), 0});
        return;
    }
    std::erase_if(peers, [](const auto& item) { return item.second.expired(); });
    if (peers.size() >= kMaxPeers) {
        return; // a Hello flood can't grow the socket's state: the dialer retries
    }
    auto peer = std::make_shared<peer_state>(shared_from_this(), source, in.header.token, true);
    peers[key] = peer;
    peer->send(rudp::packet_kind::kWelcome);
    accept(std::make_unique<udp_link>(std::move(peer)));
}

class udp_listener final : public listener {
public:
    explicit udp_listener(std::shared_ptr<udp_service> service) : service_(std::move(service)) {}
    // Stops accepting; links already handed out keep the socket open.
    ~udp_listener() override { service_->accept = nullptr; }

    [[nodiscard]] unsigned short port() const noexcept override {
        std::error_code ec;
        const auto ep = service_->socket.local_endpoint(ec);
        return ec ? 0 : ep.port();
    }

private:
    std::shared_ptr<udp_service> service_;
};

[[nodiscard]] result<void> open_socket(udp_service& service, const udp::endpoint& ep) {
    std::error_code ec;
    service.socket.open(ep.protocol(), ec);
    if (!ec) {
        service.socket.bind(ep, ec);
    }
    if (!ec) {
        service.socket.non_blocking(true, ec);
    }
    if (ec) {
        return fail(errc::kTransport, ec.message(), kWhere);
    }
    return {};
}

[[nodiscard]] result<udp::endpoint> choose(const endpoint& ep, const std::error_code& ec, const udp::resolver::results_type& found) {
    if (ec || found.empty()) {
        return fail(errc::kTransport, std::format("can't resolve {}: {}", ep.host, ec ? ec.message() : "no address"), kWhere);
    }
    // Same address rule as TCP: plaintext UDP off loopback only with insecure_lan, unless the session adds TLS.
    const auto it = std::ranges::find_if(found, [&](const auto& entry) { return detail::address_allowed(ep, entry.endpoint().address()); });
    if (it == found.end()) {
        return fail(errc::kForbidden, std::format("{} is not a loopback address: plain UDP there needs Rhp::net::insecure_lan or TLS", ep.host), kWhere);
    }
    return it->endpoint();
}

} // namespace

result<std::unique_ptr<listener>> udp_reliable::listen(io_context& io, const endpoint& ep, accept_fn on_accept) {
    auto service = std::make_shared<udp_service>(io);
    std::error_code ec;
    udp::resolver resolver{context_of(io)};
    const auto found = resolver.resolve(ep.host, std::to_string(ep.port), udp::resolver::passive | udp::resolver::numeric_service, ec);
    auto address = choose(ep, ec, found);
    if (!address) {
        return std::unexpected{std::move(address).error()};
    }
    auto cookies = rudp::cookie_jar::make(clock::now());
    if (!cookies) {
        return std::unexpected{std::move(cookies).error()};
    }
    if (auto ok = open_socket(*service, *address); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    service->cookies = std::move(*cookies);
    service->accept = std::move(on_accept);
    service->receive();
    return std::make_unique<udp_listener>(std::move(service));
}

void udp_reliable::dial(io_context& io, const endpoint& ep, connect_fn on_connect) {
    auto service = std::make_shared<udp_service>(io);
    auto resolver = std::make_shared<udp::resolver>(context_of(io));
    resolver->async_resolve(ep.host, std::to_string(ep.port), udp::resolver::numeric_service,
                            [service, resolver, ep, fn = std::move(on_connect)](const std::error_code& ec, const udp::resolver::results_type& found) mutable {
                                auto address = choose(ep, ec, found);
                                if (!address) {
                                    fn(std::unexpected{std::move(address).error()});
                                    return;
                                }
                                if (auto ok = open_socket(*service, udp::endpoint{address->protocol(), 0}); !ok) {
                                    fn(std::unexpected{std::move(ok).error()});
                                    return;
                                }
                                auto seed = platform::random_array<8>();
                                if (!seed) {
                                    fn(std::unexpected{std::move(seed).error()});
                                    return;
                                }
                                const auto token = utils::load_le<std::uint64_t>(*seed) | 1; // never zero
                                auto peer = std::make_shared<peer_state>(service, *address, token, false);
                                peer->connected = std::move(fn);
                                service->peers[{peer->remote, token}] = peer;
                                service->receive();
                                peer->on_timer(); // sends the first Hello and arms the retry
                            });
}

} // namespace Rhp::net

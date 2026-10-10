#include <algorithm>
#include <array>
#include <chrono>
#include <format>
#include <map>
#include <optional>
#include <tuple>

#include <asio/ip/multicast.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/ip/v6_only.hpp>
#if defined(RHP_PLATFORM_WINDOWS)
#include <iphlpapi.h>
#else
#include <ifaddrs.h>
#include <net/if.h>
#endif

#include <rhp/net/mdns/detail/dns.hpp>
#include <rhp/net/mdns/mdns.hpp>
#include <rhp/platform/random.hpp>

// Multicast DNS-SD without a system daemon (RFC 6762 / RFC 6763): a responder per advertisement
// (probe, announce, answer, goodbye) and a querier per browser (continuous query with backoff, a
// TTL cache, follow-up queries for missing SRV/TXT/address records).
namespace Rhp::net {

namespace {

using udp = asio::ip::udp;
using clock = std::chrono::steady_clock;
using detail::rr_type;
using std::chrono::milliseconds;

constexpr const char* kWhere = "net.mdns_wire";
constexpr std::uint32_t kTtl = 120;
constexpr unsigned kProbes = 3; // RFC 6762 §8.1
constexpr milliseconds kProbeInterval{250};
constexpr unsigned kAnnouncements = 2; // RFC 6762 §8.3
constexpr milliseconds kAnnounceInterval{1000};
constexpr milliseconds kFirstQueryInterval{1000}; // RFC 6762 §5.2: at least 1 s, then doubling
constexpr milliseconds kMaxQueryInterval{60000};  // re-query well inside the 120 s record TTL
constexpr milliseconds kFollowUpInterval{100};
constexpr std::size_t kMaxCache = 1024;
constexpr unsigned kMaxFollowUps = 64; // per round of missing SRV/TXT/A/AAAA queries

[[nodiscard]] udp::endpoint group_v4() {
    return {asio::ip::address_v4{{224, 0, 0, 251}}, detail::kMdnsPort};
}

[[nodiscard]] udp::endpoint group_v6(unsigned scope) {
    return {asio::ip::address_v6{{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb}, scope}, detail::kMdnsPort};
}

[[nodiscard]] asio::io_context& context_of(io_context& io) {
    return *static_cast<asio::io_context*>(io.native_handle());
}

// Indices of the interfaces that can carry IPv6 multicast.
std::vector<unsigned> ipv6_interfaces() {
    std::vector<unsigned> indices;
#if defined(RHP_PLATFORM_WINDOWS)
    ULONG bytes = 16384;
    std::vector<std::byte> storage(bytes);
    constexpr ULONG kFlags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()); // Win32 fills POD records in this owned buffer
    auto status = GetAdaptersAddresses(AF_INET6, kFlags, nullptr, adapters, &bytes);
    if (status == ERROR_BUFFER_OVERFLOW && bytes <= 512 * 1024) {
        storage.resize(bytes);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
        status = GetAdaptersAddresses(AF_INET6, kFlags, nullptr, adapters, &bytes);
    }
    if (status == NO_ERROR) {
        for (auto* adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
            if (adapter->OperStatus == IfOperStatusUp && adapter->Ipv6IfIndex != 0) {
                indices.push_back(adapter->Ipv6IfIndex);
            }
        }
    }
#else
    ifaddrs* addresses = nullptr;
    if (getifaddrs(&addresses) == 0) {
        for (auto* address = addresses; address != nullptr; address = address->ifa_next) {
            if (address->ifa_addr != nullptr && address->ifa_addr->sa_family == AF_INET6 && (address->ifa_flags & IFF_UP) != 0 && (address->ifa_flags & IFF_MULTICAST) != 0) {
                indices.push_back(if_nametoindex(address->ifa_name));
            }
        }
        freeifaddrs(addresses);
    }
#endif
    std::ranges::sort(indices);
    indices.erase(std::unique(indices.begin(), indices.end()), indices.end());
    return indices;
}

// The link-local scope a publication is confined to (0 = every interface).
[[nodiscard]] unsigned long scope_of(std::string_view literal) {
    std::error_code ec;
    const auto address = asio::ip::make_address(literal, ec);
    return !ec && address.is_v6() && address.to_v6().is_link_local() ? address.to_v6().scope_id() : 0;
}

// ---- multicast endpoint ------------------------------------------------------------------------

// The two mDNS sockets (IPv4 224.0.0.251 and IPv6 ff02::fb on every usable interface), shared by
// the responder and the querier through CRTP: `Derived::on_packet(message, from)` gets each valid
// packet. Lives on the io_context thread; async operations hold it weakly.
template <class Derived>
class multicast_endpoint : public std::enable_shared_from_this<Derived> {
public:
    explicit multicast_endpoint(io_context& io) : io_(io), v4_(context_of(io)), v6_(context_of(io)) {}

    multicast_endpoint(const multicast_endpoint&) = delete;
    multicast_endpoint& operator=(const multicast_endpoint&) = delete;

    [[nodiscard]] result<void> open() {
        std::error_code ec;
        v4_.socket.open(udp::v4(), ec);
        if (!ec) {
            v4_.socket.set_option(udp::socket::reuse_address{true}, ec);
        }
        if (!ec) {
            v4_.socket.bind(udp::endpoint{udp::v4(), detail::kMdnsPort}, ec);
        }
        if (!ec) {
            v4_.socket.set_option(asio::ip::multicast::join_group{group_v4().address().to_v4()}, ec);
        }
        if (!ec) {
            v4_.socket.set_option(asio::ip::multicast::hops{255}, ec);
        }
        if (!ec) {
            v4_.socket.set_option(asio::ip::multicast::enable_loopback{true}, ec);
        }
        const auto v4_error = ec;
        if (ec) {
            std::error_code ignored;
            v4_.socket.close(ignored);
        } else {
            receive(v4_);
        }
        open_v6();
        if (!v4_.socket.is_open() && !v6_.socket.is_open()) {
            return fail(errc::kTransport, v4_error ? v4_error.message() : "no multicast interface is available", kWhere);
        }
        return {};
    }

    // Sends to every group this endpoint may use; `scope` limits IPv6 to one link (link-local publications).
    void send(utils::bytes_view packet) {
        if (closed_) {
            return;
        }
        const bool use_v4 = v4_.socket.is_open() && scope_ == 0;
        std::vector<udp::endpoint> v6_groups;
        if (v6_.socket.is_open()) {
            for (const auto index : interfaces_) {
                if (scope_ == 0 || scope_ == index) {
                    v6_groups.push_back(group_v6(index));
                }
            }
        }
        if (!use_v4 && v6_groups.empty()) {
            failure_ = make_error(errc::kTransport, "no multicast route for this publication", kWhere);
            return;
        }
        // Datagrams this small don't block; a full queue is loss that the next round repairs.
        std::error_code ignored;
        if (use_v4) {
            v4_.socket.send_to(asio::buffer(packet.data(), packet.size()), group_v4(), 0, ignored);
        }
        for (const auto& group : v6_groups) {
            v6_.socket.send_to(asio::buffer(packet.data(), packet.size()), group, 0, ignored);
        }
    }

    void close() noexcept {
        closed_ = true;
        std::error_code ignored;
        v4_.socket.close(ignored);
        v6_.socket.close(ignored);
    }

    [[nodiscard]] result<void> status() const { return failure_ ? result<void>{fail(*failure_)} : result<void>{}; }

protected:
    ~multicast_endpoint() = default;

    void confine_to(unsigned long scope) noexcept { scope_ = scope; }
    [[nodiscard]] unsigned long scope() const noexcept { return scope_; }
    [[nodiscard]] bool closed() const noexcept { return closed_; }
    void set_failure(error why) { failure_ = std::move(why); }
    void clear_failure() noexcept { failure_.reset(); }
    [[nodiscard]] bool failed() const noexcept { return failure_.has_value(); }

    io_context& io_;

private:
    struct channel {
        explicit channel(asio::io_context& io) : socket(io) {}
        udp::socket socket;
        std::array<std::byte, detail::kMaxDnsPacket + 1> buffer{}; // one receive is outstanding at a time
        udp::endpoint from;
    };

    void open_v6() {
        auto indices = ipv6_interfaces();
        if (indices.empty()) {
            return;
        }
        std::error_code ec;
        v6_.socket.open(udp::v6(), ec);
        if (!ec) {
            v6_.socket.set_option(asio::ip::v6_only{true}, ec);
        }
        if (!ec) {
            v6_.socket.set_option(udp::socket::reuse_address{true}, ec);
        }
        if (!ec) {
            v6_.socket.bind(udp::endpoint{udp::v6(), detail::kMdnsPort}, ec);
        }
        if (!ec) {
            v6_.socket.set_option(asio::ip::multicast::hops{255}, ec);
        }
        if (!ec) {
            for (const auto index : indices) {
                std::error_code join;
                v6_.socket.set_option(asio::ip::multicast::join_group{group_v6(0).address().to_v6(), index}, join);
                if (!join) {
                    interfaces_.push_back(index);
                }
            }
        }
        if (ec || interfaces_.empty()) {
            std::error_code ignored;
            v6_.socket.close(ignored); // IPv6 can be unavailable; IPv4 stays usable on its own
            interfaces_.clear();
        } else {
            receive(v6_);
        }
    }

    void receive(channel& from) {
        from.socket.async_receive_from(asio::buffer(from.buffer), from.from, [weak = this->weak_from_this(), source = &from](const std::error_code& ec, std::size_t n) {
            auto self = weak.lock();
            if (!self || self->closed_ || ec == asio::error::operation_aborted || !source->socket.is_open()) {
                return;
            }
            // Per-datagram errors (oversized packets, ICMP reports) don't end the endpoint.
            if (!ec && source->from.port() == detail::kMdnsPort) {
                if (auto message = detail::read_dns({source->buffer.data(), n})) {
                    self->on_packet(*message, source->from);
                }
            }
            if (!self->closed_) {
                self->receive(*source);
            }
        });
    }

    channel v4_;
    channel v6_;
    std::vector<unsigned> interfaces_;
    unsigned long scope_ = 0;
    std::optional<error> failure_;
    bool closed_ = false;
};

// ---- responder -------------------------------------------------------------------------------

using record_set = std::vector<std::pair<std::uint16_t, std::string>>; // (type, canonical RDATA)

//   kResolving ──> kProbing (3 × 250 ms) ──> kAnnouncing (2 × 1 s) ──> kAnswering
//                       └── conflict ──> failed (status() reports kAlreadyLoaded until update())
class responder final : public multicast_endpoint<responder> {
public:
    explicit responder(io_context& io) : multicast_endpoint(io), timer_(io) {}

    [[nodiscard]] result<void> start(service_record record) {
        if (auto ok = validate(record); !ok) {
            return ok;
        }
        if (auto ok = open(); !ok) {
            return ok;
        }
        publish(std::move(record));
        return {};
    }

    [[nodiscard]] result<void> update(service_record record) {
        if (auto ok = validate(record); !ok) {
            return ok;
        }
        const bool renamed = !record_ || record.name != record_->name || detail::normalized(record).host != record_->host;
        const bool keep_names = published_ && !failed() && !renamed;
        if (published_ && renamed) {
            goodbye(); // the old names are released before the new ones are probed
        }
        clear_failure();
        publish(std::move(record), keep_names);
        return status();
    }

    void stop() noexcept {
        try {
            if (!closed() && published_ && !failed()) {
                goodbye();
            }
        } catch (...) {
        }
        timer_.cancel();
        close();
    }

    void on_packet(const detail::dns_message& message, const udp::endpoint& from) {
        if (!record_ || failed() || phase_ == phase::kResolving) {
            return;
        }
        const bool same_link = scope() == 0 || (from.address().is_v6() && from.address().to_v6().scope_id() == scope());
        if (same_link) {
            check_conflicts(message);
        }
        if (failed() || message.response || phase_ == phase::kProbing) {
            return;
        }
        const auto instance = detail::instance_domain(*record_);
        const auto type = detail::service_domain(record_->transport);
        if (std::ranges::any_of(message.questions, [&](const auto& q) { return q.first == type || q.first == instance || q.first == record_->host; })) {
            announce(kTtl);
        }
    }

private:
    enum class phase : std::uint8_t {
        kResolving,
        kProbing,
        kAnnouncing,
        kAnswering
    };

    [[nodiscard]] static result<void> validate(const service_record& record) {
        auto fields = detail::service_txt(detail::normalized(record));
        return fields ? result<void>{} : result<void>{fail(std::move(fields).error())};
    }

    // Starts the publication; host-name listen addresses are resolved off the I/O thread first.
    // `keep_names`: the names were already probed and are unchanged, so only the data is announced.
    void publish(service_record record, bool keep_names = false) {
        ++generation_;
        published_ = keep_names;
        record_.reset();
        phase_ = phase::kResolving;
        std::error_code ec;
        (void)asio::ip::make_address(record.address, ec);
        if (!ec || record.address == "localhost") {
            resolved(std::move(record), keep_names);
            return;
        }
        auto resolver = std::make_shared<asio::ip::tcp::resolver>(context_of(io_));
        resolver->async_resolve(record.address, "0", [weak = weak_from_this(), resolver, generation = generation_, keep_names, record = std::move(record)](const std::error_code& error, const asio::ip::tcp::resolver::results_type& found) mutable {
            auto self = weak.lock();
            if (!self || self->closed() || generation != self->generation_) {
                return;
            }
            if (error || found.empty()) {
                self->set_failure(make_error(errc::kTransport, std::format("can't resolve {} for discovery", record.address), kWhere));
                return;
            }
            // Prefer an IPv4 address other people can reach.
            const auto chosen = std::ranges::find_if(found, [](const auto& entry) { return entry.endpoint().address().is_v4() && !entry.endpoint().address().is_loopback(); });
            record.address = (chosen == found.end() ? found.begin() : chosen)->endpoint().address().to_string();
            self->resolved(std::move(record), keep_names);
        });
    }

    void resolved(service_record record, bool keep_names) {
        auto ready = detail::resolve_service_record(io_, std::move(record));
        if (!ready) {
            set_failure(std::move(ready).error());
            return;
        }
        auto probe = detail::dns_service_packet(*ready, kTtl, true);
        auto own = probe ? detail::read_dns(probe->view()) : result<detail::dns_message>{std::unexpected{probe.error()}};
        if (!own) {
            set_failure(std::move(own).error());
            return;
        }
        own_ = std::move(own->records);
        confine_to(scope_of(ready->address));
        record_ = std::move(*ready);
        count_ = 0;
        if (keep_names) {
            phase_ = phase::kAnnouncing;
            advance();
            return;
        }
        phase_ = phase::kProbing;
        // RFC 6762 §8.1: a random 0-250 ms delay before the first probe.
        const auto jitter = platform::random_array<1>();
        step(milliseconds{jitter ? std::to_integer<unsigned>((*jitter)[0]) % 251 : 0});
    }

    void step(milliseconds delay) {
        timer_.start(delay, [weak = weak_from_this(), generation = generation_] {
            if (auto self = weak.lock(); self && generation == self->generation_) {
                self->advance();
            }
        });
    }

    void advance() {
        if (closed() || failed() || !record_) {
            return;
        }
        if (phase_ == phase::kProbing) {
            if (count_ < kProbes) {
                ++count_;
                send_records(kTtl, true);
                step(kProbeInterval);
                return;
            }
            phase_ = phase::kAnnouncing;
            count_ = 0;
            published_ = true;
        }
        if (phase_ == phase::kAnnouncing) {
            announce(kTtl);
            if (++count_ < kAnnouncements) {
                step(kAnnounceInterval);
            } else {
                phase_ = phase::kAnswering; // from here on only queries trigger answers (RFC 6762 §8.3)
            }
        }
    }

    void announce(std::uint32_t ttl) { send_records(ttl, false); }

    void goodbye() {
        announce(0); // TTL 0 removes the records from every cache (RFC 6762 §10.1)
        published_ = false;
    }

    void send_records(std::uint32_t ttl, bool probe) {
        auto packet = detail::dns_service_packet(*record_, ttl, probe);
        if (!packet) {
            set_failure(std::move(packet).error());
            return;
        }
        send(packet->view());
    }

    // RFC 6762 §8.2 and §9: another host's answer with different data for our names is a conflict;
    // during probing, simultaneous probes are broken by comparing the proposed records.
    void check_conflicts(const detail::dns_message& message) {
        if (phase_ == phase::kProbing && count_ == 0) {
            return; // nothing sent yet
        }
        for (const auto& owner : {detail::instance_domain(*record_), record_->host}) {
            const auto ours = records_of(own_, owner);
            record_set theirs;
            for (const auto& rr : message.records) {
                if (rr.name != owner || rr.ttl == 0 || rr.unique_data.empty()) {
                    continue;
                }
                if (message.response) {
                    if (std::ranges::any_of(ours, [&](const auto& own) { return own.first == rr.type && own.second != rr.unique_data; })) {
                        set_failure(make_error(errc::kAlreadyLoaded, "DNS-SD name is already in use", kWhere));
                        return;
                    }
                } else {
                    theirs.emplace_back(rr.type, rr.unique_data);
                }
            }
            std::ranges::sort(theirs);
            if (!message.response && phase_ == phase::kProbing && !theirs.empty() && theirs > ours) {
                set_failure(make_error(errc::kAlreadyLoaded, "DNS-SD probe lost a name conflict", kWhere));
                return;
            }
        }
    }

    [[nodiscard]] static record_set records_of(const std::vector<detail::dns_record>& records, std::string_view owner) {
        record_set out;
        for (const auto& rr : records) {
            if (rr.name == owner && !rr.unique_data.empty()) {
                out.emplace_back(rr.type, rr.unique_data);
            }
        }
        std::ranges::sort(out);
        return out;
    }

    std::optional<service_record> record_; // resolved and normalized
    std::vector<detail::dns_record> own_;  // the records we probe for
    io_context::timer timer_;
    phase phase_ = phase::kResolving;
    unsigned count_ = 0;
    std::uint64_t generation_ = 0; // invalidates timers and resolutions of a replaced record
    bool published_ = false;       // probed: a goodbye is owed
};

// ---- querier -----------------------------------------------------------------------------------

class querier final : public multicast_endpoint<querier> {
public:
    querier(io_context& io, browse_options filter) : multicast_endpoint(io), filter_(std::move(filter)), query_timer_(io), follow_up_timer_(io) {}

    [[nodiscard]] result<void> start() {
        if (auto ok = open(); !ok) {
            return ok;
        }
        query();
        return {};
    }

    void stop() noexcept {
        query_timer_.cancel();
        follow_up_timer_.cancel();
        close();
    }

    void on_packet(detail::dns_message& message, const udp::endpoint& from) {
        if (!message.response) {
            return;
        }
        const auto now = clock::now();
        for (auto& record : message.records) {
            if (record.is(rr_type::kAaaa) && !scope_link_local(record, from)) {
                continue;
            }
            const auto key = cache_key{record.name, record.type, record.is(rr_type::kPtr) ? record.target : std::string{}};
            if (record.ttl == 0) {
                cache_.erase(key);
            } else if (cache_.contains(key) || cache_.size() < kMaxCache) {
                const auto ttl = std::chrono::seconds{std::min(record.ttl, kTtl)};
                cache_[key] = {std::move(record), now + ttl};
            }
        }
        follow_up();
    }

    [[nodiscard]] std::vector<service_record> services() const {
        std::vector<service_record> out;
        const auto now = clock::now();
        const auto type = filter_.service + ".local";
        const auto live = [&](const auto& it) { return it != cache_.end() && it->second.expires > now; };
        for (const auto& [key, cached] : cache_) {
            const auto& [owner, kind, target] = key;
            if (kind != static_cast<std::uint16_t>(rr_type::kSrv) || !owner.ends_with("." + type) || cached.expires <= now) {
                continue;
            }
            const auto& srv = cached.record;
            const auto ptr = cache_.find({type, static_cast<std::uint16_t>(rr_type::kPtr), srv.name});
            const auto txt = cache_.find({srv.name, static_cast<std::uint16_t>(rr_type::kTxt), ""});
            auto ip = cache_.find({srv.target, static_cast<std::uint16_t>(rr_type::kA), ""});
            if (!live(ip)) {
                ip = cache_.find({srv.target, static_cast<std::uint16_t>(rr_type::kAaaa), ""});
            }
            if (!live(ptr) || !live(txt) || !live(ip)) {
                continue;
            }
            service_record service;
            service.name = srv.name.substr(0, srv.name.size() - type.size() - 1);
            service.host = srv.target;
            service.address = ip->second.record.address;
            service.port = srv.port;
            if (auto ok = detail::read_service_txt(service, txt->second.record.txt); ok && detail::matches(service, filter_)) {
                out.push_back(std::move(service));
            }
        }
        return out;
    }

private:
    using cache_key = std::tuple<std::string, std::uint16_t, std::string>; // owner, type, PTR target
    struct cached_record {
        detail::dns_record record;
        clock::time_point expires;
    };

    // A link-local AAAA is only usable with the interface it arrived on.
    [[nodiscard]] static bool scope_link_local(detail::dns_record& record, const udp::endpoint& from) {
        std::error_code ec;
        const auto address = asio::ip::make_address_v6(record.address, ec);
        if (ec || !address.is_link_local()) {
            return true;
        }
        if (!from.address().is_v6() || from.address().to_v6().scope_id() == 0) {
            return false; // arrived over IPv4: no interface scope to attach
        }
        record.address = asio::ip::address_v6{address.to_bytes(), from.address().to_v6().scope_id()}.to_string();
        return true;
    }

    // Continuous querying (RFC 6762 §5.2): 1 s, then doubling to a minute.
    void query() {
        if (closed()) {
            return;
        }
        std::erase_if(cache_, [now = clock::now()](const auto& item) { return item.second.expires <= now; });
        send(detail::dns_query(filter_.service).view());
        follow_up();
        query_timer_.start(interval_, [weak = weak_from_this()] {
            if (auto self = weak.lock()) {
                self->query();
            }
        });
        interval_ = std::min(interval_ * 2, kMaxQueryInterval);
    }

    // Asks for the SRV/TXT of each known instance and the addresses of each known target.
    void follow_up() {
        if (closed()) {
            return;
        }
        const auto service = filter_.service + ".local";
        const auto missing = [&](const std::string& owner, rr_type type) { return !cache_.contains({owner, static_cast<std::uint16_t>(type), ""}); };
        unsigned sent = 0;
        for (const auto& [key, cached] : cache_) {
            if (sent >= kMaxFollowUps) {
                break;
            }
            const auto& [owner, type, target] = key;
            if (type == static_cast<std::uint16_t>(rr_type::kPtr) && owner == service) {
                for (const auto kind : {rr_type::kSrv, rr_type::kTxt}) {
                    if (missing(target, kind)) {
                        send(detail::dns_query(target, kind).view());
                        ++sent;
                    }
                }
            } else if (type == static_cast<std::uint16_t>(rr_type::kSrv) && missing(cached.record.target, rr_type::kA) && missing(cached.record.target, rr_type::kAaaa)) {
                send(detail::dns_query(cached.record.target, rr_type::kA).view());
                send(detail::dns_query(cached.record.target, rr_type::kAaaa).view());
                sent += 2;
            }
        }
        if (sent != 0) {
            follow_up_timer_.start(kFollowUpInterval, [weak = weak_from_this()] {
                if (auto self = weak.lock()) {
                    self->follow_up();
                }
            });
        }
    }

    browse_options filter_;
    std::map<cache_key, cached_record> cache_;
    io_context::timer query_timer_;
    io_context::timer follow_up_timer_;
    milliseconds interval_ = kFirstQueryInterval;
};

// ---- public handles ----------------------------------------------------------------------------

class wire_advertisement final : public advertisement {
public:
    explicit wire_advertisement(std::shared_ptr<responder> state) : state_(std::move(state)) {}
    ~wire_advertisement() override { state_->stop(); }

    result<void> update(service_record record) override { return state_->update(std::move(record)); }
    [[nodiscard]] result<void> status() const override { return state_->status(); }

private:
    std::shared_ptr<responder> state_;
};

class wire_browser final : public discovery_browser {
public:
    explicit wire_browser(std::shared_ptr<querier> state) : state_(std::move(state)) {}
    ~wire_browser() override { state_->stop(); }

    [[nodiscard]] result<std::vector<service_record>> services() const override {
        if (auto ok = state_->status(); !ok) {
            return std::unexpected{std::move(ok).error()};
        }
        return state_->services();
    }

private:
    std::shared_ptr<querier> state_;
};

} // namespace

namespace detail {

result<service_record> resolve_service_record(io_context& io, service_record record) {
    record = normalized(std::move(record));
    std::error_code ec;
    auto address = record.address == "localhost" ? asio::ip::address{asio::ip::address_v4::loopback()} : asio::ip::make_address(record.address, ec);
    if (ec) {
        return fail(errc::kInvalidArgument, std::format("{} is not a literal address: discovery publishes addresses, not names", record.address), kWhere);
    }
    if (address.is_unspecified()) {
        // A wildcard listener: publish the address of the interface that routes to the mDNS group.
        // connect() on a UDP socket only picks a route; nothing is sent.
        udp::socket route{context_of(io)};
        route.open(address.is_v4() ? udp::v4() : udp::v6(), ec);
        if (!ec && address.is_v4()) {
            route.connect(group_v4(), ec);
        } else if (!ec) {
            ec = asio::error::network_unreachable;
            for (const auto index : ipv6_interfaces()) {
                route.connect(group_v6(index), ec);
                if (!ec) {
                    break;
                }
            }
        }
        if (ec) {
            return fail(errc::kTransport, "no multicast route for the listener's address family", kWhere);
        }
        address = route.local_endpoint(ec).address();
    }
    if (ec || address.is_unspecified() || (address.is_v6() && address.to_v6().is_link_local() && address.to_v6().scope_id() == 0)) {
        return fail(errc::kInvalidArgument, "DNS-SD needs a usable local address with its IPv6 scope", kWhere);
    }
    record.address = address.to_string();
    if (auto packet = dns_service_packet(record, kTtl); !packet) {
        return std::unexpected{std::move(packet).error()};
    }
    return record;
}

} // namespace detail

result<std::unique_ptr<advertisement>> mdns_wire::advertise(io_context& io, service_record record) {
    auto state = std::make_shared<responder>(io);
    if (auto ok = state->start(std::move(record)); !ok) {
        state->stop();
        return std::unexpected{std::move(ok).error()};
    }
    return std::make_unique<wire_advertisement>(std::move(state));
}

result<std::unique_ptr<discovery_browser>> mdns_wire::start_browse(io_context& io, const browse_options& options) {
    if (!detail::supported_service(options.service)) {
        return fail(errc::kInvalidArgument, "discovery supports _rhp._tcp and _rhp._udp", kWhere);
    }
    auto state = std::make_shared<querier>(io, options);
    if (auto ok = state->start(); !ok) {
        state->stop();
        return std::unexpected{std::move(ok).error()};
    }
    return std::make_unique<wire_browser>(std::move(state));
}

} // namespace Rhp::net

#include <algorithm>

#include <asio/ip/address.hpp>

#include <rhp/net/mdns/detail/dns.hpp>

namespace Rhp::net::detail {

namespace {

void put(utils::byte_buffer& out, std::uint64_t n, unsigned width) {
    for (unsigned i = width; i != 0; --i) {
        const auto b = static_cast<std::byte>(n >> (8 * (i - 1)));
        out.append({&b, 1});
    }
}

void name(utils::byte_buffer& out, std::string_view text) {
    while (!text.empty()) {
        const auto dot = text.find('.');
        const auto label = text.substr(0, dot);
        put(out, label.size(), 1);
        out.append(label);
        if (dot == std::string_view::npos) {
            break;
        }
        text.remove_prefix(dot + 1);
    }
    put(out, 0, 1);
}

struct reader {
    utils::bytes_view input;
    std::size_t at = 0;
    bool good = true;
    std::uint64_t take(unsigned width) {
        if (at > input.size() || input.size() - at < width) {
            good = false;
            return 0;
        }
        std::uint64_t out = 0;
        for (unsigned i = 0; i < width; ++i) {
            out = (out << 8) | std::to_integer<unsigned>(input[at++]);
        }
        return out;
    }
    std::string name() {
        std::string out;
        std::size_t pos = at;
        bool jumped = false;
        for (unsigned hops = 0; hops < 128; ++hops) {
            if (pos >= input.size()) {
                break;
            }
            const auto n = std::to_integer<unsigned>(input[pos++]);
            if ((n & 0xc0) == 0xc0) {
                if (pos >= input.size()) {
                    break;
                }
                const auto pointer = ((n & 63) << 8) | std::to_integer<unsigned>(input[pos++]);
                if (!jumped) {
                    at = pos;
                    jumped = true;
                }
                // DNS compression may only point to previously encoded names.
                if (pointer >= pos - 2) {
                    break;
                }
                pos = pointer;
                continue;
            }
            if (n > 63 || n > input.size() - pos || out.size() + n + 1 > 254) {
                break;
            }
            if (n == 0) {
                if (!jumped) {
                    at = pos;
                }
                return out;
            }
            if (!out.empty()) {
                out += '.';
            }
            for (unsigned i = 0; i < n; ++i) {
                const auto c = std::to_integer<unsigned char>(input[pos++]);
                if (c == 0 || c == '.') {
                    good = false;
                    return {};
                }
                out += static_cast<char>(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
            }
        }
        good = false;
        return {};
    }
};

constexpr std::uint16_t kClassIn = 1;
constexpr std::uint16_t kCacheFlush = 0x8000; // unique records replace cached copies (RFC 6762 §10.2)

[[nodiscard]] constexpr std::uint16_t code(rr_type type) noexcept {
    return static_cast<std::uint16_t>(type);
}

void record(utils::byte_buffer& out, std::string_view owner, rr_type type, std::uint32_t ttl, const utils::byte_buffer& data) {
    name(out, owner);
    put(out, code(type), 2);
    put(out, type == rr_type::kPtr ? kClassIn : kClassIn | kCacheFlush, 2); // PTR records are shared
    put(out, ttl, 4);
    put(out, data.size(), 2);
    out.append(data.view());
}

} // namespace

result<dns_message> read_dns(utils::bytes_view packet) {
    if (packet.size() < 12 || packet.size() > kMaxDnsPacket) {
        return fail(errc::kProtocol, "invalid mDNS packet size", "net.mdns");
    }
    reader r{packet};
    (void)r.take(2);
    const auto flags = r.take(2);
    const auto questions = r.take(2);
    const auto records = r.take(2) + r.take(2) + r.take(2);
    if ((flags & 0x780f) != 0 || questions + records > kMaxDnsEntries) {
        return fail(errc::kProtocol, "invalid mDNS flags or record count", "net.mdns");
    }
    dns_message out;
    out.response = (flags & 0x8000) != 0;
    for (std::uint64_t i = 0; i < questions && r.good; ++i) {
        auto query = r.name();
        const auto type = static_cast<std::uint16_t>(r.take(2));
        (void)r.take(2);
        out.questions.emplace_back(std::move(query), type);
    }
    for (std::uint64_t i = 0; i < records && r.good; ++i) {
        dns_record entry;
        entry.name = r.name();
        entry.type = static_cast<std::uint16_t>(r.take(2));
        const auto klass = r.take(2) & 0x7fff;
        entry.ttl = static_cast<std::uint32_t>(r.take(4));
        const auto bytes = static_cast<std::size_t>(r.take(2));
        if (!r.good || r.at > packet.size() || bytes > packet.size() - r.at) {
            r.good = false;
            break;
        }
        const auto end = r.at + bytes;
        const auto begin = r.at;
        if (klass == kClassIn && entry.is(rr_type::kPtr)) {
            entry.target = r.name();
        } else if (klass == kClassIn && entry.is(rr_type::kSrv)) {
            const auto priority = r.take(2);
            const auto weight = r.take(2);
            entry.port = static_cast<std::uint16_t>(r.take(2));
            entry.target = r.name();
            utils::byte_buffer canonical;
            put(canonical, priority, 2);
            put(canonical, weight, 2);
            put(canonical, entry.port, 2);
            name(canonical, entry.target);
            entry.unique_data.assign(reinterpret_cast<const char*>(canonical.view().data()), canonical.size());
        } else if (klass == kClassIn && entry.is(rr_type::kTxt)) {
            while (r.good && r.at < end) {
                const auto n = r.take(1);
                if (n > end - r.at || entry.txt.size() >= 64) {
                    r.good = false;
                    break;
                }
                const std::string_view text{reinterpret_cast<const char*>(packet.data() + r.at), static_cast<std::size_t>(n)};
                const auto equal = text.find('=');
                if (equal != std::string_view::npos) {
                    entry.txt.emplace_back(text.substr(0, equal), text.substr(equal + 1));
                }
                r.at += static_cast<std::size_t>(n);
            }
        } else if (klass == kClassIn && entry.is(rr_type::kA) && bytes == 4) {
            asio::ip::address_v4::bytes_type address{};
            for (auto& b : address) {
                b = static_cast<unsigned char>(r.take(1));
            }
            entry.address = asio::ip::address_v4{address}.to_string();
        } else if (klass == kClassIn && entry.is(rr_type::kAaaa) && bytes == 16) {
            asio::ip::address_v6::bytes_type address{};
            for (auto& b : address) {
                b = static_cast<unsigned char>(r.take(1));
            }
            entry.address = asio::ip::address_v6{address}.to_string();
        }
        if (r.at > end) {
            r.good = false;
        }
        if (klass == kClassIn && (entry.is(rr_type::kTxt) || (entry.is(rr_type::kA) && bytes == 4) || (entry.is(rr_type::kAaaa) && bytes == 16))) {
            entry.unique_data.assign(reinterpret_cast<const char*>(packet.data() + begin), bytes);
        }
        r.at = end;
        if (klass == kClassIn) {
            out.records.push_back(std::move(entry));
        }
    }
    if (!r.good || r.at != packet.size()) {
        return fail(errc::kProtocol, "malformed mDNS record or compressed name", "net.mdns");
    }
    return out;
}

utils::byte_buffer dns_query(std::string_view owner, rr_type type) {
    utils::byte_buffer out;
    put(out, 0, 4);
    put(out, 1, 2);
    put(out, 0, 6);
    name(out, owner.ends_with(".local") ? std::string{owner} : std::string{owner} + ".local");
    put(out, code(type), 2);
    put(out, kClassIn, 2);
    return out;
}

result<utils::byte_buffer> dns_service_packet(const service_record& service, std::uint32_t ttl, bool probe,
                                              std::span<const std::pair<std::string, std::uint16_t>> asked) {
    auto txt = service_txt(service);
    if (!txt) {
        return std::unexpected{std::move(txt).error()};
    }
    std::error_code ec;
    const auto address = asio::ip::make_address(service.address, ec);
    bool valid_host = !service.host.empty() && service.host.size() <= 200 && service.host.find('\0') == std::string::npos;
    auto rest = std::string_view{service.host};
    while (valid_host && !rest.empty()) {
        const auto dot = rest.find('.');
        const auto label = rest.substr(0, dot);
        valid_host = !label.empty() && label.size() <= 63;
        if (dot == std::string_view::npos) {
            break;
        }
        rest.remove_prefix(dot + 1);
        valid_host = valid_host && !rest.empty();
    }
    if (ec || !valid_host) {
        return fail(errc::kInvalidArgument, "DNS-SD needs a literal address and local hostname", "net.mdns");
    }
    const auto type = service_domain(service.transport);
    const auto instance = instance_domain(service);
    // Every record's owner, type and data; the probe leaves out the PTR (its questions come first).
    struct entry {
        std::string_view owner;
        rr_type type;
        utils::byte_buffer data;
    };
    std::vector<entry> records;
    records.reserve(4);
    if (!probe) {
        utils::byte_buffer ptr;
        name(ptr, instance);
        records.push_back({type, rr_type::kPtr, std::move(ptr)});
    }
    utils::byte_buffer srv;
    put(srv, 0, 4);
    put(srv, service.port, 2);
    name(srv, service.host);
    records.push_back({instance, rr_type::kSrv, std::move(srv)});
    utils::byte_buffer text;
    for (const auto& [key, value] : *txt) {
        const auto field = key + "=" + value;
        put(text, field.size(), 1);
        text.append(field);
    }
    records.push_back({instance, rr_type::kTxt, std::move(text)});
    utils::byte_buffer ip;
    if (address.is_v4()) {
        const auto bytes = address.to_v4().to_bytes();
        ip.append(std::as_bytes(std::span{bytes}));
    } else {
        const auto bytes = address.to_v6().to_bytes();
        ip.append(std::as_bytes(std::span{bytes}));
    }
    records.push_back({service.host, address.is_v4() ? rr_type::kA : rr_type::kAaaa, std::move(ip)});

    // Without questions every record is an answer (announcements, probes' authority section).
    const auto answers = [&](const entry& e) {
        return asked.empty() || std::ranges::any_of(asked, [&](const auto& q) {
                   return q.first == e.owner && (q.second == code(e.type) || q.second == code(rr_type::kAny));
               });
    };
    const auto answered = static_cast<std::size_t>(std::ranges::count_if(records, answers));
    utils::byte_buffer out;
    put(out, 0, 2);
    put(out, probe ? 0 : 0x8400, 2);
    put(out, probe ? 2 : 0, 2);
    put(out, probe ? 0 : answered, 2);
    put(out, probe ? records.size() : 0, 2);
    put(out, probe ? 0 : records.size() - answered, 2);
    if (probe) {
        for (const auto& owner : {instance, service.host}) {
            name(out, owner);
            put(out, code(rr_type::kAny), 2);
            put(out, kClassIn, 2);
        }
    }
    for (const bool answer : {true, false}) {
        for (const auto& e : records) {
            if (probe || answers(e) == answer) {
                if (!probe || answer) {
                    record(out, e.owner, e.type, ttl, e.data);
                }
            }
        }
    }
    return out;
}

} // namespace Rhp::net::detail

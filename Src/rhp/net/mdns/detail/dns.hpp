#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/net/mdns/detail/metadata.hpp>
#include <rhp/utils/byte_buffer.hpp>

// Sans-IO DNS message codec for the multicast DNS-SD provider (RFC 1035 section 4, RFC 6762).
namespace Rhp::net::detail {

// Record types this codec understands; others are parsed past and kept with their raw type.
enum class rr_type : std::uint16_t {
    kA = 1,
    kPtr = 12,
    kTxt = 16,
    kAaaa = 28,
    kSrv = 33,
    kAny = 255
};

inline constexpr std::size_t kMaxDnsPacket = 9000; // the mDNS ceiling (RFC 6762 section 17)
inline constexpr std::size_t kMaxDnsEntries = 128; // questions + records per packet
inline constexpr std::uint16_t kMdnsPort = 5353;

struct dns_record {
    std::string name;
    std::uint16_t type = 0;
    std::uint32_t ttl = 0;
    std::string target;
    std::uint16_t port = 0;
    txt_fields txt;
    std::string address;
    std::string unique_data; // canonical uncompressed RDATA for probing and conflict checks

    [[nodiscard]] bool is(rr_type t) const noexcept { return type == static_cast<std::uint16_t>(t); }
};

struct dns_message {
    bool response = false;
    std::vector<std::pair<std::string, std::uint16_t>> questions;
    std::vector<dns_record> records;
};

[[nodiscard]] result<dns_message> read_dns(utils::bytes_view packet);
// An announcement (PTR, SRV, TXT, A/AAAA) or, with `probe`, the RFC 6762 section 8.1 probe for the
// instance and host names. `record.address` must be a literal.
[[nodiscard]] result<utils::byte_buffer> dns_service_packet(const service_record& record, std::uint32_t ttl, bool probe = false);
// A one-question query; ".local" is appended to `owner` when missing.
[[nodiscard]] utils::byte_buffer dns_query(std::string_view owner, rr_type type = rr_type::kPtr);

} // namespace Rhp::net::detail

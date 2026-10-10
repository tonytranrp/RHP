#include <algorithm>
#include <charconv>
#include <set>

#include <rhp/net/mdns/detail/metadata.hpp>

namespace Rhp::net::detail {

namespace {

constexpr std::string_view kStreamService = "_rhp._tcp";
constexpr std::string_view kDatagramService = "_rhp._udp";
constexpr std::string_view kInstanceChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
constexpr std::size_t kMaxLabel = 63;      // DNS label (RFC 1035)
constexpr std::size_t kMaxTxtItem = 255;   // one TXT string (RFC 6763 §6.1)
constexpr std::size_t kMaxTxtTotal = 1200; // keeps the whole answer in one 1500-byte packet (RFC 6763 §6.2)
constexpr std::size_t kMaxLibs = 32;

void lowercase(std::string& text) noexcept {
    std::ranges::transform(text, text.begin(), [](char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c; });
}

// "lib0" .. "lib31": the library list, published only with advertise_options::include_libs.
[[nodiscard]] bool is_lib_key(std::string_view key) noexcept {
    return key.size() > 3 && key.starts_with("lib") && std::ranges::all_of(key.substr(3), [](char c) { return c >= '0' && c <= '9'; });
}

} // namespace

std::string_view service_type(std::string_view transport) noexcept {
    return dns_sd_service(transport);
}

std::string service_domain(std::string_view transport) {
    return std::string{service_type(transport)} + ".local";
}

std::string instance_domain(const service_record& record) {
    return record.name + "." + service_domain(record.transport);
}

bool supported_service(std::string_view service) noexcept {
    return service == kStreamService || service == kDatagramService;
}

service_record normalized(service_record record) {
    if (record.host.empty()) {
        record.host = record.name + ".rhp.local";
    }
    lowercase(record.name);
    lowercase(record.host);
    if (record.host.ends_with('.')) {
        record.host.pop_back();
    }
    return record;
}

result<txt_fields> service_txt(const service_record& record) {
    if (record.name.empty() || record.name.size() > kMaxLabel || record.name.find_first_not_of(kInstanceChars) != std::string::npos || record.port == 0 ||
        record.protocol_revision == 0 || record.libs.size() > kMaxLibs) {
        return fail(errc::kInvalidArgument, "invalid DNS-SD instance, port, revision or library count", "net.mdns");
    }
    txt_fields fields{{"host", record.host}, {"platform", record.platform}, {"protocol_rev", std::to_string(record.protocol_revision)}, {"app", record.app}, {"build", record.build}, {"transport", record.transport}};
    for (std::size_t i = 0; i < record.libs.size(); ++i) {
        fields.emplace_back("lib" + std::to_string(i), record.libs[i]);
    }
    std::size_t total = 0;
    for (const auto& [key, value] : fields) {
        if (key.size() + value.size() + 1 > kMaxTxtItem || value.find('\0') != std::string::npos) {
            return fail(errc::kLimitExceeded, "DNS-SD TXT item exceeds 255 bytes or contains NUL", "net.mdns");
        }
        total += key.size() + value.size() + 2;
    }
    if (total > kMaxTxtTotal) {
        return fail(errc::kLimitExceeded, "DNS-SD TXT record exceeds 1200 bytes", "net.mdns");
    }
    return fields;
}

result<void> read_service_txt(service_record& record, const txt_fields& fields) {
    std::set<std::string> seen;
    record.libs.clear();
    for (const auto& [key, value] : fields) {
        if (!seen.insert(key).second || key.size() + value.size() + 1 > kMaxTxtItem) {
            return fail(errc::kProtocol, "duplicate or excessive DNS-SD TXT item", "net.mdns");
        }
        if (key == "host") {
            record.host = value;
        } else if (key == "platform") {
            record.platform = value;
        } else if (key == "app") {
            record.app = value;
        } else if (key == "build") {
            record.build = value;
        } else if (key == "transport") {
            record.transport = value;
        } else if (key == "protocol_rev") {
            unsigned n = 0;
            const auto [at, ec] = std::from_chars(value.data(), value.data() + value.size(), n);
            if (ec != std::errc{} || at != value.data() + value.size() || n == 0 || n > 255) {
                return fail(errc::kProtocol, "invalid DNS-SD protocol revision", "net.mdns");
            }
            record.protocol_revision = static_cast<std::uint8_t>(n);
        } else if (is_lib_key(key) && record.libs.size() < kMaxLibs) {
            record.libs.push_back(value);
        }
    }
    if (!seen.contains("protocol_rev") || !seen.contains("transport") || record.port == 0 || record.address.empty()) {
        return fail(errc::kProtocol, "incomplete DNS-SD service", "net.mdns");
    }
    return {};
}

bool matches(const service_record& record, const browse_options& options) {
    return (options.protocol_revision == 0 || record.protocol_revision == options.protocol_revision) &&
           (options.app.empty() || record.app == options.app) && (options.build.empty() || record.build == options.build) &&
           (options.platform.empty() || record.platform == options.platform) &&
           std::ranges::all_of(options.libs, [&](const auto& lib) { return std::ranges::find(record.libs, lib) != record.libs.end(); });
}

} // namespace Rhp::net::detail

#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/net/discovery.hpp>

// Mapping between service_record and its DNS-SD form, shared by the native and wire providers.
namespace Rhp::net::detail {

// "_rhp._udp" for reliable UDP, "_rhp._tcp" for every stream transport.
[[nodiscard]] std::string_view service_type(std::string_view transport) noexcept;
// The service type with the mDNS domain: "_rhp._tcp.local".
[[nodiscard]] std::string service_domain(std::string_view transport);
// "<instance>._rhp._tcp.local"
[[nodiscard]] std::string instance_domain(const service_record& record);
[[nodiscard]] bool supported_service(std::string_view service) noexcept;

// Lowercases the instance and host names, drops a trailing dot, and names the host
// "<instance>.rhp.local" when the caller left it empty. The address is left as given.
[[nodiscard]] service_record normalized(service_record record);

// normalized(), then the address a record can publish: a literal stays, "localhost" is 127.0.0.1,
// and a wildcard ("0.0.0.0", "::") becomes the interface address that routes to the mDNS group.
// Host names are refused (kInvalidArgument): resolving them would block the I/O thread, so the
// wire provider resolves them asynchronously first.
[[nodiscard]] result<service_record> resolve_service_record(io_context& io, service_record record);

using txt_fields = std::vector<std::pair<std::string, std::string>>;
[[nodiscard]] result<txt_fields> service_txt(const service_record& record);
[[nodiscard]] result<void> read_service_txt(service_record& record, const txt_fields& fields);
[[nodiscard]] bool matches(const service_record& record, const browse_options& options);

} // namespace Rhp::net::detail

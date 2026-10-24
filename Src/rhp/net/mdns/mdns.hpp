#pragma once

#include <rhp/build_config.hpp>
#include <rhp/net/discovery.hpp>

namespace Rhp::net {

// DNS-SD through the platform where it can (Windows DNS-SD API, Apple dns_sd), the multicast
// responder (mdns_wire) elsewhere and for listeners bound to one address on Windows.
struct mdns {
    static constexpr std::string_view name = "mdns";
#if RHP_ENABLE
    static result<std::unique_ptr<advertisement>> advertise(io_context& io, service_record record);
    static result<std::unique_ptr<discovery_browser>> start_browse(io_context& io, const browse_options& options);
#else
    static result<std::unique_ptr<advertisement>> advertise(io_context& io, service_record record) { return no_discovery::advertise(io, std::move(record)); }
    static result<std::unique_ptr<discovery_browser>> start_browse(io_context& io, const browse_options& options) { return no_discovery::start_browse(io, options); }
#endif
};

// Explicit native-executable fallback: DNS-SD over multicast UDP, without a
// platform service daemon or application context. Useful on Linux/headless Android.
struct mdns_wire {
    static constexpr std::string_view name = "mdns_wire";
#if RHP_ENABLE
    static result<std::unique_ptr<advertisement>> advertise(io_context& io, service_record record);
    static result<std::unique_ptr<discovery_browser>> start_browse(io_context& io, const browse_options& options);
#else
    static result<std::unique_ptr<advertisement>> advertise(io_context& io, service_record record) { return no_discovery::advertise(io, std::move(record)); }
    static result<std::unique_ptr<discovery_browser>> start_browse(io_context& io, const browse_options& options) { return no_discovery::start_browse(io, options); }
#endif
};

static_assert(discovery<mdns>);
static_assert(discovery<mdns_wire>);

} // namespace Rhp::net

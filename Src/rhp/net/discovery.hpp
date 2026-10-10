#pragma once

#include <chrono>
#include <concepts>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/io_context.hpp>

// Host discovery (Rhp::config<>::discovery<D>). A record is a hint, never a credential: clients
// still authenticate every host they find, and discovery can't turn on plaintext.
namespace Rhp::net {

// The DNS-SD service type a transport is published under: datagram transports under "_rhp._udp",
// stream transports under "_rhp._tcp".
[[nodiscard]] constexpr std::string_view dns_sd_service(std::string_view transport) noexcept {
    return transport == "udp_reliable" ? std::string_view{"_rhp._udp"} : std::string_view{"_rhp._tcp"};
}

// What a host publishes and a browser finds.
struct service_record {
    std::string name;    // instance: letters, digits, '-' and '_', at most 63
    std::string host;    // DNS name ("<name>.rhp.local" when left empty)
    std::string address; // literal address to dial (a wildcard listener publishes its interface's)
    std::uint16_t port = 0;
    std::uint8_t protocol_revision = 0;
    std::string platform;
    std::string app;
    std::string build;
    std::string transport = "tcp"; // the transport policy's name
    std::vector<std::string> libs; // only with advertise_options::include_libs

    [[nodiscard]] bool operator==(const service_record&) const = default;
};

struct advertise_options {
    std::string name; // empty: kept from the previous advertise(), else "rhp-<random>"
    std::string app;
    std::string build;
    bool include_libs = false; // publish installed library names (they describe the program)
};

// Browsing filters; empty fields match anything.
struct browse_options {
    std::string service = std::string{dns_sd_service("tcp")};
    std::string app;
    std::string build;
    std::string platform;
    std::uint8_t protocol_revision = 0; // 0 accepts any (Rhp::fleet asks for its own)
    std::vector<std::string> libs;      // every one must be published
    std::chrono::milliseconds duration{1500};
};

// A live publication; destroying it withdraws the record. I/O-thread members.
class advertisement {
public:
    virtual ~advertisement() = default;
    // Replaces the record (the same name is announced again; a new name is probed first).
    virtual result<void> update(service_record record) = 0;
    // A name conflict (kAlreadyLoaded) or a network error found since; ok while healthy.
    [[nodiscard]] virtual result<void> status() const = 0;

protected:
    advertisement() = default;
    advertisement(const advertisement&) = default;
    advertisement& operator=(const advertisement&) = default;
};

// A running browse; services() is what has been found and not expired so far. I/O-thread members.
class discovery_browser {
public:
    virtual ~discovery_browser() = default;
    [[nodiscard]] virtual result<std::vector<service_record>> services() const = 0;

protected:
    discovery_browser() = default;
    discovery_browser(const discovery_browser&) = default;
    discovery_browser& operator=(const discovery_browser&) = default;
};

// Discovery policy for Rhp::config<>::discovery<...>. Everything runs on the io_context's thread.
template <class D>
concept discovery = requires(io_context& io, service_record record, const browse_options& options) {
    { D::name } -> std::convertible_to<std::string_view>;
    { D::advertise(io, std::move(record)) } -> std::same_as<result<std::unique_ptr<advertisement>>>;
    { D::start_browse(io, options) } -> std::same_as<result<std::unique_ptr<discovery_browser>>>;
};

// A discovery policy as function pointers, so the host engine stays out of templates.
struct discovery_ops {
    std::string_view name;
    result<std::unique_ptr<advertisement>> (*advertise)(io_context&, service_record) = nullptr;
    result<std::unique_ptr<discovery_browser>> (*browse)(io_context&, const browse_options&) = nullptr;
};

template <discovery D>
inline constexpr discovery_ops discovery_ops_for{D::name, &D::advertise, &D::start_browse};

// The opt-out: hosts can't advertise and fleets can't browse (kDisabled).
struct no_discovery {
    static constexpr std::string_view name = "none";

    static result<std::unique_ptr<advertisement>> advertise(io_context&, service_record) { return fail(errc::kDisabled, "discovery is disabled (discovery<no_discovery>)", "net.discovery"); }
    static result<std::unique_ptr<discovery_browser>> start_browse(io_context&, const browse_options&) {
        return fail(errc::kDisabled, "discovery is disabled (discovery<no_discovery>)", "net.discovery");
    }
};

static_assert(discovery<no_discovery>);

} // namespace Rhp::net

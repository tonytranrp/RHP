#pragma once

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/client/detail/engine.hpp>
#include <rhp/client/rollout.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/net/discovery.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp {

struct fleet_options {
    client_options client{};                  // every member's
    std::chrono::milliseconds timeout{10000}; // per broadcast, shared by every host; zero waits without a deadline
    net::tls_mode tls = net::tls_mode::kAuto;
    bool insecure_lan = false; // the caller's opt-in only: never taken from discovery records
};

} // namespace Rhp

namespace Rhp::fleet_detail {

// Every member is a client engine on the fleet's one reactor (net::io_context), run by at most
// one I/O thread (none with io<zero_threads>: poll() and the broadcast waits run it).
struct setup {
    client_detail::setup member; // `ep` and `shared_io` are filled in per member
    // Signs a script's source (the client's signer); empty sends scripts unsigned.
    std::function<result<value>(std::string_view)> sign;
    std::string transport; // the transport's name, which records must carry
    std::chrono::milliseconds timeout{10000};
    net::tls_mode tls = net::tls_mode::kAuto;
    bool insecure_lan = false;
};

// A record a member can be made from: an address, a port, this transport and this wire revision.
[[nodiscard]] inline bool compatible(const net::service_record& record, std::string_view transport) noexcept {
    return record.port != 0 && !record.address.empty() && record.protocol_revision == wire::kProtocolRevision && record.transport == transport;
}

class engine;

struct engine_deleter {
    void operator()(engine* e) const noexcept;
};

using engine_ptr = std::unique_ptr<engine, engine_deleter>;

// One host's raw answer: the kResult body, or the error the host (or the deadline) gave.
struct outcome {
    net::service_record host;
    result<value> body;
};

[[nodiscard]] engine_ptr make_engine(setup s);
// Adds a member for the record (true), or refreshes the member at its address and port (false),
// replacing it if it closed for good. kInvalidArgument for an incompatible record.
[[nodiscard]] result<bool> join(engine& e, net::service_record record);
[[nodiscard]] std::size_t size(const engine& e) noexcept;
// Ends every member's session.
void clear(engine& e);
// zero_threads: runs whatever the network has ready, without blocking. No-op with an I/O thread.
void poll(engine& e);
// Closes every member (waiting briefly for each close to go out); the owner then stops its runner.
void close(engine& e) noexcept;
// The I/O thread's body (io<owned_io_thread>): runs the shared reactor until `stop`.
void run_io(engine& e, std::stop_token stop);

// Broadcasts: start the request on every member (replacing members that closed for good), then
// collect one outcome per member, in member order, within the shared deadline. A member that
// missed it gets kTimeout and its request is cancelled.
[[nodiscard]] std::vector<outcome> exec(engine& e, std::string_view source);
[[nodiscard]] std::vector<outcome> load(engine& e, std::string_view name, std::string_view source);
[[nodiscard]] std::vector<outcome> call(engine& e, std::string_view module, std::string_view function, std::span<const value> args);

// The members, in member order.
[[nodiscard]] std::vector<net::service_record> records(const engine& e);
// Sends one request to the members at `which` (indices into records()) within the deadline.
[[nodiscard]] std::vector<outcome> send(engine& e, wire::op code, const value& body, std::span<const std::size_t> which);

// fleet::rollout (rollout.cpp).
[[nodiscard]] rollout_report rollout(engine& e, std::span<const std::byte> envelope, const rollout_plan& plan);

// A reply body as the list of returned values (what client::exec returns).
[[nodiscard]] result<value_list> values(result<value>&& body);

} // namespace Rhp::fleet_detail

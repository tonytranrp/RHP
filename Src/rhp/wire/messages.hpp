#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp::wire {

// Message schemas: what each op's payload holds, as Rhp::value maps (encoded by the codec).
// Every type here has an Rhp::convert specialization, so `to_value(msg)` / `from_value<T>(v)` work.
// Unknown keys are ignored when decoding, so a peer may add fields without breaking older ones.

// ---- handshake (unsequenced) ----------------------------------------------------------------------

struct hello {
    std::uint8_t revision = kProtocolRevision;
    std::string platform; // "windows", "linux", ...
    value auth;           // the authenticator's hello (psk: key name + client nonce)
};

struct challenge {
    std::uint8_t revision = kProtocolRevision;
    std::string platform;
    value auth; // the authenticator's challenge (psk: host nonce + host proof)
};

struct response {
    value auth; // the authenticator's response (psk: client proof)
};

struct welcome {
    session_id session;
    std::string identity;
    role granted = role::kObserve;
    std::uint32_t heartbeat_ms = 0;
    std::string platform;
};

// ---- sequenced frames ---------------------------------------------------------------------------

// The payload of every request and reply: `req` names the client's request (0 = none, e.g. a print
// from a timer), `idem` is the client's idempotency key (0 = none), `body` is the op's own data.
struct envelope {
    std::uint64_t req = 0;
    std::uint64_t idem = 0;
    value body;
};

// A module by id, or by name when the id is 0. Converts from either.
struct module_ref {
    module_ref() = default;
    module_ref(module_id module) : id(module) {}
    module_ref(std::string_view module_name) : name(module_name) {}
    module_ref(const char* module_name) : name(module_name) {}
    module_ref(std::string module_name) : name(std::move(module_name)) {}

    module_id id;
    std::string name;

    [[nodiscard]] bool operator==(const module_ref&) const = default;
};

struct exec_request {
    std::string source;
    std::string chunk = "exec";
};

struct load_request {
    std::string name;
    std::string source;
};

struct call_request {
    module_ref module;
    std::string function;
    value::array args;
};

struct reload_request {
    module_ref module;
    std::string source;
};

struct rollback_request {
    module_ref module;
    std::uint64_t steps = 1;
};

struct unload_request {
    module_ref module;
    bool force = false;
};

// revert and status.
struct module_request {
    module_ref module;
};

// checkpoint and revert_to.
struct tag_request {
    std::string tag;
};

// The client request to stop (0 = every request this session has in flight).
struct cancel_request {
    std::uint64_t target = 0;
};

// Reply bodies (kResult):
//   exec, call            array of returned values
//   load                  module id
//   reload, rollback      revision (0 = deferred)
//   revert, unload, revert_to, revert_all   revert_summary
//   checkpoint            nil
//   list                  array of module_status
//   status                module_status
//   describe              string (LuaLS stubs)
// kError carries an Rhp::error; kOutput a string; kEmit an emit_message.

struct revert_summary {
    std::uint64_t undone = 0;
    std::uint64_t irreversible = 0;
    std::vector<error> failures;
    bool deferred = false;

    [[nodiscard]] bool clean() const noexcept { return failures.empty(); }
    [[nodiscard]] bool operator==(const revert_summary&) const = default;
};

struct module_status {
    module_id id;
    std::string name;
    std::string state; // "active", "reverted", "faulted", "loading"
    bool scratch = false;
    std::uint64_t effects = 0;
    std::uint64_t irreversible_effects = 0;
    revision_id revision;
    std::uint32_t source_hash = 0;
    std::uint64_t revisions = 0;
    bool reloading = false;
    std::vector<module_id> dependencies;
    std::optional<error> fault;

    [[nodiscard]] bool operator==(const module_status&) const = default;
};

struct emit_message {
    module_id module;
    value data;
};

} // namespace Rhp::wire

#define RHP_WIRE_MESSAGE_CONVERT(T)                            \
    template <>                                                \
    struct Rhp::convert<T> {                                   \
        static Rhp::value to_value(const T& m);                \
        static Rhp::result<T> from_value(const Rhp::value& v); \
    }

RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::hello);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::challenge);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::response);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::welcome);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::envelope);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::module_ref);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::exec_request);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::load_request);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::call_request);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::reload_request);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::rollback_request);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::unload_request);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::module_request);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::tag_request);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::cancel_request);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::revert_summary);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::module_status);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::emit_message);

#undef RHP_WIRE_MESSAGE_CONVERT

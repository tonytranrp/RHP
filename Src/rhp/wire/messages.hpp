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

// The payload of kResume (dialing side, on a new connection) and of the kWelcome that answers it:
// which session continues, and `proof` = the sender's frame MAC over a label and the NEW
// connection's channel binding - so a relay that terminates TLS on the new connection can't carry
// a resume through. Both frames are sealed with the session's keys and carry the control counter in
// `seq`, so a replayed one is refused.
struct resume {
    session_id session;
    value::bytes proof;
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

// exec, load and reload carry code: `signature` is the config's signer over the source (nil =
// unsigned, which the host accepts from observe sessions only).
struct exec_request {
    std::string source;
    std::string chunk = "exec";
    value signature;
};

struct load_request {
    std::string name;
    std::string source;
    value signature;
};

struct call_request {
    module_ref module;
    std::string function;
    value::array args;
};

struct reload_request {
    module_ref module;
    std::string source;
    value signature;
};

struct rollback_request {
    module_ref module;
    std::uint64_t steps = 1;
};

struct unload_request {
    module_ref module;
    bool force = false;
};

// revert, status, pin and unpin.
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

// One piece of a blob for a host-registered sink. A transfer is a run of chunks with the same
// `transfer` id, `offset`s back to back from 0, the same `sink` / `name` / `total`; each chunk is a
// request of its own (answered nil), and the last one's reply is the sink's verdict.
struct blob_chunk {
    std::uint64_t transfer = 0;
    std::string sink;
    std::string name; // free-form (a file name); passed to the sink
    std::uint64_t total = 0;
    std::uint64_t offset = 0;
    value::bytes data;
};

// subscribe and unsubscribe: a C++ lua_event (program-wide) or an rhp.publish of this session's
// identity ("*": every publish), by name.
struct subscribe_request {
    std::string name;
};

// Releases (Stage 10). The envelopes are opaque here: Rhp::release decodes and checks them.
struct release_apply_request {
    value::bytes envelope;
    std::string confirm = "now"; // "now", "health" or "manual"

    [[nodiscard]] bool operator==(const release_apply_request&) const = default;
};

// release_confirm and release_deactivate.
struct release_channel_request {
    std::string channel;
    bool hold = false; // deactivate: run nothing until a new release arrives

    [[nodiscard]] bool operator==(const release_channel_request&) const = default;
};

struct revoke_request {
    value::bytes envelope;
};

struct release_info_message {
    value::bytes id; // 32 bytes
    std::uint64_t seq = 0;
    std::string label;
    std::vector<std::string> signers;

    [[nodiscard]] bool operator==(const release_info_message&) const = default;
};

struct release_apply_reply {
    std::string channel;
    value::bytes id;
    std::uint64_t seq = 0;
    std::string running; // "active" or "candidate"
    bool already = false;
    value::bytes replaced; // empty: nothing ran before
    std::vector<std::string> signers;

    [[nodiscard]] bool operator==(const release_apply_reply&) const = default;
};

struct channel_status_message {
    std::string channel;
    std::string running; // "empty", "active" or "candidate"
    std::optional<release_info_message> active;
    std::optional<release_info_message> candidate;
    value::bytes previous;
    std::uint64_t floor = 0;
    bool held = false;
    std::uint64_t attempts = 0;
    std::string confirm; // "now", "health" or "manual"
    std::uint64_t handler_failures = 0;
    std::vector<std::string> modules;

    [[nodiscard]] bool operator==(const channel_status_message&) const = default;
};

struct release_status_reply {
    std::string app;
    std::string build;
    std::string platform;
    std::uint64_t revocation_seq = 0;
    std::vector<channel_status_message> channels;

    [[nodiscard]] bool operator==(const release_status_reply&) const = default;
};

// Reply bodies (kResult):
//   exec, call            array of returned values
//   load                  module id
//   reload, rollback      revision (0 = deferred)
//   revert, unload, revert_to, revert_all   revert_summary
//   checkpoint, pin, unpin, blob, subscribe, unsubscribe   nil
//   list                  array of module_status
//   status                module_status
//   describe              string (LuaLS stubs)
//   release_apply         release_apply_reply
//   release_confirm, release_deactivate   nil
//   release_status        release_status_reply
//   revoke                integer (channels that changed)
// kError carries an Rhp::error; kOutput a string; kEmit an emit_message; kEvent an event_message.

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
    bool pinned = false; // kept when its identity's last session ends

    [[nodiscard]] bool operator==(const module_status&) const = default;
};

struct emit_message {
    module_id module;
    value data;
};

// One delivery of a subscribed event (host -> client, envelope req 0).
struct event_message {
    std::string name;
    module_id module;           // the publishing module (0: C++ or the sandbox itself)
    value::array args;
    std::uint64_t dropped = 0;  // deliveries to this session dropped since the previous one (host_options::remote_events_per_pump)
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
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::resume);
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
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::blob_chunk);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::release_apply_request);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::release_channel_request);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::revoke_request);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::release_info_message);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::release_apply_reply);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::channel_status_message);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::release_status_reply);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::revert_summary);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::module_status);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::emit_message);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::subscribe_request);
RHP_WIRE_MESSAGE_CONVERT(Rhp::wire::event_message);

#undef RHP_WIRE_MESSAGE_CONVERT

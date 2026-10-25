#include <cstdint>
#include <format>
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
#include <rhp/wire/messages.hpp>

namespace Rhp::wire {

namespace {

// Builds a map value field by field.
class map_builder {
public:
    template <to_value_convertible T>
    map_builder& set(std::string_view key, const T& v) {
        m_.emplace_back(value{key}, Rhp::to_value(v));
        return *this;
    }

    map_builder& set(std::string_view key, value v) {
        m_.emplace_back(value{key}, std::move(v));
        return *this;
    }

    [[nodiscard]] value done() { return value{std::move(m_)}; }

private:
    value::map m_;
};

[[nodiscard]] std::unexpected<error> not_a_map(std::string_view what, const value& v) {
    return fail(errc::kProtocol, std::format("{} must be a map, got {}", what, to_string(v.type())), "wire");
}

// Reads one field of a message map: required (missing → kProtocol) or with a fallback.
template <from_value_convertible T>
[[nodiscard]] result<T> field(const value& m, std::string_view key, std::string_view what) {
    const value* v = m.find(key);
    if (v == nullptr) {
        return fail(errc::kProtocol, std::format("{} has no '{}'", what, key), "wire");
    }
    auto out = Rhp::from_value<T>(*v);
    if (!out) {
        out.error().where = std::format("{}.{}", what, key);
    }
    return out;
}

template <from_value_convertible T>
[[nodiscard]] result<T> field_or(const value& m, std::string_view key, std::string_view what, T fallback) {
    const value* v = m.find(key);
    if (v == nullptr || v->is_nil()) {
        return fallback;
    }
    auto out = Rhp::from_value<T>(*v);
    if (!out) {
        out.error().where = std::format("{}.{}", what, key);
    }
    return out;
}

[[nodiscard]] value field_value(const value& m, std::string_view key) {
    const value* v = m.find(key);
    return v != nullptr ? *v : value{};
}

// `auto var = expr;` returning its error from the enclosing function if it failed.
#define RHP_WIRE_READ(var, expr)                        \
    auto var = (expr);                                  \
    if (!var) {                                         \
        return std::unexpected{std::move(var).error()}; \
    }

[[nodiscard]] result<role> role_from(const value& v) {
    if (const auto* s = v.get_if<std::string>()) {
        for (const role r : {role::kObserve, role::kPatch, role::kAdmin}) {
            if (to_string(r) == *s) {
                return r;
            }
        }
    }
    return fail(errc::kProtocol, "unknown role", "wire.welcome.role");
}

} // namespace

} // namespace Rhp::wire

using namespace Rhp::wire;
using Rhp::result;
using Rhp::value;

// ---- handshake -------------------------------------------------------------------------------------

value Rhp::convert<hello>::to_value(const hello& m) {
    return map_builder{}.set("rev", m.revision).set("platform", m.platform).set("auth", m.auth).done();
}

result<hello> Rhp::convert<hello>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("hello", v);
    }
    RHP_WIRE_READ(rev, field<std::uint8_t>(v, "rev", "hello"));
    RHP_WIRE_READ(platform, field_or<std::string>(v, "platform", "hello", {}));
    return hello{*rev, std::move(*platform), field_value(v, "auth")};
}

value Rhp::convert<challenge>::to_value(const challenge& m) {
    return map_builder{}.set("rev", m.revision).set("platform", m.platform).set("auth", m.auth).done();
}

result<challenge> Rhp::convert<challenge>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("challenge", v);
    }
    RHP_WIRE_READ(rev, field<std::uint8_t>(v, "rev", "challenge"));
    RHP_WIRE_READ(platform, field_or<std::string>(v, "platform", "challenge", {}));
    return challenge{*rev, std::move(*platform), field_value(v, "auth")};
}

value Rhp::convert<response>::to_value(const response& m) {
    return map_builder{}.set("auth", m.auth).done();
}

result<response> Rhp::convert<response>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("response", v);
    }
    return response{field_value(v, "auth")};
}

value Rhp::convert<welcome>::to_value(const welcome& m) {
    return map_builder{}
        .set("session", m.session)
        .set("identity", m.identity)
        .set("role", value{to_string(m.granted)})
        .set("heartbeat_ms", m.heartbeat_ms)
        .set("platform", m.platform)
        .done();
}

result<welcome> Rhp::convert<welcome>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("welcome", v);
    }
    RHP_WIRE_READ(session, field<Rhp::session_id>(v, "session", "welcome"));
    RHP_WIRE_READ(identity, field<std::string>(v, "identity", "welcome"));
    RHP_WIRE_READ(granted, role_from(field_value(v, "role")));
    RHP_WIRE_READ(heartbeat, field_or<std::uint32_t>(v, "heartbeat_ms", "welcome", 0));
    RHP_WIRE_READ(platform, field_or<std::string>(v, "platform", "welcome", {}));
    return welcome{*session, std::move(*identity), *granted, *heartbeat, std::move(*platform)};
}

value Rhp::convert<resume>::to_value(const resume& m) {
    return map_builder{}.set("session", m.session).set("proof", value{m.proof}).done();
}

result<resume> Rhp::convert<resume>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("resume", v);
    }
    RHP_WIRE_READ(session, field<Rhp::session_id>(v, "session", "resume"));
    value::bytes proof;
    if (const value* p = v.find("proof"); p != nullptr && !p->is_nil()) {
        const auto* bytes = p->get_if<value::bytes>();
        if (bytes == nullptr) {
            return Rhp::fail(Rhp::errc::kProtocol, "resume.proof must be bytes", "wire");
        }
        proof = *bytes;
    }
    return resume{*session, std::move(proof)};
}

// ---- envelope and requests -----------------------------------------------------------------------

value Rhp::convert<envelope>::to_value(const envelope& m) {
    map_builder b;
    b.set("req", m.req);
    if (m.idem != 0) {
        b.set("idem", m.idem);
    }
    b.set("body", m.body);
    return b.done();
}

result<envelope> Rhp::convert<envelope>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("envelope", v);
    }
    RHP_WIRE_READ(req, field_or<std::uint64_t>(v, "req", "envelope", 0));
    RHP_WIRE_READ(idem, field_or<std::uint64_t>(v, "idem", "envelope", 0));
    return envelope{*req, *idem, field_value(v, "body")};
}

value Rhp::convert<module_ref>::to_value(const module_ref& m) {
    return m.id ? Rhp::to_value(m.id) : value{m.name};
}

result<module_ref> Rhp::convert<module_ref>::from_value(const value& v) {
    if (v.is_string()) {
        return module_ref{*v.get_if<std::string>()};
    }
    RHP_WIRE_READ(id, Rhp::from_value<Rhp::module_id>(v));
    return module_ref{*id};
}

value Rhp::convert<exec_request>::to_value(const exec_request& m) {
    return map_builder{}.set("source", m.source).set("chunk", m.chunk).set("signature", m.signature).done();
}

result<exec_request> Rhp::convert<exec_request>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("exec", v);
    }
    RHP_WIRE_READ(source, field<std::string>(v, "source", "exec"));
    RHP_WIRE_READ(chunk, field_or<std::string>(v, "chunk", "exec", "exec"));
    return exec_request{std::move(*source), std::move(*chunk), field_value(v, "signature")};
}

value Rhp::convert<load_request>::to_value(const load_request& m) {
    return map_builder{}.set("name", m.name).set("source", m.source).set("signature", m.signature).done();
}

result<load_request> Rhp::convert<load_request>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("load", v);
    }
    RHP_WIRE_READ(name, field<std::string>(v, "name", "load"));
    RHP_WIRE_READ(source, field<std::string>(v, "source", "load"));
    return load_request{std::move(*name), std::move(*source), field_value(v, "signature")};
}

value Rhp::convert<call_request>::to_value(const call_request& m) {
    return map_builder{}.set("module", m.module).set("function", m.function).set("args", value{m.args}).done();
}

result<call_request> Rhp::convert<call_request>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("call", v);
    }
    RHP_WIRE_READ(module, field<module_ref>(v, "module", "call"));
    RHP_WIRE_READ(function, field<std::string>(v, "function", "call"));
    value::array args;
    if (const value* a = v.find("args"); a != nullptr && !a->is_nil()) {
        const auto* items = a->get_if<value::array>();
        if (items == nullptr) {
            return Rhp::fail(Rhp::errc::kProtocol, "call.args must be an array", "wire");
        }
        args = *items;
    }
    return call_request{std::move(*module), std::move(*function), std::move(args)};
}

value Rhp::convert<reload_request>::to_value(const reload_request& m) {
    return map_builder{}.set("module", m.module).set("source", m.source).set("signature", m.signature).done();
}

result<reload_request> Rhp::convert<reload_request>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("reload", v);
    }
    RHP_WIRE_READ(module, field<module_ref>(v, "module", "reload"));
    RHP_WIRE_READ(source, field<std::string>(v, "source", "reload"));
    return reload_request{std::move(*module), std::move(*source), field_value(v, "signature")};
}

value Rhp::convert<rollback_request>::to_value(const rollback_request& m) {
    return map_builder{}.set("module", m.module).set("steps", m.steps).done();
}

result<rollback_request> Rhp::convert<rollback_request>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("rollback", v);
    }
    RHP_WIRE_READ(module, field<module_ref>(v, "module", "rollback"));
    RHP_WIRE_READ(steps, field_or<std::uint64_t>(v, "steps", "rollback", 1));
    return rollback_request{std::move(*module), *steps};
}

value Rhp::convert<unload_request>::to_value(const unload_request& m) {
    return map_builder{}.set("module", m.module).set("force", m.force).done();
}

result<unload_request> Rhp::convert<unload_request>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("unload", v);
    }
    RHP_WIRE_READ(module, field<module_ref>(v, "module", "unload"));
    RHP_WIRE_READ(force, field_or<bool>(v, "force", "unload", false));
    return unload_request{std::move(*module), *force};
}

value Rhp::convert<module_request>::to_value(const module_request& m) {
    return map_builder{}.set("module", m.module).done();
}

result<module_request> Rhp::convert<module_request>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("module request", v);
    }
    RHP_WIRE_READ(module, field<module_ref>(v, "module", "module request"));
    return module_request{std::move(*module)};
}

value Rhp::convert<tag_request>::to_value(const tag_request& m) {
    return map_builder{}.set("tag", m.tag).done();
}

result<tag_request> Rhp::convert<tag_request>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("tag request", v);
    }
    RHP_WIRE_READ(tag, field<std::string>(v, "tag", "tag request"));
    return tag_request{std::move(*tag)};
}

value Rhp::convert<cancel_request>::to_value(const cancel_request& m) {
    return map_builder{}.set("target", m.target).done();
}

result<cancel_request> Rhp::convert<cancel_request>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("cancel", v);
    }
    RHP_WIRE_READ(target, field_or<std::uint64_t>(v, "target", "cancel", 0));
    return cancel_request{*target};
}

value Rhp::convert<blob_chunk>::to_value(const blob_chunk& m) {
    return map_builder{}
        .set("transfer", m.transfer)
        .set("sink", m.sink)
        .set("name", m.name)
        .set("total", m.total)
        .set("offset", m.offset)
        .set("data", value{m.data})
        .done();
}

result<blob_chunk> Rhp::convert<blob_chunk>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("blob", v);
    }
    RHP_WIRE_READ(transfer, field<std::uint64_t>(v, "transfer", "blob"));
    RHP_WIRE_READ(sink, field<std::string>(v, "sink", "blob"));
    RHP_WIRE_READ(name, field_or<std::string>(v, "name", "blob", {}));
    RHP_WIRE_READ(total, field<std::uint64_t>(v, "total", "blob"));
    RHP_WIRE_READ(offset, field<std::uint64_t>(v, "offset", "blob"));
    value::bytes data;
    if (const value* d = v.find("data"); d != nullptr && !d->is_nil()) {
        const auto* bytes = d->get_if<value::bytes>();
        if (bytes == nullptr) {
            return Rhp::fail(Rhp::errc::kProtocol, "blob.data must be bytes", "wire");
        }
        data = *bytes;
    }
    return blob_chunk{*transfer, std::move(*sink), std::move(*name), *total, *offset, std::move(data)};
}

// ---- replies -------------------------------------------------------------------------------------

value Rhp::convert<revert_summary>::to_value(const revert_summary& m) {
    return map_builder{}.set("undone", m.undone).set("irreversible", m.irreversible).set("failures", m.failures).set("deferred", m.deferred).done();
}

result<revert_summary> Rhp::convert<revert_summary>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("revert summary", v);
    }
    RHP_WIRE_READ(undone, field_or<std::uint64_t>(v, "undone", "revert summary", 0));
    RHP_WIRE_READ(irreversible, field_or<std::uint64_t>(v, "irreversible", "revert summary", 0));
    RHP_WIRE_READ(failures, field_or<std::vector<Rhp::error>>(v, "failures", "revert summary", {}));
    RHP_WIRE_READ(deferred, field_or<bool>(v, "deferred", "revert summary", false));
    return revert_summary{*undone, *irreversible, std::move(*failures), *deferred};
}

value Rhp::convert<module_status>::to_value(const module_status& m) {
    map_builder b;
    b.set("id", m.id)
        .set("name", m.name)
        .set("state", m.state)
        .set("scratch", m.scratch)
        .set("effects", m.effects)
        .set("irreversible_effects", m.irreversible_effects)
        .set("revision", m.revision)
        .set("source_hash", m.source_hash)
        .set("revisions", m.revisions)
        .set("reloading", m.reloading)
        .set("dependencies", m.dependencies)
        .set("pinned", m.pinned);
    if (m.fault) {
        b.set("fault", *m.fault);
    }
    return b.done();
}

result<module_status> Rhp::convert<module_status>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("module status", v);
    }
    constexpr std::string_view what = "module status";
    module_status s;
    RHP_WIRE_READ(id, field<Rhp::module_id>(v, "id", what));
    RHP_WIRE_READ(name, field<std::string>(v, "name", what));
    RHP_WIRE_READ(state, field<std::string>(v, "state", what));
    RHP_WIRE_READ(scratch, field_or<bool>(v, "scratch", what, false));
    RHP_WIRE_READ(effects, field_or<std::uint64_t>(v, "effects", what, 0));
    RHP_WIRE_READ(irreversible, field_or<std::uint64_t>(v, "irreversible_effects", what, 0));
    RHP_WIRE_READ(revision, field_or<Rhp::revision_id>(v, "revision", what, {}));
    RHP_WIRE_READ(hash, field_or<std::uint32_t>(v, "source_hash", what, 0));
    RHP_WIRE_READ(revisions, field_or<std::uint64_t>(v, "revisions", what, 0));
    RHP_WIRE_READ(reloading, field_or<bool>(v, "reloading", what, false));
    RHP_WIRE_READ(dependencies, field_or<std::vector<Rhp::module_id>>(v, "dependencies", what, {}));
    RHP_WIRE_READ(pinned, field_or<bool>(v, "pinned", what, false));
    s.id = *id;
    s.name = std::move(*name);
    s.state = std::move(*state);
    s.scratch = *scratch;
    s.effects = *effects;
    s.irreversible_effects = *irreversible;
    s.revision = *revision;
    s.source_hash = *hash;
    s.revisions = *revisions;
    s.reloading = *reloading;
    s.dependencies = std::move(*dependencies);
    s.pinned = *pinned;
    if (const value* f = v.find("fault"); f != nullptr && !f->is_nil()) {
        RHP_WIRE_READ(fault, Rhp::from_value<Rhp::error>(*f));
        s.fault = std::move(*fault);
    }
    return s;
}

value Rhp::convert<emit_message>::to_value(const emit_message& m) {
    return map_builder{}.set("module", m.module).set("value", m.data).done();
}

result<emit_message> Rhp::convert<emit_message>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("emit", v);
    }
    RHP_WIRE_READ(module, field_or<Rhp::module_id>(v, "module", "emit", {}));
    return emit_message{*module, field_value(v, "value")};
}

value Rhp::convert<subscribe_request>::to_value(const subscribe_request& m) {
    return map_builder{}.set("name", m.name).done();
}

result<subscribe_request> Rhp::convert<subscribe_request>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("subscribe", v);
    }
    RHP_WIRE_READ(name, field<std::string>(v, "name", "subscribe"));
    return subscribe_request{std::move(*name)};
}

value Rhp::convert<event_message>::to_value(const event_message& m) {
    return map_builder{}.set("name", m.name).set("module", m.module).set("args", value{m.args}).set("dropped", m.dropped).done();
}

result<event_message> Rhp::convert<event_message>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("event", v);
    }
    RHP_WIRE_READ(name, field<std::string>(v, "name", "event"));
    RHP_WIRE_READ(module, field_or<Rhp::module_id>(v, "module", "event", {}));
    RHP_WIRE_READ(dropped, field_or<std::uint64_t>(v, "dropped", "event", 0));
    value::array args;
    if (const value* a = v.find("args"); a != nullptr && !a->is_nil()) {
        const auto* items = a->get_if<value::array>();
        if (items == nullptr) {
            return Rhp::fail(Rhp::errc::kProtocol, "event.args must be an array", "wire");
        }
        args = *items;
    }
    return event_message{std::move(*name), *module, std::move(args), *dropped};
}

// ---- releases ------------------------------------------------------------------------------------

value Rhp::convert<release_apply_request>::to_value(const release_apply_request& m) {
    return map_builder{}.set("envelope", value{m.envelope}).set("confirm", m.confirm).done();
}

result<release_apply_request> Rhp::convert<release_apply_request>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("release_apply", v);
    }
    RHP_WIRE_READ(envelope, field<value::bytes>(v, "envelope", "release_apply"));
    RHP_WIRE_READ(confirm, field_or<std::string>(v, "confirm", "release_apply", "now"));
    return release_apply_request{std::move(*envelope), std::move(*confirm)};
}

value Rhp::convert<release_channel_request>::to_value(const release_channel_request& m) {
    return map_builder{}.set("channel", m.channel).set("hold", m.hold).done();
}

result<release_channel_request> Rhp::convert<release_channel_request>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("release_channel", v);
    }
    RHP_WIRE_READ(channel, field<std::string>(v, "channel", "release_channel"));
    RHP_WIRE_READ(hold, field_or<bool>(v, "hold", "release_channel", false));
    return release_channel_request{std::move(*channel), *hold};
}

value Rhp::convert<revoke_request>::to_value(const revoke_request& m) {
    return map_builder{}.set("envelope", value{m.envelope}).done();
}

result<revoke_request> Rhp::convert<revoke_request>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("revoke", v);
    }
    RHP_WIRE_READ(envelope, field<value::bytes>(v, "envelope", "revoke"));
    return revoke_request{std::move(*envelope)};
}

value Rhp::convert<release_info_message>::to_value(const release_info_message& m) {
    return map_builder{}.set("id", value{m.id}).set("seq", m.seq).set("label", m.label).set("signers", m.signers).done();
}

result<release_info_message> Rhp::convert<release_info_message>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("release_info", v);
    }
    RHP_WIRE_READ(id, field<value::bytes>(v, "id", "release_info"));
    RHP_WIRE_READ(seq, field_or<std::uint64_t>(v, "seq", "release_info", 0));
    RHP_WIRE_READ(label, field_or<std::string>(v, "label", "release_info", {}));
    RHP_WIRE_READ(signers, field_or<std::vector<std::string>>(v, "signers", "release_info", {}));
    return release_info_message{std::move(*id), *seq, std::move(*label), std::move(*signers)};
}

value Rhp::convert<release_apply_reply>::to_value(const release_apply_reply& m) {
    return map_builder{}
        .set("channel", m.channel)
        .set("id", value{m.id})
        .set("seq", m.seq)
        .set("running", m.running)
        .set("already", m.already)
        .set("replaced", value{m.replaced})
        .set("signers", m.signers)
        .done();
}

result<release_apply_reply> Rhp::convert<release_apply_reply>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("release_apply reply", v);
    }
    RHP_WIRE_READ(channel, field<std::string>(v, "channel", "release_apply reply"));
    RHP_WIRE_READ(id, field<value::bytes>(v, "id", "release_apply reply"));
    RHP_WIRE_READ(seq, field_or<std::uint64_t>(v, "seq", "release_apply reply", 0));
    RHP_WIRE_READ(running, field_or<std::string>(v, "running", "release_apply reply", "active"));
    RHP_WIRE_READ(already, field_or<bool>(v, "already", "release_apply reply", false));
    RHP_WIRE_READ(replaced, field_or<value::bytes>(v, "replaced", "release_apply reply", {}));
    RHP_WIRE_READ(signers, field_or<std::vector<std::string>>(v, "signers", "release_apply reply", {}));
    return release_apply_reply{std::move(*channel), std::move(*id), *seq, std::move(*running), *already, std::move(*replaced), std::move(*signers)};
}

value Rhp::convert<channel_status_message>::to_value(const channel_status_message& m) {
    return map_builder{}
        .set("channel", m.channel)
        .set("running", m.running)
        .set("active", m.active ? Rhp::to_value(*m.active) : value{})
        .set("candidate", m.candidate ? Rhp::to_value(*m.candidate) : value{})
        .set("previous", value{m.previous})
        .set("floor", m.floor)
        .set("held", m.held)
        .set("attempts", m.attempts)
        .set("confirm", m.confirm)
        .set("handler_failures", m.handler_failures)
        .set("modules", m.modules)
        .done();
}

result<channel_status_message> Rhp::convert<channel_status_message>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("channel_status", v);
    }
    channel_status_message out;
    RHP_WIRE_READ(channel, field<std::string>(v, "channel", "channel_status"));
    RHP_WIRE_READ(running, field_or<std::string>(v, "running", "channel_status", "empty"));
    for (const auto& [key, slot] : {std::pair{"active", &out.active}, std::pair{"candidate", &out.candidate}}) {
        const value* f = v.find(key);
        if (f != nullptr && !f->is_nil()) {
            auto info = Rhp::from_value<release_info_message>(*f);
            if (!info) {
                return std::unexpected{std::move(info).error()};
            }
            *slot = std::move(*info);
        }
    }
    RHP_WIRE_READ(previous, field_or<value::bytes>(v, "previous", "channel_status", {}));
    RHP_WIRE_READ(floor, field_or<std::uint64_t>(v, "floor", "channel_status", 0));
    RHP_WIRE_READ(held, field_or<bool>(v, "held", "channel_status", false));
    RHP_WIRE_READ(attempts, field_or<std::uint64_t>(v, "attempts", "channel_status", 0));
    RHP_WIRE_READ(confirm, field_or<std::string>(v, "confirm", "channel_status", "now"));
    RHP_WIRE_READ(failures, field_or<std::uint64_t>(v, "handler_failures", "channel_status", 0));
    RHP_WIRE_READ(modules, field_or<std::vector<std::string>>(v, "modules", "channel_status", {}));
    out.channel = std::move(*channel);
    out.running = std::move(*running);
    out.previous = std::move(*previous);
    out.floor = *floor;
    out.held = *held;
    out.attempts = *attempts;
    out.confirm = std::move(*confirm);
    out.handler_failures = *failures;
    out.modules = std::move(*modules);
    return out;
}

value Rhp::convert<release_status_reply>::to_value(const release_status_reply& m) {
    value::array channels;
    for (const channel_status_message& c : m.channels) {
        channels.push_back(Rhp::to_value(c));
    }
    return map_builder{}
        .set("app", m.app)
        .set("build", m.build)
        .set("platform", m.platform)
        .set("revocation_seq", m.revocation_seq)
        .set("channels", value{std::move(channels)})
        .done();
}

result<release_status_reply> Rhp::convert<release_status_reply>::from_value(const value& v) {
    if (!v.is_map()) {
        return not_a_map("release_status reply", v);
    }
    release_status_reply out;
    RHP_WIRE_READ(app, field_or<std::string>(v, "app", "release_status reply", {}));
    RHP_WIRE_READ(build, field_or<std::string>(v, "build", "release_status reply", {}));
    RHP_WIRE_READ(platform, field_or<std::string>(v, "platform", "release_status reply", {}));
    RHP_WIRE_READ(seq, field_or<std::uint64_t>(v, "revocation_seq", "release_status reply", 0));
    out.app = std::move(*app);
    out.build = std::move(*build);
    out.platform = std::move(*platform);
    out.revocation_seq = *seq;
    if (const value* c = v.find("channels"); c != nullptr && !c->is_nil()) {
        const auto* items = c->get_if<value::array>();
        if (items == nullptr) {
            return Rhp::fail(Rhp::errc::kProtocol, "release_status.channels must be an array", "wire");
        }
        for (const value& item : *items) {
            auto ch = Rhp::from_value<channel_status_message>(item);
            if (!ch) {
                return std::unexpected{std::move(ch).error()};
            }
            out.channels.push_back(std::move(*ch));
        }
    }
    return out;
}

#undef RHP_WIRE_READ

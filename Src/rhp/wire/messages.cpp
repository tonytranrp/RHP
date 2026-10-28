#include <concepts>
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

[[nodiscard]] value field_value(const value& m, std::string_view key) {
    const value* v = m.find(key);
    return v != nullptr ? *v : value{};
}

// An array field of messages (missing or nil: empty).
template <from_value_convertible T>
[[nodiscard]] result<std::vector<T>> message_list(const value& m, std::string_view key, std::string_view what) {
    std::vector<T> out;
    const value* v = m.find(key);
    if (v == nullptr || v->is_nil()) {
        return out;
    }
    const auto* items = v->get_if<value::array>();
    if (items == nullptr) {
        return fail(errc::kProtocol, std::format("{}.{} must be an array", what, key), "wire");
    }
    for (const value& item : *items) {
        auto one = Rhp::from_value<T>(item);
        if (!one) {
            return std::unexpected{std::move(one).error()};
        }
        out.push_back(std::move(*one));
    }
    return out;
}

// A field kept exactly as it came: no conversion (a string isn't bytes).
template <class T>
concept raw_field = std::same_as<T, value::array> || std::same_as<T, value::bytes>;

// One message map being decoded; `what` names the message in every error.
class message_reader {
public:
    message_reader(const value& m, std::string_view what) noexcept : m_(&m), what_(what) {}

    // Required: missing is kProtocol "<what> has no '<key>'"; a bad value is the conversion's error
    // with `where` = "<what>.<key>".
    template <from_value_convertible T>
    [[nodiscard]] result<T> field(std::string_view key) const {
        const value* v = m_->find(key);
        if (v == nullptr) {
            return fail(errc::kProtocol, std::format("{} has no '{}'", what_, key), "wire");
        }
        return convert_field<T>(*v, key);
    }

    // Missing or nil: `fallback`.
    template <from_value_convertible T>
    [[nodiscard]] result<T> field_or(std::string_view key, T fallback) const {
        const value* v = m_->find(key);
        if (v == nullptr || v->is_nil()) {
            return fallback;
        }
        return convert_field<T>(*v, key);
    }

    // Missing or nil: empty; anything but a T is kProtocol "<what>.<key> must be ...".
    template <raw_field T>
    [[nodiscard]] result<T> raw_or_empty(std::string_view key) const {
        const value* v = m_->find(key);
        if (v == nullptr || v->is_nil()) {
            return T{};
        }
        const auto* items = v->get_if<T>();
        if (items == nullptr) {
            constexpr std::string_view kKind = std::same_as<T, value::array> ? "an array" : "bytes";
            return fail(errc::kProtocol, std::format("{}.{} must be {}", what_, key, kKind), "wire");
        }
        return *items;
    }

    // The field as it came (missing: nil).
    [[nodiscard]] value raw(std::string_view key) const { return field_value(*m_, key); }

    template <from_value_convertible T>
    [[nodiscard]] result<std::vector<T>> list(std::string_view key) const {
        return message_list<T>(*m_, key, what_);
    }

private:
    template <from_value_convertible T>
    [[nodiscard]] result<T> convert_field(const value& v, std::string_view key) const {
        auto out = Rhp::from_value<T>(v);
        if (!out) {
            out.error().where = std::format("{}.{}", what_, key);
        }
        return out;
    }

    const value* m_;
    std::string_view what_;
};

[[nodiscard]] result<message_reader> read_map(const value& v, std::string_view what) {
    if (!v.is_map()) {
        return not_a_map(what, v);
    }
    return message_reader{v, what};
}

// `auto var = expr;` returning its error from the enclosing function if it failed.
#define RHP_WIRE_READ(var, expr)                        \
    auto var = (expr);                                  \
    if (!var) {                                         \
        return std::unexpected{std::move(var).error()}; \
    }

// hello and challenge carry the same fields.
template <class M>
concept hello_like = std::same_as<M, hello> || std::same_as<M, challenge>;

template <hello_like M>
[[nodiscard]] value hello_value(const M& m) {
    return map_builder{}.set("rev", m.revision).set("platform", m.platform).set("auth", m.auth).done();
}

template <hello_like M>
[[nodiscard]] result<M> read_hello(const value& v, std::string_view what) {
    RHP_WIRE_READ(in, read_map(v, what));
    RHP_WIRE_READ(rev, in->field<std::uint8_t>("rev"));
    RHP_WIRE_READ(platform, in->field_or<std::string>("platform", {}));
    return M{*rev, std::move(*platform), in->raw("auth")};
}

// An envelope's req and idem; the caller copies or moves the body.
[[nodiscard]] result<envelope> envelope_head(const value& v) {
    RHP_WIRE_READ(in, read_map(v, "envelope"));
    RHP_WIRE_READ(req, in->field_or<std::uint64_t>("req", 0));
    RHP_WIRE_READ(idem, in->field_or<std::uint64_t>("idem", 0));
    return envelope{*req, *idem, value{}};
}

} // namespace

value envelope_value(std::uint64_t req, std::uint64_t idem, value body) {
    map_builder b;
    b.set("req", req);
    if (idem != 0) {
        b.set("idem", idem);
    }
    b.set("body", std::move(body));
    return b.done();
}

result<envelope> take_envelope(value v) {
    RHP_WIRE_READ(out, envelope_head(v));
    for (auto& [key, item] : *v.get_if<value::map>()) {
        if (const auto* name = key.get_if<std::string>(); name != nullptr && *name == "body") {
            out->body = std::move(item);
            break;
        }
    }
    return out;
}

} // namespace Rhp::wire

namespace Rhp {

// ---- handshake -------------------------------------------------------------------------------------

value convert<wire::hello>::to_value(const wire::hello& m) {
    return wire::hello_value(m);
}

result<wire::hello> convert<wire::hello>::from_value(const value& v) {
    return wire::read_hello<wire::hello>(v, "hello");
}

value convert<wire::challenge>::to_value(const wire::challenge& m) {
    return wire::hello_value(m);
}

result<wire::challenge> convert<wire::challenge>::from_value(const value& v) {
    return wire::read_hello<wire::challenge>(v, "challenge");
}

value convert<wire::response>::to_value(const wire::response& m) {
    return wire::map_builder{}.set("auth", m.auth).done();
}

result<wire::response> convert<wire::response>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "response"));
    return wire::response{in->raw("auth")};
}

value convert<wire::welcome>::to_value(const wire::welcome& m) {
    return wire::map_builder{}
        .set("session", m.session)
        .set("identity", m.identity)
        .set("role", value{to_string(m.granted)})
        .set("heartbeat_ms", m.heartbeat_ms)
        .set("platform", m.platform)
        .done();
}

result<wire::welcome> convert<wire::welcome>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "welcome"));
    RHP_WIRE_READ(session, in->field<session_id>("session"));
    RHP_WIRE_READ(identity, in->field<std::string>("identity"));
    const value* role_name = v.find("role");
    const auto* name = role_name != nullptr ? role_name->get_if<std::string>() : nullptr;
    const std::optional<role> granted = name != nullptr ? parse_role(*name) : std::nullopt;
    if (!granted) {
        return fail(errc::kProtocol, "unknown role", "wire.welcome.role");
    }
    RHP_WIRE_READ(heartbeat, in->field_or<std::uint32_t>("heartbeat_ms", 0));
    RHP_WIRE_READ(platform, in->field_or<std::string>("platform", {}));
    return wire::welcome{*session, std::move(*identity), *granted, *heartbeat, std::move(*platform)};
}

value convert<wire::resume>::to_value(const wire::resume& m) {
    return wire::map_builder{}.set("session", m.session).set("proof", m.proof).done();
}

result<wire::resume> convert<wire::resume>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "resume"));
    RHP_WIRE_READ(session, in->field<session_id>("session"));
    RHP_WIRE_READ(proof, in->raw_or_empty<value::bytes>("proof"));
    return wire::resume{*session, std::move(*proof)};
}

// ---- envelope and requests -----------------------------------------------------------------------

value convert<wire::envelope>::to_value(const wire::envelope& m) {
    return wire::envelope_value(m.req, m.idem, m.body);
}

result<wire::envelope> convert<wire::envelope>::from_value(const value& v) {
    RHP_WIRE_READ(out, wire::envelope_head(v));
    out->body = wire::field_value(v, "body");
    return out;
}

value convert<wire::module_ref>::to_value(const wire::module_ref& m) {
    return m.id ? Rhp::to_value(m.id) : value{m.name};
}

result<wire::module_ref> convert<wire::module_ref>::from_value(const value& v) {
    if (v.is_string()) {
        return wire::module_ref{*v.get_if<std::string>()};
    }
    RHP_WIRE_READ(id, Rhp::from_value<module_id>(v));
    return wire::module_ref{*id};
}

value convert<wire::exec_request>::to_value(const wire::exec_request& m) {
    return wire::map_builder{}.set("source", m.source).set("chunk", m.chunk).set("signature", m.signature).done();
}

result<wire::exec_request> convert<wire::exec_request>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "exec"));
    RHP_WIRE_READ(source, in->field<std::string>("source"));
    RHP_WIRE_READ(chunk, in->field_or<std::string>("chunk", "exec"));
    return wire::exec_request{std::move(*source), std::move(*chunk), in->raw("signature")};
}

value convert<wire::load_request>::to_value(const wire::load_request& m) {
    return wire::map_builder{}.set("name", m.name).set("source", m.source).set("signature", m.signature).done();
}

result<wire::load_request> convert<wire::load_request>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "load"));
    RHP_WIRE_READ(name, in->field<std::string>("name"));
    RHP_WIRE_READ(source, in->field<std::string>("source"));
    return wire::load_request{std::move(*name), std::move(*source), in->raw("signature")};
}

value convert<wire::call_request>::to_value(const wire::call_request& m) {
    return wire::map_builder{}.set("module", m.module).set("function", m.function).set("args", value{m.args}).done();
}

result<wire::call_request> convert<wire::call_request>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "call"));
    RHP_WIRE_READ(module, in->field<wire::module_ref>("module"));
    RHP_WIRE_READ(function, in->field<std::string>("function"));
    RHP_WIRE_READ(args, in->raw_or_empty<value::array>("args"));
    return wire::call_request{std::move(*module), std::move(*function), std::move(*args)};
}

value convert<wire::reload_request>::to_value(const wire::reload_request& m) {
    return wire::map_builder{}.set("module", m.module).set("source", m.source).set("signature", m.signature).done();
}

result<wire::reload_request> convert<wire::reload_request>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "reload"));
    RHP_WIRE_READ(module, in->field<wire::module_ref>("module"));
    RHP_WIRE_READ(source, in->field<std::string>("source"));
    return wire::reload_request{std::move(*module), std::move(*source), in->raw("signature")};
}

value convert<wire::rollback_request>::to_value(const wire::rollback_request& m) {
    return wire::map_builder{}.set("module", m.module).set("steps", m.steps).done();
}

result<wire::rollback_request> convert<wire::rollback_request>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "rollback"));
    RHP_WIRE_READ(module, in->field<wire::module_ref>("module"));
    RHP_WIRE_READ(steps, in->field_or<std::uint64_t>("steps", 1));
    return wire::rollback_request{std::move(*module), *steps};
}

value convert<wire::unload_request>::to_value(const wire::unload_request& m) {
    return wire::map_builder{}.set("module", m.module).set("force", m.force).done();
}

result<wire::unload_request> convert<wire::unload_request>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "unload"));
    RHP_WIRE_READ(module, in->field<wire::module_ref>("module"));
    RHP_WIRE_READ(force, in->field_or<bool>("force", false));
    return wire::unload_request{std::move(*module), *force};
}

value convert<wire::module_request>::to_value(const wire::module_request& m) {
    return wire::map_builder{}.set("module", m.module).done();
}

result<wire::module_request> convert<wire::module_request>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "module request"));
    RHP_WIRE_READ(module, in->field<wire::module_ref>("module"));
    return wire::module_request{std::move(*module)};
}

value convert<wire::tag_request>::to_value(const wire::tag_request& m) {
    return wire::map_builder{}.set("tag", m.tag).done();
}

result<wire::tag_request> convert<wire::tag_request>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "tag request"));
    RHP_WIRE_READ(tag, in->field<std::string>("tag"));
    return wire::tag_request{std::move(*tag)};
}

value convert<wire::cancel_request>::to_value(const wire::cancel_request& m) {
    return wire::map_builder{}.set("target", m.target).done();
}

result<wire::cancel_request> convert<wire::cancel_request>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "cancel"));
    RHP_WIRE_READ(target, in->field_or<std::uint64_t>("target", 0));
    return wire::cancel_request{*target};
}

value convert<wire::blob_chunk>::to_value(const wire::blob_chunk& m) {
    return wire::map_builder{}
        .set("transfer", m.transfer)
        .set("sink", m.sink)
        .set("name", m.name)
        .set("total", m.total)
        .set("offset", m.offset)
        .set("data", m.data)
        .done();
}

result<wire::blob_chunk> convert<wire::blob_chunk>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "blob"));
    RHP_WIRE_READ(transfer, in->field<std::uint64_t>("transfer"));
    RHP_WIRE_READ(sink, in->field<std::string>("sink"));
    RHP_WIRE_READ(name, in->field_or<std::string>("name", {}));
    RHP_WIRE_READ(total, in->field<std::uint64_t>("total"));
    RHP_WIRE_READ(offset, in->field<std::uint64_t>("offset"));
    RHP_WIRE_READ(data, in->raw_or_empty<value::bytes>("data"));
    return wire::blob_chunk{*transfer, std::move(*sink), std::move(*name), *total, *offset, std::move(*data)};
}

// ---- replies -------------------------------------------------------------------------------------

value convert<wire::revert_summary>::to_value(const wire::revert_summary& m) {
    return wire::map_builder{}.set("undone", m.undone).set("irreversible", m.irreversible).set("failures", m.failures).set("deferred", m.deferred).done();
}

result<wire::revert_summary> convert<wire::revert_summary>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "revert summary"));
    RHP_WIRE_READ(undone, in->field_or<std::uint64_t>("undone", 0));
    RHP_WIRE_READ(irreversible, in->field_or<std::uint64_t>("irreversible", 0));
    RHP_WIRE_READ(failures, in->field_or<std::vector<error>>("failures", {}));
    RHP_WIRE_READ(deferred, in->field_or<bool>("deferred", false));
    return wire::revert_summary{*undone, *irreversible, std::move(*failures), *deferred};
}

value convert<wire::module_status>::to_value(const wire::module_status& m) {
    wire::map_builder b;
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

result<wire::module_status> convert<wire::module_status>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "module status"));
    wire::module_status s;
    RHP_WIRE_READ(id, in->field<module_id>("id"));
    RHP_WIRE_READ(name, in->field<std::string>("name"));
    RHP_WIRE_READ(state, in->field<std::string>("state"));
    RHP_WIRE_READ(scratch, in->field_or<bool>("scratch", false));
    RHP_WIRE_READ(effects, in->field_or<std::uint64_t>("effects", 0));
    RHP_WIRE_READ(irreversible, in->field_or<std::uint64_t>("irreversible_effects", 0));
    RHP_WIRE_READ(revision, in->field_or<revision_id>("revision", {}));
    RHP_WIRE_READ(hash, in->field_or<std::uint32_t>("source_hash", 0));
    RHP_WIRE_READ(revisions, in->field_or<std::uint64_t>("revisions", 0));
    RHP_WIRE_READ(reloading, in->field_or<bool>("reloading", false));
    RHP_WIRE_READ(dependencies, in->field_or<std::vector<module_id>>("dependencies", {}));
    RHP_WIRE_READ(pinned, in->field_or<bool>("pinned", false));
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
        RHP_WIRE_READ(fault, Rhp::from_value<error>(*f));
        s.fault = std::move(*fault);
    }
    return s;
}

value convert<wire::emit_message>::to_value(const wire::emit_message& m) {
    return wire::map_builder{}.set("module", m.module).set("value", m.data).done();
}

result<wire::emit_message> convert<wire::emit_message>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "emit"));
    RHP_WIRE_READ(module, in->field_or<module_id>("module", {}));
    return wire::emit_message{*module, in->raw("value")};
}

value convert<wire::subscribe_request>::to_value(const wire::subscribe_request& m) {
    return wire::map_builder{}.set("name", m.name).done();
}

result<wire::subscribe_request> convert<wire::subscribe_request>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "subscribe"));
    RHP_WIRE_READ(name, in->field<std::string>("name"));
    return wire::subscribe_request{std::move(*name)};
}

value convert<wire::event_message>::to_value(const wire::event_message& m) {
    return wire::map_builder{}.set("name", m.name).set("module", m.module).set("args", value{m.args}).set("dropped", m.dropped).done();
}

result<wire::event_message> convert<wire::event_message>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "event"));
    RHP_WIRE_READ(name, in->field<std::string>("name"));
    RHP_WIRE_READ(module, in->field_or<module_id>("module", {}));
    RHP_WIRE_READ(dropped, in->field_or<std::uint64_t>("dropped", 0));
    RHP_WIRE_READ(args, in->raw_or_empty<value::array>("args"));
    return wire::event_message{std::move(*name), *module, std::move(*args), *dropped};
}

// ---- releases ------------------------------------------------------------------------------------

value convert<wire::release_apply_request>::to_value(const wire::release_apply_request& m) {
    return wire::map_builder{}.set("envelope", m.envelope).set("confirm", m.confirm).done();
}

result<wire::release_apply_request> convert<wire::release_apply_request>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "release_apply"));
    RHP_WIRE_READ(envelope, in->field<value::bytes>("envelope"));
    RHP_WIRE_READ(confirm, in->field_or<std::string>("confirm", "now"));
    return wire::release_apply_request{std::move(*envelope), std::move(*confirm)};
}

value convert<wire::release_channel_request>::to_value(const wire::release_channel_request& m) {
    return wire::map_builder{}.set("channel", m.channel).set("hold", m.hold).set("release", m.release).done();
}

result<wire::release_channel_request> convert<wire::release_channel_request>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "release_channel"));
    RHP_WIRE_READ(channel, in->field<std::string>("channel"));
    RHP_WIRE_READ(hold, in->field_or<bool>("hold", false));
    RHP_WIRE_READ(release, in->field_or<value::bytes>("release", {}));
    return wire::release_channel_request{std::move(*channel), *hold, std::move(*release)};
}

value convert<wire::revoke_request>::to_value(const wire::revoke_request& m) {
    return wire::map_builder{}.set("envelope", m.envelope).done();
}

result<wire::revoke_request> convert<wire::revoke_request>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "revoke"));
    RHP_WIRE_READ(envelope, in->field<value::bytes>("envelope"));
    return wire::revoke_request{std::move(*envelope)};
}

value convert<wire::release_info_message>::to_value(const wire::release_info_message& m) {
    return wire::map_builder{}.set("id", m.id).set("seq", m.seq).set("label", m.label).set("signers", m.signers).done();
}

result<wire::release_info_message> convert<wire::release_info_message>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "release_info"));
    RHP_WIRE_READ(id, in->field<value::bytes>("id"));
    RHP_WIRE_READ(seq, in->field_or<std::uint64_t>("seq", 0));
    RHP_WIRE_READ(label, in->field_or<std::string>("label", {}));
    RHP_WIRE_READ(signers, in->field_or<std::vector<std::string>>("signers", {}));
    return wire::release_info_message{std::move(*id), *seq, std::move(*label), std::move(*signers)};
}

value convert<wire::release_apply_reply>::to_value(const wire::release_apply_reply& m) {
    return wire::map_builder{}
        .set("channel", m.channel)
        .set("id", m.id)
        .set("seq", m.seq)
        .set("running", m.running)
        .set("already", m.already)
        .set("replaced", m.replaced)
        .set("signers", m.signers)
        .done();
}

result<wire::release_apply_reply> convert<wire::release_apply_reply>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "release_apply reply"));
    RHP_WIRE_READ(channel, in->field<std::string>("channel"));
    RHP_WIRE_READ(id, in->field<value::bytes>("id"));
    RHP_WIRE_READ(seq, in->field_or<std::uint64_t>("seq", 0));
    RHP_WIRE_READ(running, in->field_or<std::string>("running", "active"));
    RHP_WIRE_READ(already, in->field_or<bool>("already", false));
    RHP_WIRE_READ(replaced, in->field_or<value::bytes>("replaced", {}));
    RHP_WIRE_READ(signers, in->field_or<std::vector<std::string>>("signers", {}));
    return wire::release_apply_reply{std::move(*channel), std::move(*id), *seq, std::move(*running), *already, std::move(*replaced), std::move(*signers)};
}

value convert<wire::channel_status_message>::to_value(const wire::channel_status_message& m) {
    return wire::map_builder{}
        .set("channel", m.channel)
        .set("running", m.running)
        .set("active", m.active)
        .set("candidate", m.candidate)
        .set("previous", m.previous)
        .set("floor", m.floor)
        .set("held", m.held)
        .set("attempts", m.attempts)
        .set("confirm", m.confirm)
        .set("handler_failures", m.handler_failures)
        .set("modules", m.modules)
        .done();
}

result<wire::channel_status_message> convert<wire::channel_status_message>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "channel_status"));
    wire::channel_status_message out;
    RHP_WIRE_READ(channel, in->field<std::string>("channel"));
    RHP_WIRE_READ(running, in->field_or<std::string>("running", "empty"));
    // Not field_or: a bad release_info keeps its own `where`.
    for (const auto& [key, slot] : {std::pair{"active", &out.active}, std::pair{"candidate", &out.candidate}}) {
        const value* f = v.find(key);
        if (f != nullptr && !f->is_nil()) {
            RHP_WIRE_READ(info, Rhp::from_value<wire::release_info_message>(*f));
            *slot = std::move(*info);
        }
    }
    RHP_WIRE_READ(previous, in->field_or<value::bytes>("previous", {}));
    RHP_WIRE_READ(floor, in->field_or<std::uint64_t>("floor", 0));
    RHP_WIRE_READ(held, in->field_or<bool>("held", false));
    RHP_WIRE_READ(attempts, in->field_or<std::uint64_t>("attempts", 0));
    RHP_WIRE_READ(confirm, in->field_or<std::string>("confirm", "now"));
    RHP_WIRE_READ(failures, in->field_or<std::uint64_t>("handler_failures", 0));
    RHP_WIRE_READ(modules, in->field_or<std::vector<std::string>>("modules", {}));
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

value convert<wire::release_status_reply>::to_value(const wire::release_status_reply& m) {
    return wire::map_builder{}
        .set("app", m.app)
        .set("build", m.build)
        .set("platform", m.platform)
        .set("revocation_seq", m.revocation_seq)
        .set("channels", m.channels)
        .set("root_version", m.root_version)
        .set("identity_seq", m.identity_seq)
        .done();
}

result<wire::release_status_reply> convert<wire::release_status_reply>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "release_status reply"));
    RHP_WIRE_READ(app, in->field_or<std::string>("app", {}));
    RHP_WIRE_READ(build, in->field_or<std::string>("build", {}));
    RHP_WIRE_READ(platform, in->field_or<std::string>("platform", {}));
    RHP_WIRE_READ(seq, in->field_or<std::uint64_t>("revocation_seq", 0));
    // Its errors say "release_status", not "release_status reply".
    RHP_WIRE_READ(channels, wire::message_list<wire::channel_status_message>(v, "channels", "release_status"));
    RHP_WIRE_READ(root_version, in->field_or<std::uint64_t>("root_version", 0));
    RHP_WIRE_READ(identity_seq, in->field_or<std::uint64_t>("identity_seq", 0));
    return wire::release_status_reply{std::move(*app), std::move(*build), std::move(*platform), *seq, std::move(*channels), *root_version, *identity_seq};
}

value convert<wire::trust_request>::to_value(const wire::trust_request& m) {
    return wire::map_builder{}.set("documents", m.documents).done();
}

result<wire::trust_request> convert<wire::trust_request>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "trust"));
    RHP_WIRE_READ(documents, in->field<std::vector<value::bytes>>("documents"));
    return wire::trust_request{std::move(*documents)};
}

value convert<wire::trust_reply>::to_value(const wire::trust_reply& m) {
    return wire::map_builder{}.set("root_version", m.root_version).set("identity_seq", m.identity_seq).done();
}

result<wire::trust_reply> convert<wire::trust_reply>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "trust reply"));
    RHP_WIRE_READ(root_version, in->field_or<std::uint64_t>("root_version", 0));
    RHP_WIRE_READ(identity_seq, in->field_or<std::uint64_t>("identity_seq", 0));
    return wire::trust_reply{*root_version, *identity_seq};
}

// ---- Stage 11: tunables, profiler, debugger ----------------------------------------------------------

value convert<wire::tunables_request>::to_value(const wire::tunables_request& m) {
    return wire::map_builder{}.set("prefix", m.prefix).done();
}

result<wire::tunables_request> convert<wire::tunables_request>::from_value(const value& v) {
    if (v.is_nil()) {
        return wire::tunables_request{};
    }
    RHP_WIRE_READ(in, wire::read_map(v, "tunables"));
    RHP_WIRE_READ(prefix, in->field_or<std::string>("prefix", {}));
    return wire::tunables_request{std::move(*prefix)};
}

value convert<wire::tunable_message>::to_value(const wire::tunable_message& m) {
    return wire::map_builder{}
        .set("path", m.path)
        .set("type", m.type)
        .set("value", m.current)
        .set("writable", m.writable)
        .set("min", m.min)
        .set("max", m.max)
        .set("step", m.step)
        .set("unit", m.unit)
        .set("doc", m.doc)
        .done();
}

result<wire::tunable_message> convert<wire::tunable_message>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "tunable"));
    RHP_WIRE_READ(path, in->field<std::string>("path"));
    RHP_WIRE_READ(type, in->field_or<std::string>("type", "any"));
    RHP_WIRE_READ(writable, in->field_or<bool>("writable", false));
    RHP_WIRE_READ(min, in->field_or<std::optional<double>>("min", std::nullopt));
    RHP_WIRE_READ(max, in->field_or<std::optional<double>>("max", std::nullopt));
    RHP_WIRE_READ(step, in->field_or<std::optional<double>>("step", std::nullopt));
    RHP_WIRE_READ(unit, in->field_or<std::string>("unit", {}));
    RHP_WIRE_READ(doc, in->field_or<std::string>("doc", {}));
    return wire::tunable_message{std::move(*path), std::move(*type), in->raw("value"), *writable, *min, *max, *step, std::move(*unit), std::move(*doc)};
}

value convert<wire::tune_request>::to_value(const wire::tune_request& m) {
    return wire::map_builder{}.set("path", m.path).set("value", m.to).done();
}

result<wire::tune_request> convert<wire::tune_request>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "tune"));
    RHP_WIRE_READ(path, in->field<std::string>("path"));
    if (v.find("value") == nullptr) {
        return fail(errc::kProtocol, "tune has no 'value'", "wire");
    }
    return wire::tune_request{std::move(*path), in->raw("value")};
}

value convert<wire::profile_request>::to_value(const wire::profile_request& m) {
    return wire::map_builder{}.set("action", m.action).set("interval", m.interval).set("max_depth", m.max_depth).set("max_stacks", m.max_stacks).done();
}

result<wire::profile_request> convert<wire::profile_request>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "profile"));
    RHP_WIRE_READ(action, in->field_or<std::string>("action", "read"));
    RHP_WIRE_READ(interval, in->field_or<std::uint32_t>("interval", 1000));
    RHP_WIRE_READ(depth, in->field_or<std::uint64_t>("max_depth", 64));
    RHP_WIRE_READ(stacks, in->field_or<std::uint64_t>("max_stacks", 10'000));
    return wire::profile_request{std::move(*action), *interval, *depth, *stacks};
}

value convert<wire::profile_stack_message>::to_value(const wire::profile_stack_message& m) {
    return value{value::array{value{m.stack}, value{m.samples}}}; // [stack, samples]: a report holds thousands
}

result<wire::profile_stack_message> convert<wire::profile_stack_message>::from_value(const value& v) {
    const auto* pair = v.get_if<value::array>();
    if (pair == nullptr || pair->size() != 2) {
        return fail(errc::kProtocol, "a profile stack is [stack, samples]", "wire");
    }
    auto stack = Rhp::from_value<std::string>((*pair)[0]);
    auto samples = Rhp::from_value<std::uint64_t>((*pair)[1]);
    if (!stack || !samples) {
        return fail(errc::kProtocol, "a profile stack is [stack, samples]", "wire");
    }
    return wire::profile_stack_message{std::move(*stack), *samples};
}

value convert<wire::profile_reply>::to_value(const wire::profile_reply& m) {
    return wire::map_builder{}
        .set("running", m.running)
        .set("interval", m.interval)
        .set("samples", m.samples)
        .set("dropped", m.dropped)
        .set("elapsed_us", m.elapsed_us)
        .set("stacks", m.stacks)
        .set("truncated", m.truncated)
        .done();
}

result<wire::profile_reply> convert<wire::profile_reply>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "profile reply"));
    RHP_WIRE_READ(running, in->field_or<bool>("running", false));
    RHP_WIRE_READ(interval, in->field_or<std::uint32_t>("interval", 0));
    RHP_WIRE_READ(samples, in->field_or<std::uint64_t>("samples", 0));
    RHP_WIRE_READ(dropped, in->field_or<std::uint64_t>("dropped", 0));
    RHP_WIRE_READ(elapsed, in->field_or<std::uint64_t>("elapsed_us", 0));
    RHP_WIRE_READ(stacks, in->list<wire::profile_stack_message>("stacks"));
    RHP_WIRE_READ(truncated, in->field_or<std::uint64_t>("truncated", 0));
    return wire::profile_reply{*running, *interval, *samples, *dropped, *elapsed, std::move(*stacks), *truncated};
}

value convert<wire::debug_request>::to_value(const wire::debug_request& m) {
    return wire::map_builder{}
        .set("action", m.action)
        .set("source", m.source)
        .set("lines", m.lines)
        .set("request", m.request)
        .set("frame", m.frame)
        .set("scope", m.scope)
        .set("path", m.path)
        .set("expression", m.expression)
        .done();
}

result<wire::debug_request> convert<wire::debug_request>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "debug"));
    RHP_WIRE_READ(action, in->field<std::string>("action"));
    RHP_WIRE_READ(source, in->field_or<std::string>("source", {}));
    RHP_WIRE_READ(lines, in->field_or<std::vector<std::uint32_t>>("lines", {}));
    RHP_WIRE_READ(request, in->field_or<std::uint64_t>("request", 0));
    RHP_WIRE_READ(frame, in->field_or<std::uint32_t>("frame", 0));
    RHP_WIRE_READ(scope, in->field_or<std::string>("scope", "locals"));
    RHP_WIRE_READ(path, in->field_or<std::vector<std::string>>("path", {}));
    RHP_WIRE_READ(expression, in->field_or<std::string>("expression", {}));
    return wire::debug_request{std::move(*action), std::move(*source), std::move(*lines), *request, *frame, std::move(*scope), std::move(*path), std::move(*expression)};
}

value convert<wire::debug_stop_message>::to_value(const wire::debug_stop_message& m) {
    return wire::map_builder{}
        .set("request", m.request)
        .set("label", m.label)
        .set("reason", m.reason)
        .set("source", m.source)
        .set("line", m.line)
        .set("module", m.module)
        .done();
}

result<wire::debug_stop_message> convert<wire::debug_stop_message>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "debug stop"));
    RHP_WIRE_READ(request, in->field<std::uint64_t>("request"));
    RHP_WIRE_READ(label, in->field_or<std::string>("label", {}));
    RHP_WIRE_READ(reason, in->field_or<std::string>("reason", {}));
    RHP_WIRE_READ(source, in->field_or<std::string>("source", {}));
    RHP_WIRE_READ(line, in->field_or<std::uint32_t>("line", 0));
    RHP_WIRE_READ(module, in->field_or<std::uint64_t>("module", 0));
    return wire::debug_stop_message{*request, std::move(*label), std::move(*reason), std::move(*source), *line, *module};
}

value convert<wire::debug_frame_message>::to_value(const wire::debug_frame_message& m) {
    return wire::map_builder{}
        .set("level", m.level)
        .set("name", m.name)
        .set("what", m.what)
        .set("source", m.source)
        .set("line", m.line)
        .set("defined", m.defined)
        .done();
}

result<wire::debug_frame_message> convert<wire::debug_frame_message>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "debug frame"));
    RHP_WIRE_READ(level, in->field_or<std::uint32_t>("level", 0));
    RHP_WIRE_READ(name, in->field_or<std::string>("name", "?"));
    RHP_WIRE_READ(what, in->field_or<std::string>("what", {}));
    RHP_WIRE_READ(source, in->field_or<std::string>("source", {}));
    RHP_WIRE_READ(line, in->field_or<std::uint32_t>("line", 0));
    RHP_WIRE_READ(defined, in->field_or<std::uint32_t>("defined", 0));
    return wire::debug_frame_message{*level, std::move(*name), std::move(*what), std::move(*source), *line, *defined};
}

value convert<wire::debug_variable_message>::to_value(const wire::debug_variable_message& m) {
    return wire::map_builder{}.set("name", m.name).set("type", m.type).set("text", m.text).set("expandable", m.expandable).done();
}

result<wire::debug_variable_message> convert<wire::debug_variable_message>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "debug variable"));
    RHP_WIRE_READ(name, in->field_or<std::string>("name", {}));
    RHP_WIRE_READ(type, in->field_or<std::string>("type", {}));
    RHP_WIRE_READ(text, in->field_or<std::string>("text", {}));
    RHP_WIRE_READ(expandable, in->field_or<bool>("expandable", false));
    return wire::debug_variable_message{std::move(*name), std::move(*type), std::move(*text), *expandable};
}

value convert<wire::debug_reply>::to_value(const wire::debug_reply& m) {
    return wire::map_builder{}
        .set("lines", m.lines)
        .set("paused", m.paused)
        .set("frames", m.frames)
        .set("variables", m.variables)
        .done();
}

result<wire::debug_reply> convert<wire::debug_reply>::from_value(const value& v) {
    RHP_WIRE_READ(in, wire::read_map(v, "debug reply"));
    RHP_WIRE_READ(lines, in->field_or<std::vector<std::uint32_t>>("lines", {}));
    RHP_WIRE_READ(paused, in->list<wire::debug_stop_message>("paused"));
    RHP_WIRE_READ(frames, in->list<wire::debug_frame_message>("frames"));
    RHP_WIRE_READ(variables, in->list<wire::debug_variable_message>("variables"));
    return wire::debug_reply{std::move(*lines), std::move(*paused), std::move(*frames), std::move(*variables)};
}

} // namespace Rhp

#undef RHP_WIRE_READ

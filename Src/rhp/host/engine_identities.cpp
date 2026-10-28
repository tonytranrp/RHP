// The host engine on the pump thread: sessions opening and closing, identities' sandboxes (made,
// reverted, released), host events, script events and remote subscriptions.

#include <rhp/host/detail/engine_impl.hpp>

namespace Rhp::host_detail {

void engine::publish(event::any e) {
    if (setup_.events == nullptr) {
        return;
    }
    try {
        setup_.events->publish(e);
    } catch (const std::exception& ex) {
        log(log_level::kError, "an event handler threw: {}", ex.what());
    } catch (...) {
        log_text(log_level::kError, "an event handler threw");
    }
}

void engine::process(std::vector<inbound>& batch) {
    for (inbound& in : batch) {
        switch (in.what) {
        case inbound::kind::kOpened: opened(in); break;
        case inbound::kind::kClosed: closed(in); break;
        case inbound::kind::kRequest: admit(in); break;
        case inbound::kind::kAuthFailed:
            if (wants<event::auth_failed>()) {
                publish(event::auth_failed{now(), std::move(in.peer), std::move(in.reason), std::move(in.identity)});
            }
            break;
        case inbound::kind::kResumed:
            if (wants<event::session_resumed>()) {
                publish(event::session_resumed{now(), in.session, in.identity, std::move(in.peer), in.tls});
            }
            break;
        }
    }
}

void engine::opened(inbound& in) {
    pump_session fresh;
    fresh.identity = in.identity;
    fresh.granted = in.granted;
    fresh.scopes = in.scopes;
    fresh.peer = in.peer;
    pump_sessions_[in.session] = std::move(fresh);
    auto it = identities_.find(in.identity);
    if (it == identities_.end()) {
        identity_runtime rt;
        rt.name = in.identity;
        rt.relay = in.relay;
        rt.box = std::make_unique<script::sandbox>(sandbox_options_for(in.identity, in.granted, in.scopes));
        for (const auto& [name, fn] : installers_) {
            if (auto ok = fn(*rt.box); !ok) {
                log(log_level::kWarn, "install {} into identity {}: {}", name, in.identity, ok.error());
            }
        }
        {
            const std::scoped_lock lock{rt.relay->mutex};
            rt.relay->box = rt.box.get();
        }
        rt.script_listener =
            rt.box->on_script_event("*", [this, identity = in.identity](const script::script_event& e) { forward_script_event(identity, e); });
        it = identities_.emplace(in.identity, std::move(rt)).first;
        identity_count_.store(identities_.size(), std::memory_order_release);
        log(log_level::kInfo, "identity {} ({}) has a sandbox", in.identity, in.granted);
    } else if (it->second.relay != in.relay) {
        // The identity outlived its sessions (pinned modules) and the network made a new relay
        // for the one that just arrived: hand it the sandbox.
        identity_runtime& rt = it->second;
        {
            const std::scoped_lock lock{rt.relay->mutex};
            rt.relay->box = nullptr;
        }
        rt.relay = in.relay;
        const std::scoped_lock lock{rt.relay->mutex};
        rt.relay->box = rt.box.get();
    }
    it->second.sessions.insert(in.session);
    if (wants<event::session_opened>()) {
        publish(event::session_opened{now(), in.session, in.identity, in.granted, std::move(in.peer), std::move(in.platform), in.tls});
    }
}

void engine::closed(inbound& in) {
    if (const auto it = identities_.find(in.identity); it != identities_.end()) {
        drop_queued(it->second, in.session);
    }
    if (const auto ps = pump_sessions_.find(in.session); ps != pump_sessions_.end()) {
        for (const std::string& name : ps->second.program_subs) {
            drop_program_sub(name, in.session);
        }
    }
    pump_sessions_.erase(in.session);
    if (wants<event::session_closed>()) {
        publish(event::session_closed{now(), in.session, in.identity, in.peer, in.reason});
    }
    const auto it = identities_.find(in.identity);
    if (it == identities_.end()) {
        return;
    }
    identity_runtime& rt = it->second;
    rt.sessions.erase(in.session);
    std::erase_if(rt.waiting, [&](const auto& entry) { return entry.second.session == in.session; });
    if (rt.debuggers.erase(in.session) != 0 && rt.debuggers.empty()) { // the last debugging session: its breakpoints go, paused scripts run on
        rt.box->debug_reset();
    }
    if (rt.profiler == in.session) {
        rt.profiler = session_id{};
        (void)rt.box->stop_profile();
    }
    {
        // Every request of this session that was queued before its close has been processed.
        const std::scoped_lock lock{rt.relay->mutex};
        std::erase_if(rt.relay->suspended, [&](const auto& entry) { return entry.first.first == in.session.value(); });
        rt.relay->cancels.erase(in.session.value());
    }
    if (!rt.sessions.empty()) {
        return;
    }
    if (!rt.pinned.empty()) {
        release(rt);
        return;
    }
    teardown(rt);
    identities_.erase(it);
    identity_count_.store(identities_.size(), std::memory_order_release);
}

void engine::detach_relay(identity_runtime& rt) {
    const std::scoped_lock lock{rt.relay->mutex};
    rt.relay->box = nullptr;
    rt.relay->suspended.clear();
    rt.relay->cancels.clear();
}

void engine::teardown(identity_runtime& rt) {
    detach_relay(rt);
    const script::revert_report report = rt.box->revert_all();
    // Asynchronous calls still running for it: a success arriving later is still taken back.
    if (script::async_leftovers left = rt.box->release_async(); !left.empty()) {
        async_leftovers_.push_back(std::move(left));
    }
    rt.box.reset();
    rt.pinned.clear();
    for (auto& [r, record] : std::exchange(rt.audits, {})) {
        record.outcome = make_error(errc::kCancelled, "the identity was reverted before the request finished", record.op);
        publish(std::move(record));
    }
    log(log_level::kInfo, "identity {} reverted: {} effects undone, {} irreversible, {} failures", rt.name, report.undone, report.irreversible,
        report.failures.size());
    if (wants<event::identity_reverted>()) {
        publish(event::identity_reverted{now(), rt.name, report.undone, report.irreversible, report.failures.size(), 0});
    }
}

void engine::release(identity_runtime& rt) {
    detach_relay(rt);
    const std::vector<script::module_info> modules = rt.box->list();
    std::set<module_id> keep = rt.pinned;
    for (bool grew = true; grew;) {
        grew = false;
        for (const script::module_info& m : modules) {
            if (keep.contains(m.id)) {
                for (const module_id dep : m.dependencies) {
                    grew = keep.insert(dep).second || grew;
                }
            }
        }
    }
    script::revert_report report;
    for (const script::module_info& m : modules) {
        if (m.scratch || keep.contains(m.id)) {
            continue;
        }
        if (auto r = rt.box->unload(m.id, script::force)) {
            report += std::move(*r);
        }
    }
    if (auto r = rt.box->revert(rt.box->scratch_module())) {
        report += std::move(*r);
    }
    rt.box->restore_builtins(); // shared by every module (decision AL3): the pinned ones get them as they were made
    log(log_level::kInfo, "identity {} released: {} effects undone, {} pinned modules kept", rt.name, report.undone, rt.pinned.size());
    if (wants<event::identity_reverted>()) {
        publish(event::identity_reverted{now(), rt.name, report.undone, report.irreversible, report.failures.size(), rt.pinned.size()});
    }
}

script::sandbox_options engine::sandbox_options_for(const std::string& identity, role granted, const scope_set& scopes) {
    script::sandbox_options o;
    o.caller_role = granted;
    o.scopes = scopes; // libs, caps, patch points and events the identity's scripts may reach
    o.limits = limits_for(granted);
    o.admin_stdlib = setup_.hardening == hardening::kDev;
    o.identity = identity;
    o.clock = setup_.clock;
    o.on_output = [this, identity](request_id r, module_id, std::string_view line) {
        log(log_level::kDebug, "[{}] {}", identity, line);
        route(identity, r, wire::op::kOutput, value{line});
    };
    o.on_emit = [this, identity](request_id r, module_id mod, const value& v) {
        route(identity, r, wire::op::kEmit, Rhp::to_value(wire::emit_message{mod, v}));
    };
    o.on_result = [this, identity](request_id r, const result<script::value_list>& res) { finished(identity, r, res); };
    o.handler_errors = setup_.options.handler_errors;
    o.on_handler_error = [this, identity](const script::handler_failure& f) { handler_failed(identity, f); };
    return o;
}

void engine::handler_failed(const std::string& identity, const script::handler_failure& f) {
    const std::string line =
        std::format("[handler failed] {} ({} {}): {} ({})", f.module_name.empty() ? "?" : f.module_name, f.kind, f.source, f.err, f.action);
    log(log_level::kWarn, "[{}] {}", identity, line);
    route(identity, f.request, wire::op::kOutput, value{line});
    if (wants<event::handler_failed>()) {
        publish(event::handler_failed{now(), identity, f.module_name, std::string{script::to_string(f.kind)}, f.source, f.handler,
                                      std::string{script::to_string(f.action)}, f.err});
    }
}

void engine::forward_script_event(const std::string& identity, const script::script_event& e) {
    if (setup_.script_events != nullptr && setup_.script_events->wants(e.name)) {
        event::script_event copy{now(), identity, std::string{e.module_name}, std::string{e.name}, {e.args.begin(), e.args.end()}};
        try {
            setup_.script_events->publish(copy);
        } catch (const std::exception& ex) {
            log(log_level::kError, "a script event handler threw: {}", ex.what());
        } catch (...) {
            log_text(log_level::kError, "a script event handler threw");
        }
    }
    const auto it = identities_.find(identity);
    if (it == identities_.end()) {
        return;
    }
    for (const session_id s : it->second.sessions) {
        const auto ps = pump_sessions_.find(s);
        if (ps != pump_sessions_.end() && (ps->second.script_subs.contains(e.name) || ps->second.script_subs.contains("*")) &&
            ps->second.scopes.allows(scope_kind::kEvent, e.name)) {
            send_event(s, ps->second, e.name, e.module, e.args);
        }
    }
}

void engine::send_event(session_id s, pump_session& sess, std::string_view name, module_id module, std::span<const value> args) {
    if (sess.sent_this_pump >= setup_.options.remote_events_per_pump) {
        ++sess.dropped;
        return;
    }
    ++sess.sent_this_pump;
    wire::event_message m{std::string{name}, module, value::array{args.begin(), args.end()}, std::exchange(sess.dropped, 0)};
    to_network({s, wire::op::kEvent, 0, Rhp::to_value(m)});
}

void engine::deliver(std::string_view event, const script::detail::event_args& args) {
    send_program_event(event, args.values(args.data));
}

void engine::enqueue(std::string_view event, const script::detail::event_args& args) noexcept {
    try {
        const std::uint32_t cap = setup_.limits.event_queue;
        const std::scoped_lock lock{program_mutex_};
        if (cap != 0 && program_inbox_.size() >= cap) {
            return; // each session's next event says nothing about these: they never queued
        }
        program_inbox_.emplace_back(std::string{event}, args.values(args.data));
    } catch (...) { // out of memory: the clients miss this one
    }
}

void engine::deliver_program_events() {
    std::vector<std::pair<std::string, std::vector<value>>> queued;
    {
        const std::scoped_lock lock{program_mutex_};
        queued.swap(program_inbox_);
    }
    for (const auto& [event, args] : queued) {
        send_program_event(event, args);
    }
}

void engine::send_program_event(std::string_view event, const std::vector<value>& args) {
    const auto subs = program_subs_.find(event);
    if (subs == program_subs_.end()) {
        return;
    }
    for (const session_id s : subs->second) {
        if (const auto ps = pump_sessions_.find(s); ps != pump_sessions_.end()) {
            send_event(s, ps->second, event, module_id{}, args);
        }
    }
}

void engine::drop_program_sub(const std::string& name, session_id s) {
    const auto subs = program_subs_.find(name);
    if (subs == program_subs_.end()) {
        return;
    }
    subs->second.erase(s);
    if (!subs->second.empty()) {
        return;
    }
    program_subs_.erase(subs);
    if (const auto attached = program_attached_.find(name); attached != program_attached_.end()) {
        attached->second->detach(this);
        program_attached_.erase(attached);
    }
}

void engine::subscription_request(pump_session& sess, const inbound& in) {
    auto m = Rhp::from_value<wire::subscribe_request>(in.body);
    if (!m) {
        return reply_error(in.session, in.req, m.error());
    }
    const std::string& name = m->name;
    const std::string_view op = wire::to_string(in.code);
    if (name != "*" && !utils::is_dotted_name(name)) {
        return reply_error(in.session, in.req,
                           make_error(errc::kInvalidArgument, std::format("'{}' is not an event name (dotted lowercase, or *)", name), std::string{op}));
    }
    // The identity's scopes (decision AL13): C++ lua_events and script events alike. "*" (every
    // script event of the identity) is delivered only for the names they allow (forward_script_event).
    if (in.code == wire::op::kSubscribe && name != "*" && !sess.scopes.allows(scope_kind::kEvent, name)) {
        return reply_error(in.session, in.req,
                           make_error(errc::kForbidden, std::format("{} needs scope event:{}, {} lacks it", op, name, sess.identity), std::string{op}));
    }
    script::detail::event_state* state = nullptr;
    if (name != "*") {
        auto found = script::detail::find_event(name);
        if (found) {
            state = (*found)->state;
        } else if (found.error().code != errc::kNotFound) {
            return reply_error(in.session, in.req, make_error(found.error().code, found.error().message, std::string{op}));
        }
    }
    if (in.code == wire::op::kUnsubscribe) {
        if (state != nullptr) {
            if (sess.program_subs.erase(name) != 0) {
                drop_program_sub(name, in.session);
            }
        } else {
            sess.script_subs.erase(name);
        }
        return reply(in.session, in.req, value{});
    }
    if (state != nullptr) {
        if (sess.program_subs.insert(name).second) {
            program_subs_[name].insert(in.session);
            if (!program_attached_.contains(name)) {
                program_attached_.emplace(name, state);
                state->attach(this);
            }
        }
    } else {
        sess.script_subs.insert(name);
    }
    reply(in.session, in.req, value{});
}

void engine::route(const std::string& identity, request_id r, wire::op code, value body) {
    const auto it = identities_.find(identity);
    if (it == identities_.end()) {
        return;
    }
    identity_runtime& rt = it->second;
    // The operation's own request (an event handler started inside it is a request of its own).
    if (rt.current_session && r && r == rt.box->last_request()) {
        to_network({rt.current_session, code, rt.current_req, std::move(body)});
        return;
    }
    if (const auto w = rt.waiting.find(r); w != rt.waiting.end()) {
        to_network({w->second.session, code, w->second.req, std::move(body)});
        return;
    }
    for (const session_id s : rt.sessions) {
        to_network({s, code, 0, body});
    }
}

void engine::finished(const std::string& identity, request_id r, const result<script::value_list>& res) {
    const auto it = identities_.find(identity);
    if (it == identities_.end()) {
        return;
    }
    identity_runtime& rt = it->second;
    if (const auto a = rt.audits.find(r); a != rt.audits.end()) {
        event::script_executed record = std::move(a->second);
        rt.audits.erase(a);
        if (!res) {
            record.outcome = res.error();
        }
        publish(std::move(record));
    }
    const auto w = rt.waiting.find(r);
    if (w == rt.waiting.end()) {
        return; // a timer or event request, or its session is gone
    }
    const pending_reply p = w->second;
    rt.waiting.erase(w);
    {
        const std::scoped_lock lock{rt.relay->mutex};
        rt.relay->suspended.erase({p.session.value(), p.req});
    }
    if (!res) {
        reply_error(p.session, p.req, res.error());
        return;
    }
    switch (p.code) {
    case wire::op::kLoad: reply(p.session, p.req, Rhp::to_value(p.module)); return;
    case wire::op::kReload:
    case wire::op::kRollback: {
        const auto info = rt.box->status(p.module);
        reply(p.session, p.req, Rhp::to_value(info ? info->revision : revision_id{}));
        return;
    }
    default: reply(p.session, p.req, value{value::array(res->begin(), res->end())}); return;
    }
}

} // namespace Rhp::host_detail

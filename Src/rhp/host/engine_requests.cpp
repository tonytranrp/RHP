// The host engine on the pump thread: one request at a time, checked, audited and run against its
// identity's sandbox, and the replies it gets.

#include <rhp/host/detail/engine_impl.hpp>

namespace Rhp::host_detail {

namespace {

[[nodiscard]] wire::revert_summary summarize(const script::revert_report& r) {
    return {r.undone, r.irreversible, r.failures, r.deferred};
}

[[nodiscard]] wire::module_status describe(const script::module_info& m, bool pinned) {
    wire::module_status s;
    s.id = m.id;
    s.name = m.name;
    s.state = std::string{script::to_string(m.state)};
    s.scratch = m.scratch;
    s.effects = m.effects;
    s.irreversible_effects = m.irreversible_effects;
    s.revision = m.revision;
    s.source_hash = m.source_hash;
    s.revisions = m.revisions;
    s.reloading = m.reloading;
    s.dependencies = m.dependencies;
    s.fault = m.fault;
    s.pinned = pinned;
    return s;
}

// Requests the audit log reports (event::script_executed): everything that runs code or changes
// state. Introspection, cancel and blobs (event::blob_received) are left out; of the debugger, the
// actions that change what scripts do (breakpoints, pause, resume, steps, reset).
[[nodiscard]] bool audited(wire::op code, const value& body) noexcept {
    if (code == wire::op::kDebug) {
        const value* action = body.find("action");
        const auto* name = action != nullptr ? action->get_if<std::string>() : nullptr;
        if (name == nullptr) {
            return true;
        }
        return *name != "paused" && *name != "stack" && *name != "variables" && *name != "evaluate";
    }
    switch (code) {
    case wire::op::kList:
    case wire::op::kStatus:
    case wire::op::kDescribe:
    case wire::op::kCancel:
    case wire::op::kBlob:
    case wire::op::kSubscribe:
    case wire::op::kUnsubscribe:
    case wire::op::kReleaseStatus:
    case wire::op::kTunables:
    case wire::op::kProfile: return false;
    default: return true;
    }
}

[[nodiscard]] bool is_release_op(wire::op code) noexcept {
    switch (code) {
    case wire::op::kReleaseApply:
    case wire::op::kReleaseConfirm:
    case wire::op::kReleaseDeactivate:
    case wire::op::kReleaseStatus:
    case wire::op::kRevoke:
    case wire::op::kTrust: return true;
    default: return false;
    }
}

// The report as one reply: stacks (most samples first) up to about a quarter of the frame limit,
// the rest counted as truncated.
[[nodiscard]] wire::profile_reply profile_message(const script::profile_report& r, std::uint32_t max_frame) {
    wire::profile_reply out;
    out.running = r.running;
    out.interval = r.interval;
    out.samples = r.samples;
    out.dropped = r.dropped;
    out.elapsed_us = static_cast<std::uint64_t>(r.elapsed.count());
    const std::size_t budget = std::max<std::size_t>(max_frame / 4, 4096);
    std::size_t used = 0;
    for (const script::profile_stack& s : r.stacks) {
        used += s.stack.size() + 16;
        if (used > budget) {
            out.truncated = r.stacks.size() - out.stacks.size();
            break;
        }
        out.stacks.push_back(wire::profile_stack_message{s.stack, s.samples});
    }
    return out;
}

// Both only for the debugger, which a production build leaves out.
[[nodiscard, maybe_unused]] std::optional<script::debug_scope> parse_scope(std::string_view text) noexcept {
    for (const auto s : {script::debug_scope::kLocals, script::debug_scope::kUpvalues, script::debug_scope::kGlobals}) {
        if (script::to_string(s) == text) {
            return s;
        }
    }
    return std::nullopt;
}

[[nodiscard, maybe_unused]] wire::debug_variable_message variable_message(const script::debug_variable& v) {
    return wire::debug_variable_message{v.name, v.type, v.text, v.expandable};
}

[[nodiscard]] std::string ref_text(const wire::module_ref& ref) {
    return ref.name.empty() ? std::format("#{}", ref.id) : ref.name;
}

// limits.request_rate: a bucket of `rate` tokens refilled at `rate` a second, kept as the time it is
// full again. A request moves that time on by 1/rate; one that would move it more than a second past
// now finds the bucket empty, and takes nothing.
[[nodiscard]] bool take_token(std::chrono::steady_clock::time_point& full, std::chrono::steady_clock::time_point now, std::uint32_t rate) noexcept {
    const auto next = std::max(full, now) + std::chrono::nanoseconds{std::chrono::seconds{1}} / rate;
    if (next - now > std::chrono::seconds{1}) {
        return false;
    }
    full = next;
    return true;
}

// Where a blob chunk says it belongs (transfer 0 for any other request), unchecked: blob() checks it.
struct chunk_info {
    std::uint64_t transfer = 0;
    std::uint64_t offset = 0;
    std::uint64_t total = 0;
    std::uint64_t size = 0; // its data's bytes
};

[[nodiscard]] chunk_info chunk_of(const inbound& in) {
    if (in.code != wire::op::kBlob) {
        return {};
    }
    const auto number = [&](std::string_view key) -> std::uint64_t {
        const value* v = in.body.find(value{key});
        return v != nullptr ? Rhp::from_value<std::uint64_t>(*v).value_or(0) : 0;
    };
    const value* data = in.body.find("data");
    const auto* bytes = data != nullptr ? data->get_if<value::bytes>() : nullptr;
    return {number("transfer"), number("offset"), number("total"), bytes != nullptr ? bytes->size() : 0};
}

} // namespace

void engine::reply_error(session_id s, std::uint64_t req, const error& err) {
    // The request being audited right now failed: its audit record says why.
    if (audit_ != nullptr && s == audit_session_ && req == audit_req_ && audit_->outcome.code == errc::kOk) {
        audit_->outcome = err;
    }
    to_network({s, wire::op::kError, req, Rhp::to_value(err)});
}

void engine::flush_outbox() {
    bool pushed = false;
    while (!outbox_backlog_.empty()) {
        if (!outbox_.try_push(std::move(outbox_backlog_.front()))) {
            break;
        }
        outbox_backlog_.pop_front();
        pushed = true;
    }
    // Wake the network thread only when there is something for it: replies, or requests it is
    // holding back because the inbox was full (pump() just made room).
    if (pushed || !outbox_backlog_.empty() || inbox_backlog_waiting_.load(std::memory_order_acquire)) {
        io_.post([this] { drain_outbox(); });
    }
}

result<module_id> engine::resolve(script::sandbox& box, const wire::module_ref& ref) {
    if (ref.id) {
        return ref.id;
    }
    return box.find(ref.name);
}

result<std::string> engine::check_signature(const pump_session& sess, const inbound& in, std::string_view module, std::string_view source,
                                            const value& signature) {
    if (audit_ != nullptr) {
        audit_->module = module;
        audit_->hash = security::to_hex(security::blake2b_256(source));
    }
    auto who = in.signer ? *in.signer : setup_.verify ? setup_.verify(source, signature, signature_context_for(sess.identity, sess.granted))
                                                      : result<std::string>{std::string{}};
    if constexpr (kBuildHardening != hardening::kProduction) { // production: observe signs too
        if (!who && signature.is_nil() && sess.granted == role::kObserve && setup_.hardening != hardening::kProduction) {
            who = std::string{}; // observe can't mutate anything: unsigned code is allowed
        }
    }
    // A signer key the served release manager's identity revocations name signs nothing any more.
    if (who && !who->empty() && setup_.signer_key && releases_.revoked_signer) {
        if (const auto key = setup_.signer_key(*who); key && releases_.revoked_signer(*key)) {
            who = fail(errc::kRevoked, std::format("the key of signer '{}' is revoked (identity revocations)", *who), "host.signature");
        }
    }
    if (who && audit_ != nullptr) {
        audit_->signer = *who;
    }
    return who;
}

void engine::answer(request_ctx& c, result<value> r) {
    if (!r) {
        reject(c, r.error());
        return;
    }
    reply(c.in.session, c.in.req, std::move(*r));
}

void engine::request(const inbound& in, const error* refused) {
    const auto ps = pump_sessions_.find(in.session);
    if (ps == pump_sessions_.end()) {
        return; // the session ended before its request ran
    }
    pump_session& sess = ps->second;

    // The audit record of this request, reported when request() returns (reply_error fills in
    // the outcome; a suspended request reports how it started).
    std::optional<event::script_executed> audit;
    if (audited(in.code, in.body) && wants<event::script_executed>()) {
        audit.emplace();
        audit->time = now();
        audit->session = in.session;
        audit->identity = sess.identity;
        audit->granted = sess.granted;
        audit->peer = in.peer.empty() ? sess.peer : in.peer;
        audit->op = std::string{wire::to_string(in.code)};
    }
    audit_ = audit ? &*audit : nullptr;
    audit_session_ = in.session;
    audit_req_ = in.req;
    audit_deferred_ = false;
    const utils::scope_guard report{[&] {
        audit_ = nullptr;
        if (audit && !std::exchange(audit_deferred_, false)) {
            publish(std::move(*audit));
        }
    }};

    if (!is_enabled()) {
        abandon_blob(sess, in);
        reply_error(in.session, in.req, make_error(errc::kDisabled, "the host is disabled", std::string{wire::to_string(in.code)}));
        return;
    }
    if (refused != nullptr) {
        abandon_blob(sess, in);
        reply_error(in.session, in.req, *refused);
        return;
    }
    const auto need = wire::required_role(in.code);
    if (!need) {
        reply_error(in.session, in.req, make_error(errc::kProtocol, std::format("{} is not a request", in.code), "host"));
        return;
    }
    if (!allows(sess.granted, *need)) {
        reply_error(in.session, in.req,
                    make_error(errc::kForbidden, std::format("{} needs role {}, {} has {}", in.code, *need, sess.identity, sess.granted),
                               std::string{wire::to_string(in.code)}));
        return;
    }
    if (!sess.scopes.allows(scope_kind::kOp, wire::to_string(in.code))) { // decision AL13
        reply_error(in.session, in.req,
                    make_error(errc::kForbidden, std::format("{} needs scope op:{}, {} lacks it", in.code, in.code, sess.identity),
                               std::string{wire::to_string(in.code)}));
        return;
    }
    const auto it = identities_.find(sess.identity);
    if (it == identities_.end()) {
        return;
    }
    identity_runtime& rt = it->second;
    {
        const std::scoped_lock lock{rt.relay->mutex};
        if (rt.relay->dead(in.session)) {
            if (audit) {
                audit->outcome = make_error(errc::kCancelled, "its session ended before it ran", "host");
            }
            return; // its session ended before it could run: nobody to answer
        }
        if (rt.relay->covers(in.session, in.req, in.arrival)) {
            abandon_blob(sess, in);
            reply_error(in.session, in.req, make_error(errc::kCancelled, "cancelled before it started", std::string{wire::to_string(in.code)}));
            return;
        }
    }
    request_ctx c{in, sess, rt, *rt.box};
    if (in.code == wire::op::kBlob) {
        return blob(sess, in);
    }
    if (in.code == wire::op::kSubscribe || in.code == wire::op::kUnsubscribe) {
        return subscription_request(sess, in);
    }
    if (is_release_op(in.code)) {
        return op_release(c);
    }
    const running_scope running{*rt.relay, in};
    switch (in.code) {
    case wire::op::kExec: return op_exec(c);
    case wire::op::kLoad: return op_load(c);
    case wire::op::kCall: return op_call(c);
    case wire::op::kReload:
    case wire::op::kRollback: return op_reload(c);
    case wire::op::kUnload:
    case wire::op::kRevert:
    case wire::op::kStatus:
    case wire::op::kPin:
    case wire::op::kUnpin: return op_module(c);
    case wire::op::kCheckpoint:
    case wire::op::kRevertTo: return op_tag(c);
    case wire::op::kRevertAll: return op_revert_all(c);
    case wire::op::kList:
    case wire::op::kDescribe: return op_list(c);
    case wire::op::kTunables: return op_tunables(c);
    case wire::op::kTune: return op_tune(c);
    case wire::op::kProfile: return op_profile(c);
    case wire::op::kDebug: return op_debug(c);
    default:
        return reject(c, make_error(errc::kInvalidArgument, std::format("{} is not supported by this host", in.code), std::string{wire::to_string(in.code)}));
    }
}

void engine::admit(inbound& in) {
    const auto ps = pump_sessions_.find(in.session);
    const auto it = ps != pump_sessions_.end() ? identities_.find(ps->second.identity) : identities_.end();
    if (it == identities_.end() || !is_enabled()) {
        return request(in); // which drops a request nobody is left to answer, and refuses while disabled
    }
    const Rhp::limits& l = limits_for(ps->second.granted); // the identity's own: observe's, capped for the hardening level
    if (l.request_rate == 0 && l.pump_requests == 0) {
        return request(in);
    }
    pump_session& sess = ps->second;
    identity_runtime& rt = it->second;
    if (l.request_rate != 0) {
        // A blob counts once: its first chunk takes a token, the chunks that go on from where the last
        // admitted one ended (within the total it announced) don't. Any other chunk takes one, whatever
        // transfer id or offset it claims (they're checked later, in blob()).
        const chunk_info chunk = chunk_of(in);
        pump_session::rated_blob& rated = sess.rated;
        const bool next_chunk = chunk.transfer != 0 && chunk.transfer == rated.transfer && chunk.offset == rated.next && chunk.size != 0 &&
                                chunk.size <= rated.total - rated.next;
        if (next_chunk) {
            rated.next += chunk.size;
            if (rated.next == rated.total) {
                rated = {};
            }
        } else if (!take_token(rt.bucket_full, setup_.clock(), l.request_rate)) {
            const error over = make_error(errc::kLimitExceeded, std::format("{} sends more than {} requests a second (limits.request_rate)", rt.name, l.request_rate),
                                          std::string{wire::to_string(in.code)});
            return request(in, &over);
        } else if (chunk.transfer != 0 && chunk.offset == 0 && chunk.size < chunk.total && chunk.total <= setup_.limits.max_blob) {
            rated = {chunk.transfer, chunk.size, chunk.total};
        }
    }
    if (l.pump_requests == 0) {
        return request(in);
    }
    // Bounded in count and in bytes: one identity can't make the host hold gigabytes of requests.
    const std::size_t bytes = approx_size(in.body);
    if (rt.queued.size() >= kMaxQueued || (!rt.queued.empty() && bytes > kMaxQueuedBytes - std::min(rt.queued_bytes, kMaxQueuedBytes))) {
        const error full = make_error(errc::kLimitExceeded,
                                      std::format("{} has {} requests ({} bytes) waiting for pump() (limits.pump_requests)", rt.name, rt.queued.size(), rt.queued_bytes),
                                      std::string{wire::to_string(in.code)});
        return request(in, &full);
    }
    rt.queued_bytes += bytes;
    rt.queued.push_back(std::move(in));
}

void engine::start_queued() {
    // By name, as the map keeps them, with each identity's own budget (limits.pump_requests for its
    // role; only identities with one queue); looked up again before each start (a request may end an
    // identity).
    struct turn {
        std::string name;
        std::uint32_t left = 0;
    };
    std::vector<turn> turns;
    for (const auto& [name, rt] : identities_) {
        if (!rt.queued.empty()) {
            turns.push_back({name, limits_for(rt.box->caller_role()).pump_requests});
        }
    }
    if (turns.empty()) {
        return;
    }
    std::ranges::rotate(turns, std::ranges::upper_bound(turns, first_turn_, {}, &turn::name));
    first_turn_ = turns.front().name;
    for (bool started = true; started;) {
        started = false;
        for (turn& t : turns) {
            if (t.left == 0) {
                continue;
            }
            const auto it = identities_.find(t.name);
            if (it == identities_.end() || it->second.queued.empty()) {
                t.left = 0;
                continue;
            }
            const inbound in = std::move(it->second.queued.front());
            it->second.queued.pop_front();
            it->second.queued_bytes -= std::min(it->second.queued_bytes, approx_size(in.body));
            --t.left;
            request(in);
            started = true;
        }
    }
}

void engine::drop_queued(identity_runtime& rt, session_id session) {
    const auto ended = std::ranges::stable_partition(rt.queued, [&](const inbound& in) { return in.session != session; });
    const std::vector<inbound> gone(std::make_move_iterator(ended.begin()), std::make_move_iterator(ended.end()));
    rt.queued.erase(ended.begin(), ended.end());
    for (const inbound& in : gone) {
        rt.queued_bytes -= std::min(rt.queued_bytes, approx_size(in.body));
    }
    for (const inbound& in : gone) {
        request(in); // audited as cancelled, as it would have been had it come before the close
    }
}

void engine::op_release(request_ctx& c) {
    if (!releases_.handle) {
        return reject(c, make_error(errc::kNotFound, "this host serves no releases (host.serve)", std::string{wire::to_string(c.in.code)}));
    }
    answer(c, releases_.handle(c.in.code, c.in.body));
}

void engine::op_exec(request_ctx& c) {
    auto m = decode<wire::exec_request>(c);
    if (!m) {
        return;
    }
    if (auto who = check_signature(c.sess, c.in, "", m->source, m->signature); !who) {
        return reject(c, who.error());
    }
    run_tracked(c, {}, [&]() -> result<value> {
        auto r = c.box.exec(m->source, m->chunk);
        if (!r) {
            return std::unexpected{std::move(r).error()};
        }
        return value{std::move(*r)}; // a value_list is a value::array
    });
}

void engine::op_load(request_ctx& c) {
    auto m = decode<wire::load_request>(c);
    if (!m) {
        return;
    }
    if (auto who = check_signature(c.sess, c.in, m->name, m->source, m->signature); !who) {
        return reject(c, who.error());
    }
    // The module id is only known once load() returns: track it through `loaded` (a load of a
    // loaded name is a reload of that module).
    module_id loaded;
    const auto existing = c.box.find(m->name);
    const request_id before = c.box.last_request();
    run_tracked(c, existing ? *existing : module_id{}, [&]() -> result<value> {
        auto r = c.box.load(m->name, m->source);
        if (!r) {
            return std::unexpected{std::move(r).error()};
        }
        loaded = *r;
        return Rhp::to_value(*r);
    });
    if (const request_id after = c.box.last_request(); after != before) {
        if (const auto w = c.rt.waiting.find(after); w != c.rt.waiting.end()) {
            w->second.module = loaded;
        }
    }
}

void engine::op_call(request_ctx& c) {
    auto m = decode<wire::call_request>(c);
    if (!m) {
        return;
    }
    if (audit_ != nullptr) {
        audit_->module = ref_text(m->module);
    }
    auto mod = resolve(c.box, m->module);
    if (!mod) {
        return reject(c, mod.error());
    }
    run_tracked(c, *mod, [&]() -> result<value> {
        auto r = c.box.call(*mod, m->function, m->args);
        if (!r) {
            return std::unexpected{std::move(r).error()};
        }
        return value{value::array(std::make_move_iterator(r->begin()), std::make_move_iterator(r->end()))};
    });
}

void engine::op_reload(request_ctx& c) {
    std::optional<wire::reload_request> reload;
    std::optional<wire::rollback_request> rollback;
    if (c.in.code == wire::op::kReload) {
        reload = decode<wire::reload_request>(c);
        if (!reload) {
            return;
        }
        if (auto who = check_signature(c.sess, c.in, ref_text(reload->module), reload->source, reload->signature); !who) {
            return reject(c, who.error());
        }
    } else {
        rollback = decode<wire::rollback_request>(c);
        if (!rollback) {
            return;
        }
        if (audit_ != nullptr) {
            audit_->module = ref_text(rollback->module);
        }
    }
    auto mod = resolve(c.box, reload ? reload->module : rollback->module);
    if (!mod) {
        return reject(c, mod.error());
    }
    const module_id target = *mod;
    run_tracked(c, target, [&]() -> result<value> {
        auto r = reload ? c.box.reload(target, reload->source)
                        : c.box.rollback(target, rollback->steps > std::numeric_limits<std::size_t>::max() ? std::numeric_limits<std::size_t>::max()
                                                                                                           : static_cast<std::size_t>(rollback->steps));
        if (!r) {
            return std::unexpected{std::move(r).error()};
        }
        return Rhp::to_value(*r);
    });
}

void engine::op_module(request_ctx& c) {
    const inbound& in = c.in;
    wire::module_ref ref;
    bool forced = false;
    if (in.code == wire::op::kUnload) {
        auto m = decode<wire::unload_request>(c);
        if (!m) {
            return;
        }
        ref = std::move(m->module);
        forced = m->force;
    } else {
        auto m = decode<wire::module_request>(c);
        if (!m) {
            return;
        }
        ref = std::move(m->module);
    }
    if (audit_ != nullptr) {
        audit_->module = ref_text(ref);
    }
    auto mod = resolve(c.box, ref);
    if (!mod) {
        return reject(c, mod.error());
    }
    const auto info = c.box.status(*mod);
    if (!info) {
        return reject(c, make_error(errc::kNotFound, std::format("no module {}", *mod), std::string{wire::to_string(in.code)}));
    }
    if (in.code == wire::op::kStatus) {
        return answer(c, Rhp::to_value(describe(*info, c.rt.pinned.contains(*mod))));
    }
    if (in.code == wire::op::kPin || in.code == wire::op::kUnpin) {
        return op_pin(c, *mod, *info);
    }
    if (c.rt.pinned.contains(*mod)) {
        return reject(c, make_error(errc::kForbidden, std::format("module {} is pinned: unpin it first", info->name), std::string{wire::to_string(in.code)}));
    }
    auto r = in.code == wire::op::kRevert ? c.box.revert(*mod) : forced ? c.box.unload(*mod, script::force)
                                                                        : c.box.unload(*mod);
    if (!r) {
        return reject(c, r.error());
    }
    answer(c, Rhp::to_value(summarize(*r)));
}

void engine::op_pin(request_ctx& c, module_id mod, const script::module_info& info) {
    if (info.scratch) {
        return reject(c, make_error(errc::kInvalidArgument, "the scratch module can't be pinned (load a module)", std::string{wire::to_string(c.in.code)}));
    }
    identity_runtime& rt = c.rt;
    const bool pinning = c.in.code == wire::op::kPin;
    if (pinning) {
        rt.pinned.insert(mod);
    } else {
        rt.pinned.erase(mod);
    }
    {
        // Its requests suspended right now outlive their sessions from now on (or stop doing so).
        const std::scoped_lock lock{rt.relay->mutex};
        for (const auto& [r, p] : rt.waiting) {
            if (p.module == mod) {
                if (const auto s = rt.relay->suspended.find({p.session.value(), p.req}); s != rt.relay->suspended.end()) {
                    s->second.pinned = pinning;
                }
            }
        }
    }
    log(log_level::kInfo, "{} {} module {} ({})", c.sess.identity, pinning ? "pinned" : "unpinned", info.name, mod);
    answer(c, value{});
}

void engine::op_tag(request_ctx& c) {
    auto m = decode<wire::tag_request>(c);
    if (!m) {
        return;
    }
    if (audit_ != nullptr) {
        audit_->module = m->tag;
    }
    if (c.in.code == wire::op::kCheckpoint) {
        auto r = c.box.checkpoint(m->tag);
        if (!r) {
            return reject(c, r.error());
        }
        return answer(c, value{});
    }
    if (!c.rt.pinned.empty()) {
        // revert_to undoes every effect after the mark, whatever module made it: it would
        // hollow out pinned modules, which only unpin + revert / unload or revert_all may undo.
        return reject(c, make_error(errc::kForbidden, "this identity has pinned modules: unpin them before revert_to", "revert_to"));
    }
    auto r = c.box.revert_to(m->tag);
    if (!r) {
        return reject(c, r.error());
    }
    answer(c, Rhp::to_value(summarize(*r)));
}

void engine::op_revert_all(request_ctx& c) {
    script::revert_report total;
    std::vector<std::string> sessionless;
    for (auto& [name, other] : identities_) {
        total += other.box->revert_all();
        other.pinned.clear();
        if (other.sessions.empty()) {
            sessionless.push_back(name);
        }
    }
    for (const std::string& name : sessionless) {
        if (const auto gone = identities_.find(name); gone != identities_.end()) {
            teardown(gone->second);
            identities_.erase(gone);
        }
    }
    identity_count_.store(identities_.size(), std::memory_order_release);
    log(log_level::kWarn, "revert_all by {}: {} effects undone", c.sess.identity, total.undone);
    answer(c, Rhp::to_value(summarize(total)));
}

void engine::op_list(request_ctx& c) {
    if (c.in.code == wire::op::kDescribe) {
        return answer(c, value{c.box.stubs()});
    }
    value::array modules;
    for (const script::module_info& m : c.box.list()) {
        modules.push_back(Rhp::to_value(describe(m, c.rt.pinned.contains(m.id))));
    }
    answer(c, value{std::move(modules)});
}

void engine::op_tunables(request_ctx& c) {
    auto m = decode<wire::tunables_request>(c);
    if (!m) {
        return;
    }
    auto list = c.box.tunables(m->prefix);
    if (!list) {
        return reject(c, list.error());
    }
    value::array out;
    out.reserve(list->size());
    for (script::tunable_info& t : *list) {
        out.push_back(Rhp::to_value(wire::tunable_message{std::move(t.path), std::move(t.type), std::move(t.current), t.writable, t.min, t.max, t.step,
                                                          std::move(t.unit), std::move(t.doc)}));
    }
    answer(c, value{std::move(out)});
}

void engine::op_tune(request_ctx& c) {
    auto m = decode<wire::tune_request>(c);
    if (!m) {
        return;
    }
    if (auto r = c.box.tune(m->path, m->to); !r) {
        return reject(c, r.error());
    }
    answer(c, value{});
}

void engine::op_profile(request_ctx& c) {
    auto m = decode<wire::profile_request>(c);
    if (!m) {
        return;
    }
    if (m->action == "start") {
        const script::profile_options options{m->interval, static_cast<std::size_t>(m->max_depth), static_cast<std::size_t>(m->max_stacks)};
        if (auto r = c.box.start_profile(options); !r) {
            return reject(c, r.error());
        }
        c.rt.profiler = c.in.session;
        return answer(c, Rhp::to_value(profile_message(c.box.profile(), setup_.limits.max_frame)));
    }
    if (m->action == "read") {
        return answer(c, Rhp::to_value(profile_message(c.box.profile(), setup_.limits.max_frame)));
    }
    if (m->action == "stop") {
        c.rt.profiler = session_id{};
        return answer(c, Rhp::to_value(profile_message(c.box.stop_profile(), setup_.limits.max_frame)));
    }
    reject(c, make_error(errc::kInvalidArgument, std::format("profile action is start, read or stop, not '{}'", m->action), "profile"));
}

void engine::op_debug(request_ctx& c) {
    auto m = decode<wire::debug_request>(c);
    if (!m) {
        return;
    }
    auto r = debug(c.rt, c.box, c.in.session, *m);
    if (!r) {
        return reject(c, r.error());
    }
    answer(c, Rhp::to_value(*r));
}

result<wire::debug_reply> engine::debug(identity_runtime& rt, script::sandbox& box, session_id session, const wire::debug_request& m) {
    if constexpr (kBuildHardening == hardening::kProduction) { // decision AL2: not in a production binary
        (void)rt;
        (void)box;
        (void)session;
        (void)m;
        return fail(errc::kForbidden, "the remote debugger is compiled out of this build (RHP_HARDENING=production)", "debug");
    } else {
        if (setup_.hardening == hardening::kProduction) {
            return fail(errc::kForbidden, "a host at hardening production has no remote debugger", "debug");
        }
        wire::debug_reply out;
        const request_id req{m.request};
        const std::string_view action = m.action;
        if (action == "break") {
            auto lines = box.set_breakpoints(m.source, m.lines);
            if (!lines) {
                return std::unexpected{std::move(lines).error()};
            }
            out.lines = std::move(*lines);
            rt.debuggers.insert(session);
        } else if (action == "pause") {
            box.debug_pause();
            rt.debuggers.insert(session);
        } else if (action == "continue" || action == "into" || action == "over" || action == "out") {
            const script::step_mode mode = action == "into"   ? script::step_mode::kInto
                                           : action == "over" ? script::step_mode::kOver
                                           : action == "out"  ? script::step_mode::kOut
                                                              : script::step_mode::kContinue;
            if (auto r = box.debug_resume(req, mode); !r) {
                return std::unexpected{std::move(r).error()};
            }
        } else if (action == "paused") {
            for (const script::debug_stop& p : box.paused()) {
                out.paused.push_back(wire::debug_stop_message{p.request.value(), p.label, p.reason, p.source, p.line, p.module.value()});
            }
        } else if (action == "stack") {
            auto frames = box.debug_stack(req);
            if (!frames) {
                return std::unexpected{std::move(frames).error()};
            }
            for (script::debug_frame& f : *frames) {
                out.frames.push_back(wire::debug_frame_message{f.level, std::move(f.name), std::move(f.what), std::move(f.source), f.line, f.defined});
            }
        } else if (action == "variables") {
            const auto scope = parse_scope(m.scope);
            if (!scope) {
                return fail(errc::kInvalidArgument, std::format("scope is locals, upvalues or globals, not '{}'", m.scope), "debug");
            }
            auto vars = box.debug_variables(req, m.frame, *scope, m.path);
            if (!vars) {
                return std::unexpected{std::move(vars).error()};
            }
            for (const script::debug_variable& v : *vars) {
                out.variables.push_back(variable_message(v));
            }
        } else if (action == "evaluate") {
            auto v = box.debug_evaluate(req, m.frame, m.expression);
            if (!v) {
                return std::unexpected{std::move(v).error()};
            }
            out.variables.push_back(variable_message(*v));
        } else if (action == "reset") {
            box.debug_reset();
            rt.debuggers.clear();
        } else {
            return fail(errc::kInvalidArgument, std::format("'{}' is not a debug action", m.action), "debug");
        }
        return out;
    }
}

void engine::blob_failed(pump_session& sess, std::uint64_t transfer) noexcept {
    sess.failed_transfer = transfer;
    if (sess.rated.transfer == transfer) { // its chunks still to come take tokens
        sess.rated = {};
    }
}

void engine::abandon_blob(pump_session& sess, const inbound& in) {
    if (in.code != wire::op::kBlob || !sess.blob) {
        return;
    }
    const auto chunk = Rhp::from_value<wire::blob_chunk>(in.body);
    if (chunk && chunk->transfer == sess.blob->id) {
        blob_failed(sess, sess.blob->id);
        sess.blob.reset();
    }
}

void engine::blob(pump_session& sess, const inbound& in) {
    auto chunk = Rhp::from_value<wire::blob_chunk>(in.body);
    if (!chunk) {
        reply_error(in.session, in.req, chunk.error());
        return;
    }
    if (chunk->transfer == 0) {
        reply_error(in.session, in.req, make_error(errc::kProtocol, "a blob needs a transfer id", "blob"));
        return;
    }
    if (chunk->transfer == sess.failed_transfer) {
        reply_error(in.session, in.req, make_error(errc::kCancelled, "an earlier chunk of this blob was refused", "blob"));
        return;
    }
    const auto refuse = [&](const error& err) {
        if (sess.blob && sess.blob->id == chunk->transfer) {
            sess.blob.reset();
        }
        blob_failed(sess, chunk->transfer);
        if (wants<event::blob_received>()) {
            publish(event::blob_received{now(), in.session, sess.identity, chunk->sink, chunk->name, chunk->total, {}, err});
        }
        reply_error(in.session, in.req, err);
    };
    if (!sess.blob || sess.blob->id != chunk->transfer) {
        if (chunk->offset != 0) {
            return refuse(make_error(errc::kProtocol, "a blob must start at offset 0", "blob"));
        }
        const auto sink = blob_sinks_.find(chunk->sink);
        if (sink == blob_sinks_.end()) {
            return refuse(make_error(errc::kNotFound, std::format("no blob sink named '{}'", chunk->sink), "blob"));
        }
        if (!allows(sess.granted, sink->second.need)) {
            return refuse(make_error(errc::kForbidden, std::format("blob sink '{}' needs role {}, {} has {}", chunk->sink, sink->second.need, sess.identity, sess.granted),
                                     "blob"));
        }
        if (chunk->total > setup_.limits.max_blob) {
            return refuse(make_error(errc::kLimitExceeded, std::format("a {}-byte blob is over the limit ({} bytes)", chunk->total, setup_.limits.max_blob), "blob"));
        }
        if (sess.blob) {
            // A new transfer replaces one the client gave up on (a chunk timed out or was
            // cancelled): its later chunks are refused.
            log(log_level::kInfo, "blob '{}' from {} abandoned at {} of {} bytes", sess.blob->name, sess.identity, sess.blob->data.size(), sess.blob->total);
            blob_failed(sess, sess.blob->id);
            sess.blob.reset();
        }
        blob_transfer t;
        t.id = chunk->transfer;
        t.sink = chunk->sink;
        t.name = chunk->name;
        t.total = chunk->total;
        t.data.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(chunk->total, 1u << 20)));
        sess.blob = std::move(t);
    }
    blob_transfer& t = *sess.blob;
    if (chunk->offset != t.data.size() || chunk->sink != t.sink || chunk->total != t.total) {
        return refuse(make_error(errc::kProtocol, "blob chunks out of order or inconsistent", "blob"));
    }
    if (chunk->data.size() > t.total - t.data.size()) {
        return refuse(make_error(errc::kProtocol, "more blob bytes than announced", "blob"));
    }
    t.data.insert(t.data.end(), chunk->data.begin(), chunk->data.end());
    if (t.data.size() < t.total) {
        reply(in.session, in.req, value{});
        return;
    }
    // Complete: the sink decides.
    const auto sink = blob_sinks_.find(t.sink);
    result<void> verdict = fail(errc::kNotFound, std::format("no blob sink named '{}'", t.sink), "blob");
    if (sink != blob_sinks_.end()) {
        try {
            verdict = sink->second.fn(blob_view{t.sink, t.name, sess.identity, t.data});
        } catch (const std::exception& ex) {
            verdict = fail(errc::kRuntime, std::format("blob sink '{}' threw: {}", t.sink, ex.what()), "blob");
        } catch (...) {
            verdict = fail(errc::kRuntime, std::format("blob sink '{}' threw", t.sink), "blob");
        }
    }
    if (wants<event::blob_received>()) {
        publish(event::blob_received{now(), in.session, sess.identity, t.sink, t.name, t.total, security::to_hex(security::blake2b_256(t.data)),
                                     verdict ? error{} : verdict.error()});
    }
    log(log_level::kInfo, "blob '{}' ({} bytes) from {} for sink {}: {}", t.name, t.total, sess.identity, t.sink, verdict ? "taken" : verdict.error().message);
    const std::uint64_t id = t.id;
    sess.blob.reset();
    if (!verdict) {
        blob_failed(sess, id);
        reply_error(in.session, in.req, verdict.error());
        return;
    }
    reply(in.session, in.req, value{});
}

} // namespace Rhp::host_detail

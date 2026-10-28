// The host engine: construction, setup calls (install, serve, blob sinks, discovery), the goodbye,
// pump() and logging, and the free functions host<Cfg> calls.

#include <rhp/host/detail/engine_impl.hpp>
#include <rhp/net/local/local.hpp>
#include <rhp/security/dev_session.hpp>

namespace Rhp::host_detail {

namespace {

// The setup at its effective hardening level (decisions AL1 and AL4): the build's level added (a
// setup can't go below it), the limits capped, observe identities' own limits settled.
[[nodiscard]] setup hardened(setup s) {
    s.hardening = strictest(kBuildHardening, s.hardening);
    Rhp::limits observe = s.options.observe_limits.value_or(s.limits);
    if (s.hardening == hardening::kProduction) {
        s.limits = capped(s.limits, kProductionCaps);
        observe = capped(observe, kProductionCaps);
    }
    if (s.hardening != hardening::kDev) {
        observe = capped(observe, kObserveCaps);
    }
    s.options.observe_limits = observe;
    if (s.options.env.empty()) { // what certified claims and certificates name (decision AL11)
        s.options.env = s.hardening == hardening::kProduction ? "prod" : "dev";
    }
    return s;
}

} // namespace

security::signature_context engine::signature_context_for(std::string_view identity, role granted) const {
    security::signature_context c;
    c.identity = identity;
    c.granted = granted;
    c.app = setup_.options.app;
    c.env = setup_.options.env;
    c.host_id = setup_.options.host_id;
    c.now = std::chrono::system_clock::now();
    c.level = setup_.hardening;
    return c;
}

engine::engine(setup s)
    : setup_(hardened(std::move(s))),
      inbox_(setup_.options.inbox_capacity),
      outbox_(setup_.options.inbox_capacity) {
    sample_clock();
    session_options_.limits = setup_.limits;
    session_options_.codec = setup_.codec;
    session_options_.ack_delay_ms = setup_.options.ack_delay_ms;
    session_options_.platform = std::string{platform::kOsName};
    session_options_.resumable = setup_.limits.resume_ms != 0;
    if (const auto seed = session::random_seed()) {
        rng_.seed(*seed);
    }
    if (auto refused = refusal()) {
        if (setup_.options.gateway) {
            gateway_error_ = *refused; // gateway_port() says why too
        }
        listen_error_ = std::move(*refused);
        log(log_level::kError, "host refused to start at hardening {}: {}", setup_.hardening, *listen_error_);
        return;
    }
    auto policy = session::channel_policy::make(setup_.ep, setup_.transport.network, setup_.tls, setup_.options.tls);
    if (!policy) {
        listen_error_ = std::move(policy).error();
        log(log_level::kError, "host can't use {}: {}", setup_.ep, *listen_error_);
        return;
    }
    policy_ = std::move(*policy);
    start_gateway();
    const std::string tls_note = policy_.tls() ? std::format(", TLS: {}", policy_.backend()) : std::string{", no TLS"};
    if (setup_.ep.direction == net::endpoint::mode::kDial) {
        // Reverse mode: the host dials a listening client, and keeps dialing.
        reverse_ = true;
        log(log_level::kInfo, "host dialing {} over {} (reverse mode{})", setup_.ep, setup_.transport.name, tls_note);
        dial_out();
        return;
    }
    auto listener = setup_.transport.listen(io_, policy_.transport_endpoint(), [this](std::unique_ptr<net::link> link) { accept(std::move(link)); });
    if (!listener) {
        listen_error_ = std::move(listener).error();
        log(log_level::kError, "host can't listen ({}): {}", setup_.ep, *listen_error_);
        return;
    }
    listener_ = std::move(*listener);
    listen_port_ = static_cast<std::uint16_t>(listener_->port());
    log(log_level::kInfo, "host listening on {} over {} (port {}{})", setup_.ep, setup_.transport.name, listener_->port(), tls_note);
    open_dev_session();
}

engine::~engine() {
    if (!dev_session_file_.empty()) {
        std::error_code ignored;
        std::filesystem::remove(dev_session_file_, ignored);
    }
    release_events_.reset(); // a manager that outlives the host never calls into it again
    for (const auto& [name, state] : program_attached_) {
        state->detach(this); // a game thread may still fire: never after this
    }
    program_attached_.clear();
    advertisement_.reset();
    gateway_.reset();
    enforce_timer_.cancel();
    redial_timer_.cancel();
    listener_.reset();
    sessions_.clear(); // aborts the links: no callbacks after this
    for (auto& [name, id] : identities_) {
        teardown(id);
    }
    identities_.clear();
}

std::optional<error> engine::refusal() const {
    const hardening level = setup_.hardening;
    if (setup_.unsigned_scripts && level != hardening::kDev) {
        return make_error(errc::kForbidden,
                          std::format("signer<unsigned_scripts> runs only at hardening dev, and this host is at {} (RHP_HARDENING, config<>::hardening, host_options::hardening)", level),
                          "host");
    }
    if (setup_.ep.insecure_lan && level != hardening::kDev) {
        return make_error(errc::kForbidden, std::format("{}: insecure_lan is refused at hardening {}; use TLS", setup_.ep, level), "host");
    }
    if (setup_.options.dev_session.empty()) {
        return std::nullopt;
    }
    if constexpr (kBuildHardening != hardening::kDev) {
        return make_error(errc::kForbidden, std::format("dev sessions are compiled out of this build (RHP_HARDENING={})", kBuildHardening), "host.dev_session");
    } else {
        if (level != hardening::kDev) {
            return make_error(errc::kForbidden, std::format("a dev session needs hardening dev, and this host is at {}", level), "host.dev_session");
        }
        // On this machine only, at an address other processes can dial.
        const bool local = setup_.transport.name == net::local_ipc::name || (setup_.transport.network && net::is_loopback_host(setup_.ep.host));
        if (setup_.ep.direction != net::endpoint::mode::kListen || !local) {
            return make_error(errc::kForbidden,
                              std::format("a dev session listens on a loopback address or local IPC only, not {} over {}", setup_.ep, setup_.transport.name),
                              "host.dev_session");
        }
        // The HTTP gateway accepts the same identities, the dev session's admin one included.
        if (const auto& gateway = setup_.options.gateway; gateway && !net::is_loopback_host(gateway->host)) {
            return make_error(errc::kForbidden, std::format("a dev session's HTTP gateway listens on a loopback address only, not {}", *gateway), "host.dev_session");
        }
        if (!setup_.dev_identity) {
            return setup_.dev_identity.error();
        }
        return std::nullopt;
    }
}

void engine::open_dev_session() {
    if constexpr (kBuildHardening == hardening::kDev) {
        if (setup_.options.dev_session.empty()) {
            return;
        }
        security::dev_session session;
        session.app = setup_.options.dev_session;
        session.transport = std::string{setup_.transport.name};
        session.host = setup_.ep.host;
        session.port = setup_.transport.network ? listen_port_ : std::uint16_t{0};
        session.identity = std::move(*setup_.dev_identity);
        auto path = security::dev_session_path(session.app);
        auto written = path ? security::write_dev_session(*path, session) : result<void>{std::unexpected{path.error()}};
        if (!written) {
            listen_error_ = std::move(written).error();
            listener_.reset();
            listen_port_ = 0;
            if (gateway_) { // it accepts the dev session's identity too
                gateway_.reset();
                gateway_port_ = 0;
                gateway_error_ = listen_error_;
            }
            log(log_level::kError, "host stopped listening: no dev session file: {}", *listen_error_);
            return;
        }
        dev_session_file_ = std::move(*path);
        log(log_level::kInfo, "dev session of {} at {}: rhp-cli connect --dev {}", session.app, session.endpoint(), session.app);
    }
}

result<void> engine::listening() const {
    if (listen_error_) {
        return fail(*listen_error_);
    }
    return {};
}

result<std::uint16_t> engine::gateway_port() const {
    if (gateway_error_) {
        return fail(*gateway_error_);
    }
    if (gateway_port_ == 0) {
        return fail(errc::kDisabled, "the HTTP listener was not requested (host_options::gateway)", "host.gateway");
    }
    return gateway_port_;
}

void engine::set_enabled(bool on) noexcept {
    enabled_.store(on, std::memory_order_release);
    try {
        // The flag already holds for pump() and new connections; the network closes the sessions
        // (or dials again) when the post runs, in the order the calls were made.
        io_.post([this, on] { apply_enabled(on); });
    } catch (...) { // out of memory: requests are still refused, and new connections closed
    }
    try {
        log_text(log_level::kWarn, on ? "host enabled" : "host disabled: sessions closed, new connections refused, no scripts run until enabled");
    } catch (...) { // the user's logger threw (or its lock failed): the switch flipped all the same
    }
}

result<void> engine::on_pump_thread(std::string_view where) const {
    const std::thread::id owner = pump_thread_.load(std::memory_order_acquire);
    if (owner != std::thread::id{} && owner != std::this_thread::get_id()) {
        return fail(errc::kInvalidArgument, "call this from the thread that calls pump() (or before the first pump())", std::string{where});
    }
    return {};
}

result<void> engine::install(std::string_view name, installer fn) {
    if (auto here = on_pump_thread("host.install"); !here) {
        return here;
    }
    for (const auto& [n, f] : installers_) {
        if (n == name) {
            return fail(errc::kAlreadyLoaded, std::format("a lib named '{}' is already installed", name), "host.install");
        }
    }
    installers_.emplace_back(std::string{name}, fn);
    for (auto& [identity, id] : identities_) {
        if (auto ok = fn(*id.box); !ok) {
            log(log_level::kWarn, "install {} into identity {}: {}", name, identity, ok.error());
        }
    }
    if (advertise_options_ && advertise_options_->include_libs) {
        return advertise(*advertise_options_);
    }
    return {};
}

result<void> engine::serve_releases(release_bridge bridge) {
    if (auto here = on_pump_thread("host.serve"); !here) {
        return here;
    }
    if (releases_.handle) {
        return fail(errc::kAlreadyLoaded, "this host already serves a release manager", "host.serve");
    }
    if (bridge.harden) { // its channels run at the host's level at least (decision AL2)
        if (auto hardened = bridge.harden(setup_.hardening); !hardened) {
            return hardened;
        }
    }
    releases_ = std::move(bridge);
    // Operator certificates (decision AL12): revoked serials from the manager's identity revocations,
    // operator CAs from its root of trust (refreshed when the root changes: refresh_operator_trust).
    if (setup_.operator_trust && releases_.revoked_serial) {
        operator_revoked_ = [revoked = releases_.revoked_serial](const security::operator_cert& cert) { return revoked(std::to_string(cert.fields.serial)); };
        root_version_ = std::nullopt;
        refresh_operator_trust();
    }
    if (releases_.on_event) {
        release_events_ = releases_.on_event([this](event::release_changed e) {
            if (wants<event::release_changed>()) {
                publish(std::move(e));
            }
        });
    }
    return {};
}

void engine::refresh_operator_trust() {
    if (!operator_revoked_ || !releases_.root_version) {
        return;
    }
    const std::uint64_t version = releases_.root_version();
    if (root_version_ == version) {
        return; // a root changes only by version (a restore, update_root, a kTrust request)
    }
    root_version_ = version;
    setup_.operator_trust(releases_.operator_cas ? releases_.operator_cas() : std::nullopt, operator_revoked_);
}

result<void> engine::add_blob_sink(std::string_view name, blob_fn fn, role need) {
    if (auto here = on_pump_thread("host.on_blob"); !here) {
        return here;
    }
    if (name.empty() || !fn) {
        return fail(errc::kInvalidArgument, "a blob sink needs a name and a function", "host.on_blob");
    }
    if (blob_sinks_.contains(name)) {
        return fail(errc::kAlreadyLoaded, std::format("a blob sink named '{}' is already registered", name), "host.on_blob");
    }
    blob_sinks_.emplace(std::string{name}, blob_sink{std::move(fn), need});
    return {};
}

result<void> engine::advertise(net::advertise_options options) {
    if (setup_.hardening == hardening::kProduction) {
        return fail(errc::kForbidden, "a host at hardening production doesn't advertise itself", "host.advertise");
    }
    if (auto here = on_pump_thread("host.advertise"); !here) {
        return here;
    }
    if (listen_port_ == 0 || !setup_.transport.network) {
        return fail(errc::kInvalidArgument, "only a listening host on a network transport can advertise", "host.advertise");
    }
    if (options.name.empty()) {
        if (advertise_options_) {
            options.name = advertise_options_->name;
        } else {
            auto nonce = platform::random_array<4>();
            if (!nonce) {
                return std::unexpected{std::move(nonce).error()};
            }
            options.name = "rhp-" + security::to_hex(*nonce);
        }
    }
    net::service_record record;
    record.name = options.name;
    record.address = setup_.ep.host;
    record.port = listen_port_;
    record.protocol_revision = wire::kProtocolRevision;
    record.platform = platform::kOsName;
    record.app = options.app;
    record.build = options.build;
    record.transport = setup_.transport.name;
    if (options.include_libs) {
        for (const auto& [name, fn] : installers_) {
            record.libs.push_back(name);
        }
    }
    auto published = on_io<void>([this, record = std::move(record)]() mutable -> result<void> {
        if (advertisement_) {
            return advertisement_->update(std::move(record));
        }
        auto advertised = setup_.discovery.advertise(io_, std::move(record));
        if (!advertised) {
            return std::unexpected{std::move(advertised).error()};
        }
        advertisement_ = std::move(*advertised);
        return {};
    });
    if (published) {
        advertise_options_ = std::move(options);
    }
    return published;
}

result<void> engine::discovery_status() {
    if (!setup_.io_thread) {
        if (auto here = on_pump_thread("host.discovery_status"); !here) {
            return here;
        }
    }
    return on_io<void>([this]() -> result<void> {
        return advertisement_ ? advertisement_->status() : result<void>{fail(errc::kDisabled, "the host is not advertising", "host.discovery")};
    });
}

void engine::goodbye() {
    io_.post([this] {
        stopping_ = true;
        redial_timer_.cancel();
        listener_.reset();
        advertisement_.reset();
        if (gateway_) {
            gateway_->stop();
        }
        for (auto& [id, rec] : sessions_) {
            rec.s->close(make_error(errc::kTransport, "the host is shutting down", "host"));
        }
        said_goodbye_.store(true, std::memory_order_release);
    });
    const auto deadline = std::chrono::steady_clock::now() + kGoodbyeWait;
    // An HTTP-only host has no native session to wait for, but its gateway's answers are only
    // sent once the posted goodbye ran.
    while ((!said_goodbye_.load(std::memory_order_acquire) || open_sessions_.load(std::memory_order_acquire) != 0) &&
           std::chrono::steady_clock::now() < deadline) {
        if (setup_.io_thread) {
            std::this_thread::sleep_for(std::chrono::milliseconds{2});
        } else {
            io_.run_one_for(std::chrono::milliseconds{5});
        }
    }
}

void engine::pump() {
    pump_thread_.store(std::this_thread::get_id(), std::memory_order_release);
    sample_clock();
    if (!setup_.io_thread) {
        io_.poll();
    }
    for (auto& [id, sess] : pump_sessions_) {
        sess.sent_this_pump = 0;
    }
    std::vector<inbound> batch;
    while (auto item = inbox_.try_pop()) {
        batch.push_back(std::move(*item));
    }
    process(batch); // while disabled, requests are answered kDisabled and closed sessions revert
    start_queued(); // limits.pump_requests
    deliver_program_events();
    // The kill switch: no handlers, tasks or release channels run while the host is disabled (they
    // wait, as they are, until it is enabled again).
    const bool enabled = is_enabled();
    if (enabled) {
        for (auto& [name, id] : identities_) {
            id.box->pump();
        }
    }
    std::erase_if(async_leftovers_, [](script::async_leftovers& left) { return left.pump() == 0; });
    if (enabled && releases_.pump) {
        releases_.pump();
    }
    refresh_operator_trust();
    flush_outbox();
    if (!setup_.io_thread) {
        io_.poll();
    }
}

void engine::log_text(log_level level, std::string_view message) {
    if (log_on(level)) {
        write_log(level, message);
    }
}

void engine::write_log(log_level level, std::string_view message) {
    const std::scoped_lock lock{log_mutex_};
    setup_.log(level, message);
}

// ---- the C++ wall --------------------------------------------------------------------------------------

void engine_deleter::operator()(engine* e) const noexcept {
    delete e;
}

engine_ptr make_engine(setup s) {
    return engine_ptr{new engine{std::move(s)}};
}

result<std::uint16_t> port(const engine& e) {
    if (auto ok = e.listening(); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    return e.port();
}

result<std::uint16_t> gateway_port(const engine& e) {
    return e.gateway_port();
}

result<void> advertise(engine& e, net::advertise_options options) {
    return e.advertise(std::move(options));
}

result<void> discovery_status(engine& e) {
    return e.discovery_status();
}

result<void> install(engine& e, std::string_view name, installer fn) {
    return e.install(name, fn);
}

result<void> add_blob_sink(engine& e, std::string_view name, blob_fn fn, role need) {
    return e.add_blob_sink(name, std::move(fn), need);
}

result<void> serve_releases(engine& e, release_bridge bridge) {
    return e.serve_releases(std::move(bridge));
}

void set_enabled(engine& e, bool on) noexcept {
    e.set_enabled(on);
}

bool enabled(const engine& e) noexcept {
    return e.is_enabled();
}

void pump(engine& e) {
    e.pump();
}

void goodbye(engine& e) {
    e.goodbye();
}

void run_io(engine& e, std::stop_token stop) {
    e.run_io(std::move(stop));
}

std::size_t sessions(const engine& e) noexcept {
    return e.ready_sessions();
}

std::size_t identities(const engine& e) noexcept {
    return e.identity_count();
}

} // namespace Rhp::host_detail

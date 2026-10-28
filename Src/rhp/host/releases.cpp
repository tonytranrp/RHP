#include <algorithm>
#include <chrono>
#include <cstddef>
#include <format>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/event/events.hpp>
#include <rhp/host/detail/engine.hpp>
#include <rhp/host/detail/releases.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/release/root_of_trust.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/operator_cert.hpp>
#include <rhp/wire/messages.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp::host_detail {

namespace {

value::bytes id_bytes(const release::release_id& id) {
    return value::bytes(id.begin(), id.end());
}

std::optional<wire::release_info_message> info_message(const std::optional<release::release_info>& info) {
    if (!info) {
        return std::nullopt;
    }
    return wire::release_info_message{id_bytes(info->id), info->seq, info->label, info->signers};
}

std::string_view kind_name(release::release_event::kind k) noexcept {
    switch (k) {
    case release::release_event::kind::kApplied: return "applied";
    case release::release_event::kind::kConfirmed: return "confirmed";
    case release::release_event::kind::kRolledBack: return "rolled_back";
    case release::release_event::kind::kRefused: return "refused";
    case release::release_event::kind::kRevocations: return "revocations";
    case release::release_event::kind::kTrust: return "trust";
    }
    return "unknown";
}

// The wire form of a manager's status.
wire::release_status_reply to_message(const release::manager& m) {
    wire::release_status_reply out;
    out.app = m.options().app;
    out.build = m.options().build;
    out.platform = m.options().platform;
    out.revocation_seq = m.revocation_seq();
    const auto trust = m.trust_held();
    out.root_version = trust.root_version;
    out.identity_seq = trust.identity_seq;
    for (const release::channel_status& s : m.status()) {
        wire::channel_status_message c;
        c.channel = s.channel;
        c.running = std::string{release::to_string(s.running)};
        c.active = info_message(s.active);
        c.candidate = info_message(s.candidate);
        c.previous = s.previous ? id_bytes(*s.previous) : value::bytes{};
        c.floor = s.floor;
        c.held = s.held;
        c.attempts = s.attempts;
        c.confirm = std::string{release::to_string(s.confirm)};
        c.handler_failures = s.handler_failures;
        c.modules = s.modules;
        out.channels.push_back(std::move(c));
    }
    return out;
}

// The operator CAs the held root's operator_ca role names (Ed25519 keys; compromised ones are in no
// role), named "root:<key id>"; nullopt without a root or when the role names none.
std::optional<security::trusted_cas> operator_cas(const release::manager& m) {
    const release::signed_root* root = m.root();
    if (root == nullptr) {
        return std::nullopt;
    }
    const release::root_document& doc = root->body;
    security::trusted_cas cas;
    for (const std::string& id : doc.role(release::root_role::kOperatorCa).keys) {
        const auto key = doc.keys.find(id);
        if (key == doc.keys.end() || key->second.alg != release::kEd25519Alg) {
            continue;
        }
        if (auto pub = security::ed25519_public_key::from_bytes(key->second.pub)) {
            (void)cas.add({std::format("root:{}", id), *pub, std::string{}}); // a key listed twice counts once
        }
    }
    if (cas.size() == 0) {
        return std::nullopt;
    }
    return cas;
}

result<value> handle(release::manager& m, wire::op code, const value& body) {
    switch (code) {
    case wire::op::kReleaseApply: {
        auto req = Rhp::from_value<wire::release_apply_request>(body);
        if (!req) {
            return std::unexpected{std::move(req).error()};
        }
        const auto mode = release::parse_confirm_mode(req->confirm);
        if (!mode) {
            return fail(errc::kInvalidArgument, std::format("confirm is now, health or manual, not '{}'", req->confirm), "release_apply");
        }
        auto r = m.apply(req->envelope, *mode);
        if (!r) {
            return std::unexpected{std::move(r).error()};
        }
        wire::release_apply_reply out{r->channel, id_bytes(r->id), r->seq, std::string{release::to_string(r->running)}, r->already,
                                      r->replaced ? id_bytes(*r->replaced) : value::bytes{}, r->signers};
        return Rhp::to_value(out);
    }
    case wire::op::kReleaseConfirm:
    case wire::op::kReleaseDeactivate: {
        auto req = Rhp::from_value<wire::release_channel_request>(body);
        if (!req) {
            return std::unexpected{std::move(req).error()};
        }
        std::optional<release::release_id> expected;
        if (!req->release.empty()) {
            if (req->release.size() != release::release_id{}.size()) {
                return fail(errc::kInvalidArgument, "release is a 32-byte release id", "release_channel");
            }
            expected.emplace();
            std::ranges::copy(req->release, expected->begin());
        }
        auto r = code == wire::op::kReleaseConfirm ? m.confirm(req->channel, expected) : m.deactivate(req->channel, req->hold, expected);
        if (!r) {
            return std::unexpected{std::move(r).error()};
        }
        return value{id_bytes(*r)};
    }
    case wire::op::kReleaseStatus: return Rhp::to_value(to_message(m));
    case wire::op::kRevoke: {
        auto req = Rhp::from_value<wire::revoke_request>(body);
        if (!req) {
            return std::unexpected{std::move(req).error()};
        }
        auto r = m.revoke(req->envelope);
        if (!r) {
            return std::unexpected{std::move(r).error()};
        }
        return value{*r};
    }
    case wire::op::kTrust: {
        auto req = Rhp::from_value<wire::trust_request>(body);
        if (!req) {
            return std::unexpected{std::move(req).error()};
        }
        const std::vector<std::vector<std::byte>> documents(req->documents.begin(), req->documents.end());
        auto r = m.update_trust(documents);
        if (!r) {
            return std::unexpected{std::move(r).error()};
        }
        return Rhp::to_value(wire::trust_reply{r->root_version, r->identity_seq});
    }
    default: return fail(errc::kProtocol, "not a release request", "host.releases");
    }
}

} // namespace

release_bridge bridge(release::manager& m) {
    release_bridge b;
    b.handle = [&m](wire::op code, const value& body) { return handle(m, code, body); };
    b.pump = [&m] { m.pump(); };
    b.harden = [&m](hardening level) { return m.harden(level); };
    b.revoked_signer = [ids = m.identities()](const security::ed25519_public_key& key) { return ids->is_revoked_signer(key); };
    b.revoked_serial = [ids = m.identities()](std::string_view serial) { return ids->is_revoked_serial(serial); };
    b.root_version = [&m] { return m.trust_held().root_version; };
    b.operator_cas = [&m] { return operator_cas(m); };
    b.on_event = [&m](std::function<void(event::release_changed)> publish) {
        return m.on_event([publish = std::move(publish)](const release::release_event& e) {
            event::release_changed out;
            out.time = std::chrono::system_clock::now();
            out.kind = std::string{kind_name(e.what)};
            out.channel = e.channel;
            out.release = e.release ? release::to_hex(*e.release) : std::string{};
            out.fallback = e.fallback ? release::to_hex(*e.fallback) : std::string{};
            out.seq = e.seq;
            out.reason = e.reason;
            out.outcome = e.err.value_or(error{});
            publish(std::move(out));
        });
    };
    return b;
}

} // namespace Rhp::host_detail

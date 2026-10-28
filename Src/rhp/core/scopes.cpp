#include <algorithm>
#include <cstddef>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/scopes.hpp>

namespace Rhp {

namespace {

std::string_view trim(std::string_view s) noexcept {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
        s.remove_suffix(1);
    }
    return s;
}

// The names both patterns match, as one pattern (nullopt: none). Prefix patterns end with a dot,
// so of two of them one is a prefix of the other or they share no name.
std::optional<std::string> meet(std::string_view p, std::string_view q) {
    if (p == "*") {
        return std::string{q};
    }
    if (q == "*") {
        return std::string{p};
    }
    const bool p_prefix = p.ends_with(".*");
    const bool q_prefix = q.ends_with(".*");
    if (!p_prefix) {
        return name_matches(q, p) ? std::optional<std::string>{std::string{p}} : std::nullopt;
    }
    if (!q_prefix) {
        return name_matches(p, q) ? std::optional<std::string>{std::string{q}} : std::nullopt;
    }
    const std::string_view ps = p.substr(0, p.size() - 1); // "game."
    const std::string_view qs = q.substr(0, q.size() - 1);
    if (qs.starts_with(ps)) {
        return std::string{q};
    }
    if (ps.starts_with(qs)) {
        return std::string{p};
    }
    return std::nullopt;
}

void sort_unique(std::vector<std::string>& v) {
    std::ranges::sort(v);
    const auto [first, last] = std::ranges::unique(v);
    v.erase(first, last);
}

} // namespace

void scope_set::normalize() {
    for (kind_rules& r : kinds_) {
        sort_unique(r.deny);
        if (std::ranges::find(r.deny, "*") != r.deny.end()) {
            r.deny.assign(1, "*"); // denies everything: allow patterns change nothing
            r.restricted = false;
            r.allow.clear();
            continue;
        }
        if (r.restricted && std::ranges::find(r.allow, "*") != r.allow.end()) {
            r.restricted = false;
        }
        if (!r.restricted) {
            r.allow.clear();
        }
        sort_unique(r.allow);
    }
}

result<scope_set> scope_set::parse(std::string_view text) {
    scope_set out;
    if (trim(text).empty()) {
        return out;
    }
    const auto bad = [](std::string_view item) {
        return fail(errc::kInvalidArgument,
                    std::format("'{}' is not a scope pattern (lib:, cap:, patch:, event: or op: and a name, \"*\" or \"prefix.*\"; \"!\" denies)", item),
                    "scopes");
    };
    while (true) {
        const auto comma = text.find(',');
        const std::string_view item = trim(text.substr(0, comma));
        std::string_view pattern = item;
        const bool deny = pattern.starts_with('!');
        if (deny) {
            pattern.remove_prefix(1);
        }
        if (pattern == "*") { // every kind
            if (deny) {
                for (kind_rules& r : out.kinds_) {
                    r.deny.emplace_back("*");
                }
            }
        } else {
            const auto colon = pattern.find(':');
            if (colon == std::string_view::npos) {
                return bad(item);
            }
            const auto kind = parse_scope_kind(pattern.substr(0, colon));
            const std::string_view name = pattern.substr(colon + 1);
            if (!kind || !valid_name_pattern(name)) {
                return bad(item);
            }
            kind_rules& r = out.kinds_[static_cast<std::size_t>(*kind)];
            if (deny) {
                r.deny.emplace_back(name);
            } else {
                r.restricted = true;
                r.allow.emplace_back(name);
            }
        }
        if (comma == std::string_view::npos) {
            break;
        }
        text.remove_prefix(comma + 1);
    }
    out.normalize();
    return out;
}

scope_set scope_set::intersect(const scope_set& a, const scope_set& b) {
    scope_set out;
    for (std::size_t k = 0; k < kScopeKinds; ++k) {
        const kind_rules& x = a.kinds_[k];
        const kind_rules& y = b.kinds_[k];
        kind_rules& r = out.kinds_[k];
        r.deny = x.deny;
        r.deny.insert(r.deny.end(), y.deny.begin(), y.deny.end());
        if (!x.restricted) {
            r.restricted = y.restricted;
            r.allow = y.allow;
        } else if (!y.restricted) {
            r.restricted = true;
            r.allow = x.allow;
        } else {
            r.restricted = true;
            for (const std::string& p : x.allow) {
                for (const std::string& q : y.allow) {
                    if (auto both = meet(p, q)) {
                        r.allow.push_back(std::move(*both));
                    }
                }
            }
        }
    }
    out.normalize();
    return out;
}

bool scope_set::denies(scope_kind kind, std::string_view name) const noexcept {
    const kind_rules& r = kinds_[static_cast<std::size_t>(kind)];
    return std::ranges::any_of(r.deny, [&](const std::string& p) { return name_matches(p, name); });
}

bool scope_set::allows(scope_kind kind, std::string_view name) const noexcept {
    const kind_rules& r = kinds_[static_cast<std::size_t>(kind)];
    if (denies(kind, name)) {
        return false;
    }
    if (!r.restricted) {
        return true;
    }
    return std::ranges::any_of(r.allow, [&](const std::string& p) { return name_matches(p, name); });
}

bool scope_set::unrestricted(scope_kind kind) const noexcept {
    const kind_rules& r = kinds_[static_cast<std::size_t>(kind)];
    return !r.restricted && r.deny.empty();
}

bool scope_set::unrestricted() const noexcept {
    return std::ranges::all_of(kinds_, [](const kind_rules& r) { return !r.restricted && r.deny.empty(); });
}

std::string scope_set::to_string() const {
    std::string out;
    const auto add = [&](bool deny, std::size_t k, std::string_view name) {
        if (!out.empty()) {
            out += ',';
        }
        if (deny) {
            out += '!';
        }
        out += Rhp::to_string(static_cast<scope_kind>(k));
        out += ':';
        out += name;
    };
    for (std::size_t k = 0; k < kScopeKinds; ++k) {
        const kind_rules& r = kinds_[k];
        if (r.restricted && r.allow.empty()) {
            add(true, k, "*"); // allow patterns that share no name: nothing of this kind
            continue;
        }
        for (const std::string& p : r.allow) {
            add(false, k, p);
        }
        for (const std::string& p : r.deny) {
            add(true, k, p);
        }
    }
    return out.empty() ? std::string{"*"} : out;
}

} // namespace Rhp

#include <cstddef>
#include <filesystem>
#include <format>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/test/detail/snapshots.hpp>
#include <rhp/test/detail/support.hpp>

namespace Rhp::test::detail {

namespace {

namespace fs = std::filesystem;
using script::sandbox;

// A Lua long string holding `text` exactly: [[...]], [=[...]=], ... (multi-line text starts on its
// own line: Lua drops a newline right after the opening bracket).
std::string long_bracket(std::string_view text) {
    std::size_t level = 0;
    while (true) {
        const std::string close = "]" + std::string(level, '=');
        if (text.find(close + "]") == std::string_view::npos && !text.ends_with(close)) {
            break;
        }
        ++level;
    }
    const std::string eq(level, '=');
    const bool own_line = text.find('\n') != std::string_view::npos || text.starts_with('\r');
    return std::format("[{}[{}{}]{}]", eq, own_line ? "\n" : "", text, eq);
}

// A Lua string literal in double quotes.
std::string lua_quoted(std::string_view text) {
    std::string out = "\"";
    for (const char c : text) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) {
                out += std::format("\\{:03}", static_cast<unsigned char>(c));
            } else {
                out += c;
            }
        }
    }
    out += '"';
    return out;
}

void load_snapshots(snapshot_store& store) {
    store.loaded = true;
    std::error_code ec;
    if (!fs::exists(store.path, ec)) {
        return;
    }
    std::optional<error> failure;
    const std::string source = read_text(store.path, failure);
    if (failure) {
        store.broken = std::format("can't read {}: {}", generic(store.path), failure->message);
        return;
    }
    script::sandbox_options reader_options{.caller_role = role::kObserve, .output = [](std::string_view) {}};
    reader_options.limits.instructions = 100'000'000; // a corrupted file can't hang the run
    reader_options.limits.wall_ms = 10'000;
    sandbox reader{std::move(reader_options)};
    auto values = reader.exec(source, generic(store.path));
    const auto* as_array = values && !values->empty() ? values->front().get_if<value::array>() : nullptr;
    if (as_array != nullptr && as_array->empty()) {
        return; // `return {}`: no snapshots left
    }
    if (!values || values->empty() || values->front().get_if<value::map>() == nullptr) {
        store.broken = std::format("{} isn't a snapshot file (fix or delete it): {}", generic(store.path),
                                   !values ? std::format("{}", values.error()) : std::string{"it doesn't return a table"});
        return;
    }
    if (const auto* m = values->front().get_if<value::map>()) {
        for (const auto& [k, v] : *m) {
            const auto* key = k.get_if<std::string>();
            const auto* text = v.get_if<std::string>();
            if (key != nullptr && text != nullptr) {
                store.stored[*key] = *text;
            }
        }
    }
}

} // namespace

value check_snapshot(snapshot_store& store, const std::string& key, const std::string& text, bool ci, bool update) {
    if (!store.loaded) {
        load_snapshots(store);
    }
    if (!store.broken.empty()) {
        return object{}.set("status", value{"broken"}).set("message", value{store.broken}).done();
    }
    if (const auto seen = store.written.find(key); seen != store.written.end() && seen->second != text) {
        return object{}
            .set("status", value{"broken"})
            .set("message", value{std::format("two snapshots are named '{}' in this run (tests with the same full name? name them: assert.snapshot(v, 'name'))", key)})
            .done();
    }
    store.written[key] = text;
    const auto it = store.stored.find(key);
    if (it == store.stored.end()) {
        if (ci && !update) {
            return object{}.set("status", value{"missing"}).done();
        }
        store.dirty = true;
        return object{}.set("status", value{"new"}).done();
    }
    if (it->second == text) {
        return object{}.set("status", value{"match"}).done();
    }
    if (update) {
        store.dirty = true;
        return object{}.set("status", value{"updated"}).done();
    }
    return object{}.set("status", value{"mismatch"}).set("stored", value{it->second}).done();
}

void save_snapshots(snapshot_store& store, bool update, std::string_view file, std::string_view shown, std::vector<std::string>& notes) {
    if (!store.loaded || !store.broken.empty()) {
        return;
    }
    // Keys no test checked are obsolete: kept, or dropped with --update-snapshots.
    std::map<std::string, std::string> out = store.written;
    std::size_t obsolete = 0;
    for (const auto& [k, v] : store.stored) {
        if (!store.written.contains(k)) {
            if (update) {
                store.dirty = true;
            } else {
                out.emplace(k, v);
            }
            ++obsolete;
        } else if (!update && store.written.at(k) != v) {
            out[k] = v; // a mismatch keeps the stored value
        }
    }
    if (obsolete != 0 && !update) {
        notes.push_back(std::format("{}: {} snapshot(s) no test checked (obsolete: --update-snapshots removes them)", shown, obsolete));
    }
    if (!store.dirty) {
        return;
    }
    std::string text = std::format("-- Snapshots of {} (Rhp::test). Review changes to it like code.\nreturn {{\n", file);
    for (const auto& [k, v] : out) {
        text += std::format("  [{}] = {},\n", lua_quoted(k), long_bracket(v));
    }
    text += "}\n";
    if (auto written = write_text(store.path, text); !written) {
        notes.push_back(std::format("can't write {}: {}", shown, written.error()));
    }
}

} // namespace Rhp::test::detail

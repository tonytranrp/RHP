#pragma once

// Private to Src/rhp/test: the snapshots of one test file, __snapshots__/<file name>.snap.lua next to
// it, a Lua chunk returning {[key] = text}. Read (in a sandbox of its own) when a test first checks
// one, written back after the file ran.

#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/value.hpp>

namespace Rhp::test::detail {

struct snapshot_store {
    std::filesystem::path path;
    bool loaded = false;
    std::map<std::string, std::string> stored;  // key -> serialized value
    std::map<std::string, std::string> written; // what this run checked or stored
    bool dirty = false;
    std::string broken; // why the file can't be read: its tests fail, and it isn't rewritten
};

// The framework's "snapshot" service: {status = match / new / updated / mismatch (with `stored`) /
// missing / broken (with `message`)}. `ci`: a missing snapshot isn't stored; `update`: a different
// one is replaced.
[[nodiscard]] value check_snapshot(snapshot_store& store, const std::string& key, const std::string& text, bool ci, bool update);

// Writes the file back when it changed (`file`: the test file, named in its header). Notes obsolete
// keys and a failed write, with the file shown as `shown`.
void save_snapshots(snapshot_store& store, bool update, std::string_view file, std::string_view shown, std::vector<std::string>& notes);

} // namespace Rhp::test::detail

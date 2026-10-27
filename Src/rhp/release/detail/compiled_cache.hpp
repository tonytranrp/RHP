#pragma once

// Private to Src/rhp/release: the release manager's compiled-chunk cache (manager_options::bytecode_key,
// bytecode.hpp). Bytecode is only ever read from the store, and only after its MAC checks out under the
// host's key; envelopes from the wire are parsed (text).

#include <concepts>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/release/bytecode.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/release/release.hpp>
#include <rhp/release/store.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/security/hash.hpp>
#include <rhp/security/key.hpp>

namespace Rhp::release::detail {

// The bytecode one swap loads a release's modules from (the compiled-chunk cache), and what it
// compiled for the cache meanwhile.
struct chunk_set {
    std::optional<compiled_release> stored; // the release's entry from the store, checked
    std::vector<std::string> made;          // per module: compiled here
    std::vector<char> refused;              // per module: Lua refused the stored bytecode (the source was parsed)

    [[nodiscard]] std::string_view stored_code(std::size_t i) const noexcept {
        if (!stored || i >= stored->modules.size() || refused[i] != 0) {
            return {};
        }
        const std::vector<std::byte>& code = stored->modules[i].code;
        return std::string_view{reinterpret_cast<const char*>(code.data()), code.size()};
    }
};

// The cache of one manager: its store and its key (both the manager's, which outlives this).
class compiled_cache {
public:
    compiled_cache(const any_store& store, const security::key& key);

    // What a swap of `r` loads from: its checked entry, or nothing (the cache is off, there is none,
    // or it was thrown away).
    [[nodiscard]] chunk_set cached_chunks(const release& r);

    result<module_id> load_module(script::sandbox& box, const release& r, std::size_t i, chunk_set& chunks);
    result<revision_id> reload_module(script::sandbox& box, module_id mod, const release& r, std::size_t i, chunk_set& chunks);

    // After a swap loaded `r`: stores its entry unless the store's served every module. Modules the
    // swap didn't load (unchanged since `before`) take their bytecode from `before`'s entry, else are
    // compiled here (parsed, nothing runs). Failing to store only costs the next load a parse.
    void keep_chunks(script::sandbox& box, const release& r, const chunk_set& chunks, const release* before);

    [[nodiscard]] const bytecode_stats& bytecode_cache_stats() const noexcept { return cache_stats_; }

private:
    // An entry whose MAC checks out, made by this Lua build for exactly `r`'s modules.
    result<compiled_release> check_entry(std::span<const std::byte> bytes, const release& r) const;
    void discard(const release_id& id, error why);
    // The bytecode to load module i of `r` from: the stored entry's, else (the cache on) compiled here
    // and kept in `chunks`; empty: parse the source.
    std::string_view bytecode_for(script::sandbox& box, const release& r, std::size_t i, chunk_set& chunks);
    // Runs a load given bytecode; notes whether Lua refused stored bytecode (the sandbox parsed the source).
    template <std::invocable F>
    auto tracked(script::sandbox& box, std::size_t i, chunk_set& chunks, F&& load);

    const any_store& store_;
    const security::key& key_;
    security::digest256 build_{}; // compiled_build()
    bool caching_ = false;        // a bytecode key, and a build to key entries by
    bytecode_stats cache_stats_;
};

} // namespace Rhp::release::detail

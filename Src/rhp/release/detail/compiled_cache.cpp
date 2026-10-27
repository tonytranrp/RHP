#include <algorithm>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/release/bytecode.hpp>
#include <rhp/release/detail/compiled_cache.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/release/release.hpp>
#include <rhp/release/store.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/security/hash.hpp>
#include <rhp/security/key.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace Rhp::release::detail {

compiled_cache::compiled_cache(const any_store& store, const security::key& key)
    : store_(store), key_(key), build_(compiled_build()), caching_(!key.empty() && build_ != security::digest256{}) {}

chunk_set compiled_cache::cached_chunks(const release& r) {
    chunk_set out;
    out.made.resize(r.sources.size());
    out.refused.resize(r.sources.size(), 0);
    if (!caching_) {
        return out;
    }
    auto bytes = store_.read(compiled_store_key(r.id));
    if (!bytes) {
        return out; // none yet (or unreadable right now): compiled here
    }
    auto entry = check_entry(*bytes, r);
    if (!entry) {
        discard(r.id, std::move(entry).error());
        return out;
    }
    out.stored = std::move(*entry);
    return out;
}

result<compiled_release> compiled_cache::check_entry(std::span<const std::byte> bytes, const release& r) const {
    auto entry = open_compiled(bytes, key_);
    if (!entry) {
        return entry;
    }
    if (entry->build != build_) {
        return fail(errc::kOutOfScope, "a bytecode cache entry was made by another Lua build", "release.bytecode");
    }
    const std::vector<module_entry>& mods = r.body.modules;
    bool same = entry->release == r.id && entry->modules.size() == mods.size();
    for (std::size_t i = 0; same && i < mods.size(); ++i) {
        same = entry->modules[i].name == mods[i].name && entry->modules[i].hash == mods[i].hash;
    }
    if (!same) {
        return fail(errc::kIntegrity, std::format("a bytecode cache entry doesn't hold release {}'s modules", short_id(r.id)), "release.bytecode");
    }
    return entry;
}

void compiled_cache::discard(const release_id& id, error why) {
    (void)store_.remove(compiled_store_key(id));
    ++cache_stats_.discarded;
    cache_stats_.last_discarded = std::move(why);
}

std::string_view compiled_cache::bytecode_for(script::sandbox& box, const release& r, std::size_t i, chunk_set& chunks) {
    if (const std::string_view code = chunks.stored_code(i); !code.empty()) {
        return code;
    }
    if (!caching_) {
        return {};
    }
    auto made = box.compile_module(r.body.modules[i].name, r.sources[i]);
    if (!made) {
        return {}; // loading the source reports why
    }
    ++cache_stats_.compiled;
    chunks.made[i] = std::move(*made);
    return chunks.made[i];
}

template <std::invocable F>
auto compiled_cache::tracked(script::sandbox& box, std::size_t i, chunk_set& chunks, F&& load) {
    const bool from_store = !chunks.stored_code(i).empty();
    const std::uint64_t refused_before = box.stats().bytecode_rejected;
    auto out = load();
    if (box.stats().bytecode_rejected != refused_before) {
        chunks.refused[i] = 1;
    } else if (from_store) {
        ++cache_stats_.loaded;
    }
    return out;
}

result<module_id> compiled_cache::load_module(script::sandbox& box, const release& r, std::size_t i, chunk_set& chunks) {
    const std::string& name = r.body.modules[i].name;
    const std::string_view code = bytecode_for(box, r, i, chunks);
    if (code.empty()) {
        return box.load(name, r.sources[i]);
    }
    return tracked(box, i, chunks, [&] { return box.load(name, r.sources[i], script::trusted_bytecode{code}); });
}

result<revision_id> compiled_cache::reload_module(script::sandbox& box, module_id mod, const release& r, std::size_t i, chunk_set& chunks) {
    const std::string_view code = bytecode_for(box, r, i, chunks);
    if (code.empty()) {
        return box.reload(mod, r.sources[i]);
    }
    return tracked(box, i, chunks, [&] { return box.reload(mod, r.sources[i], script::trusted_bytecode{code}); });
}

void compiled_cache::keep_chunks(script::sandbox& box, const release& r, const chunk_set& chunks, const release* before) {
    if (!caching_) {
        return;
    }
    const bool refused = std::ranges::any_of(chunks.refused, [](char x) { return x != 0; });
    if (chunks.stored && !refused) {
        return;
    }
    if (refused) {
        discard(r.id, make_error(errc::kIntegrity, "Lua refused a module's cached bytecode", "release.bytecode"));
    }
    std::optional<compiled_release> prior;
    bool prior_read = false;
    compiled_release entry;
    entry.release = r.id;
    entry.build = build_;
    for (std::size_t i = 0; i < r.body.modules.size(); ++i) {
        const module_entry& m = r.body.modules[i];
        std::vector<std::byte> code;
        if (!chunks.made[i].empty()) {
            const auto bytes = utils::as_bytes(chunks.made[i]);
            code.assign(bytes.begin(), bytes.end());
        } else if (const std::string_view stored = chunks.stored_code(i); !stored.empty()) {
            code = chunks.stored->modules[i].code;
        } else {
            if (before != nullptr && !prior_read && chunks.refused[i] == 0) {
                prior_read = true;
                if (auto bytes = store_.read(compiled_store_key(before->id))) {
                    if (auto e = check_entry(*bytes, *before)) {
                        prior = std::move(*e);
                    }
                }
            }
            if (prior && chunks.refused[i] == 0) {
                for (const compiled_module& p : prior->modules) {
                    if (p.name == m.name && p.hash == m.hash) {
                        code = p.code;
                        break;
                    }
                }
            }
            if (code.empty()) {
                auto made = box.compile_module(m.name, r.sources[i]);
                if (!made) {
                    return;
                }
                ++cache_stats_.compiled;
                const auto bytes = utils::as_bytes(*made);
                code.assign(bytes.begin(), bytes.end());
            }
        }
        entry.modules.push_back(compiled_module{m.name, m.hash, std::move(code)});
    }
    auto sealed = seal_compiled(entry, key_);
    if (!sealed || !store_.write(compiled_store_key(r.id), *sealed)) {
        ++cache_stats_.store_failures;
        return;
    }
    ++cache_stats_.stored;
}

} // namespace Rhp::release::detail

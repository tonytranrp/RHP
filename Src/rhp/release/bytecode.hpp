#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/security/hash.hpp>
#include <rhp/security/key.hpp>

namespace Rhp::release {

// The compiled-chunk cache (manager_options::bytecode_key): the Lua bytecode of a release's modules,
// kept in the store beside its envelope under "bytecode/<hex id>" so a restart loads it instead of
// parsing the sources again. Lua doesn't verify bytecode (a forged chunk escapes the sandbox) and the
// release's signature covers its sources, not this, so every entry carries a MAC under a host-local
// key, checked before anything in it is read:
//
//   entry = MAC || body                 MAC = keyed BLAKE2b-256(key, kBytecodeMacDomain || body)
//   body  = MessagePack {rhp = "release-bytecode", revision, build, release,
//                        modules = [{name, hash, code}...]}
//
// `build` is compiled_build() (which Lua made the bytecode), `release` the release's id, `hash` each
// module's manifest hash (BLAKE2b-256 of its source), `code` its lua_dump with debug information.
// The entry is not part of the release: ids, signatures and manifests don't change.
inline constexpr std::string_view kBytecodeMacDomain{"rhp/bytecode\0", 13};
inline constexpr std::uint64_t kBytecodeRevision = 1; // the body's layout

struct compiled_module {
    std::string name;
    security::digest256 hash{};
    std::vector<std::byte> code;
};

struct compiled_release {
    release_id release{};
    security::digest256 build{};
    std::vector<compiled_module> modules;
};

// "bytecode/<hex id>": where a manager keeps the entry of a release.
[[nodiscard]] std::string compiled_store_key(const release_id& id);

// BLAKE2b-256 of script::bytecode_build(): what an entry's `build` must be for this build to load it.
// All zero when there is none (RHP_ENABLE=0, or the probe couldn't be compiled).
[[nodiscard]] security::digest256 compiled_build();

// An entry for `r`, MAC'd under `key` (kInvalidArgument when the key is empty).
[[nodiscard]] result<std::vector<std::byte>> seal_compiled(const compiled_release& r, const security::key& key);

// The entry's contents once its MAC checks out under `key`. kIntegrity: shorter than a MAC, or the MAC
// doesn't match (another key, an edited or truncated entry); kProtocol: a malformed body or another
// revision. What the body says (build, release, modules) is the caller's to compare.
[[nodiscard]] result<compiled_release> open_compiled(std::span<const std::byte> entry, const security::key& key);

} // namespace Rhp::release

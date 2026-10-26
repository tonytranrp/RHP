#include <algorithm>
#include <cstddef>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/release/bytecode.hpp>
#include <rhp/release/detail/codec.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/security/hash.hpp>
#include <rhp/security/key.hpp>

namespace Rhp::release {

namespace {

constexpr std::string_view kTag = "release-bytecode";
constexpr std::size_t kMac = security::digest256{}.size();

std::span<const std::byte> key_bytes(const security::key& key) {
    return key.bytes();
}

} // namespace

std::string compiled_store_key(const release_id& id) {
    return std::format("bytecode/{}", to_hex(id));
}

security::digest256 compiled_build() {
    const std::string_view build = script::bytecode_build();
    return build.empty() ? security::digest256{} : security::blake2b_256(build);
}

result<std::vector<std::byte>> seal_compiled(const compiled_release& r, const security::key& key) {
    if (key.empty()) {
        return fail(errc::kInvalidArgument, "the bytecode cache needs a key", "release.bytecode");
    }
    value::array modules;
    for (const compiled_module& m : r.modules) {
        value::map entry;
        entry.emplace_back(value{"name"}, value{m.name});
        entry.emplace_back(value{"hash"}, detail::digest_value(m.hash));
        entry.emplace_back(value{"code"}, value{value::bytes(m.code.begin(), m.code.end())});
        modules.emplace_back(std::move(entry));
    }
    value::map doc;
    doc.emplace_back(value{"rhp"}, value{kTag});
    doc.emplace_back(value{"revision"}, value{kBytecodeRevision});
    doc.emplace_back(value{"build"}, detail::digest_value(r.build));
    doc.emplace_back(value{"release"}, detail::digest_value(r.release));
    doc.emplace_back(value{"modules"}, value{std::move(modules)});
    auto body = detail::encode(value{std::move(doc)});
    if (!body) {
        return std::unexpected{std::move(body).error()};
    }
    const security::digest256 mac = security::keyed_blake2b_256(key_bytes(key), kBytecodeMacDomain, *body);
    std::vector<std::byte> out;
    out.reserve(kMac + body->size());
    out.insert(out.end(), mac.begin(), mac.end());
    out.insert(out.end(), body->begin(), body->end());
    return out;
}

result<compiled_release> open_compiled(std::span<const std::byte> entry, const security::key& key) {
    if (key.empty()) {
        return fail(errc::kInvalidArgument, "the bytecode cache needs a key", "release.bytecode");
    }
    if (entry.size() <= kMac) {
        return fail(errc::kIntegrity, "a bytecode cache entry is truncated", "release.bytecode");
    }
    // The MAC first: nothing of an entry this host didn't write is read, let alone loaded.
    const auto body = entry.subspan(kMac);
    security::digest256 claimed{};
    std::copy_n(entry.begin(), kMac, claimed.begin());
    if (!security::digests_equal(claimed, security::keyed_blake2b_256(key_bytes(key), kBytecodeMacDomain, body))) {
        return fail(errc::kIntegrity, "a bytecode cache entry doesn't match its MAC (another key, or it was changed)", "release.bytecode");
    }
    auto v = detail::decode(body);
    if (!v) {
        return std::unexpected{detail::bad_body(std::format("a bytecode cache entry isn't MessagePack: {}", v.error().message))};
    }
    auto f = detail::fields(*v, "a bytecode cache entry");
    if (!f) {
        return std::unexpected{std::move(f).error()};
    }
    if (auto ok = detail::exact_size(**f, 5, "a bytecode cache entry"); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    const value::map& m = **f;
    const auto tag = detail::field(m, 0, "rhp");
    const auto revision = detail::field(m, 1, "revision");
    const auto build = detail::field(m, 2, "build");
    const auto release = detail::field(m, 3, "release");
    const auto modules = detail::field(m, 4, "modules");
    if (!tag || !revision || !build || !release || !modules) {
        return std::unexpected{detail::bad_body("a bytecode cache entry is {rhp, revision, build, release, modules}")};
    }
    const auto* tag_text = (*tag)->get_if<std::string>();
    auto rev = detail::count(**revision, "revision");
    if (tag_text == nullptr || *tag_text != kTag || !rev || *rev != kBytecodeRevision) {
        return std::unexpected{detail::bad_body("not a bytecode cache entry of this revision")};
    }
    compiled_release out;
    auto b = detail::digest(**build, "build");
    auto id = detail::digest(**release, "release");
    const auto* list = (*modules)->get_if<value::array>();
    if (!b || !id || list == nullptr || list->size() > kMaxModules) {
        return std::unexpected{detail::bad_body("a bytecode cache entry's build, release or modules are malformed")};
    }
    out.build = *b;
    out.release = *id;
    for (const value& item : *list) {
        const value* name = item.find("name");
        const value* hash = item.find("hash");
        const value* code = item.find("code");
        const auto* name_text = name != nullptr ? name->get_if<std::string>() : nullptr;
        const auto* code_bytes = code != nullptr ? code->get_if<value::bytes>() : nullptr;
        auto h = hash != nullptr ? detail::digest(*hash, "hash") : result<security::digest256>{std::unexpected{detail::bad_body("no hash")}};
        if (name_text == nullptr || code_bytes == nullptr || !h) {
            return std::unexpected{detail::bad_body("a module of a bytecode cache entry is {name, hash, code}")};
        }
        out.modules.push_back(compiled_module{*name_text, *h, *code_bytes});
    }
    return out;
}

} // namespace Rhp::release

// The compiled-chunk cache of the release manager (manager_options::bytecode_key, bytecode.hpp):
// hits, every way an entry can be refused (and the source parsed instead), and what is never cached.
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "release_support.hpp"
#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/value.hpp>
#include <rhp/release/bytecode.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/release/store.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/security/key.hpp>

using Rhp::errc;
using namespace release_test;

namespace release_bytecode_fixture {

inline int g_level = 0;

using level_lib = Rhp::lib<"bclevel">::var<"value", &g_level>;

} // namespace release_bytecode_fixture

namespace {

namespace fx = release_bytecode_fixture;

const std::vector<module_source> kModules = {
    {"lvl.a", "local M = {}\n"
              "function M.get()\n"
              "    return 'a' .. bclevel.value\n"
              "end\n"
              "function M.boom()\n"
              "    error('bang')\n"
              "end\n"
              "return M\n"},
    {"lvl.b", "bclevel.value = 7\n"
              "return {get = function() return 'b' end}\n"},
};

Rhp::security::key new_key() {
    auto k = Rhp::security::key::generate();
    REQUIRE(k.has_value());
    return *k;
}

struct fixture {
    signer dev{"dev"};
    Rhp::release::any_store store = Rhp::release::memory_store{};
    Rhp::security::key key = new_key();

    fixture() { fx::g_level = 0; }

    [[nodiscard]] Rhp::release::manager_options options(std::optional<Rhp::security::key> k) const {
        Rhp::release::manager_options o;
        o.app = "bcgame";
        o.output = [](std::string_view, std::string_view) {};
        if (k) {
            o.bytecode_key = *k;
        }
        return o;
    }

    [[nodiscard]] Rhp::release::manager make(std::optional<Rhp::security::key> k) const {
        Rhp::release::manager m{trust_of({{&dev, {"*"}}}), options(std::move(k)), store};
        REQUIRE(m.install<fx::level_lib>());
        return m;
    }

    // A manager that applied `modules` (seq 1) and is gone again: what a restart finds.
    Rhp::release::release_id applied(std::optional<Rhp::security::key> k, const std::vector<module_source>& modules = kModules) {
        auto m = make(std::move(k));
        REQUIRE(m.restore());
        const auto env = envelope("lvl.main", 1, modules, dev);
        REQUIRE(m.apply(env));
        return id_of(env);
    }

    [[nodiscard]] std::optional<std::vector<std::byte>> entry(const Rhp::release::release_id& id) const {
        auto bytes = store.read(Rhp::release::compiled_store_key(id));
        return bytes ? std::optional{std::move(*bytes)} : std::nullopt;
    }

    void put_entry(const Rhp::release::release_id& id, const std::vector<std::byte>& bytes) const {
        REQUIRE(store.write(Rhp::release::compiled_store_key(id), bytes));
    }

    [[nodiscard]] std::size_t entries() const {
        std::size_t n = 0;
        for (const auto& k : *store.keys()) {
            n += k.starts_with("bytecode/") ? 1 : 0;
        }
        return n;
    }
};

// The channel's modules answer (their sources ran).
void check_runs(Rhp::release::manager& m) {
    auto* box = m.sandbox("lvl.main");
    REQUIRE(box != nullptr);
    const auto a = box->find("lvl.a");
    REQUIRE(a.has_value());
    CHECK(*box->call(*a, "get") == Rhp::value_list{Rhp::value{"a7"}});
    CHECK(fx::g_level == 7);
}

// Restarts with `k` and restores; returns the manager to inspect.
Rhp::release::manager restart(fixture& f, std::optional<Rhp::security::key> k) {
    fx::g_level = 0;
    auto m = f.make(std::move(k));
    const auto report = m.restore();
    REQUIRE(report.has_value());
    CHECK(report->restored == std::vector<std::string>{"lvl.main"});
    CHECK(report->failed.empty());
    check_runs(m);
    return m;
}

} // namespace

TEST_CASE("release bytecode: a restart loads the cached bytecode instead of parsing", "[release][bytecode]") {
    fixture f;
    const auto id = f.applied(f.key);
    REQUIRE(f.entry(id).has_value());
    auto m = restart(f, f.key);
    const auto st = m.bytecode_cache_stats();
    CHECK(st.loaded == 2);
    CHECK(st.compiled == 0);
    CHECK(st.discarded == 0);
    CHECK(st.stored == 0); // the entry was already there
    CHECK(m.sandbox("lvl.main")->stats().bytecode_loaded == 2);
    // Debug information came along: errors name the module and the line.
    auto* box = m.sandbox("lvl.main");
    const auto failed = box->call(*box->find("lvl.a"), "boom");
    REQUIRE_FALSE(failed.has_value());
    CHECK(failed.error().message.find("lvl.a:6:") != std::string::npos);
}

TEST_CASE("release bytecode: applying compiles once and stores one entry", "[release][bytecode]") {
    fixture f;
    auto m = f.make(f.key);
    REQUIRE(m.restore());
    REQUIRE(m.apply(envelope("lvl.main", 1, kModules, f.dev)));
    check_runs(m);
    const auto st = m.bytecode_cache_stats();
    CHECK(st.compiled == 2);
    CHECK(st.stored == 1);
    CHECK(st.loaded == 0);
    CHECK(f.entries() == 1);
}

TEST_CASE("release bytecode: no key means nothing cached and nothing read", "[release][bytecode]") {
    fixture f;
    const auto id = f.applied(std::nullopt);
    CHECK(f.entries() == 0);
    {
        auto m = restart(f, std::nullopt);
        CHECK(m.bytecode_cache_stats().compiled == 0);
        CHECK(m.sandbox("lvl.main")->stats().bytecode_loaded == 0);
    }
    { // a key turns it on: the next load compiles and stores
        auto m = restart(f, f.key);
        CHECK(m.bytecode_cache_stats().compiled == 2);
        CHECK(m.bytecode_cache_stats().stored == 1);
    }
    REQUIRE(f.entry(id).has_value());
    { // without the key again, the entry that is there is never used
        auto m = restart(f, std::nullopt);
        CHECK(m.sandbox("lvl.main")->stats().bytecode_loaded == 0);
        CHECK(m.bytecode_cache_stats().loaded == 0);
    }
}

TEST_CASE("release bytecode: an entry made under another key is thrown away", "[release][bytecode]") {
    fixture f;
    const auto id = f.applied(f.key);
    const auto other = new_key();
    {
        auto m = restart(f, other);
        const auto st = m.bytecode_cache_stats();
        CHECK(st.discarded == 1);
        REQUIRE(st.last_discarded.has_value());
        CHECK(st.last_discarded->code == errc::kIntegrity);
        CHECK(st.loaded == 0);
        CHECK(st.compiled == 2);
        CHECK(st.stored == 1);                                      // made again, under the new key
        CHECK(m.sandbox("lvl.main")->stats().bytecode_loaded == 2); // what it compiled itself
    }
    auto m = restart(f, other);
    CHECK(m.bytecode_cache_stats().loaded == 2);
    REQUIRE(f.entry(id).has_value());
    CHECK_FALSE(Rhp::release::open_compiled(*f.entry(id), f.key).has_value());
}

TEST_CASE("release bytecode: a tampered or truncated entry is thrown away and the sources parsed", "[release][bytecode]") {
    fixture f;
    const auto id = f.applied(f.key);
    const auto good = f.entry(id);
    REQUIRE(good.has_value());
    std::vector<std::vector<std::byte>> bad;
    for (const std::size_t at : {std::size_t{0}, std::size_t{40}, good->size() / 2, good->size() - 1}) {
        auto flipped = *good;
        flipped[at] ^= std::byte{0x20};
        bad.push_back(std::move(flipped));
    }
    bad.emplace_back(good->begin(), good->begin() + static_cast<std::ptrdiff_t>(good->size() / 2));
    bad.emplace_back(good->begin(), good->begin() + 10); // shorter than the MAC
    bad.emplace_back();
    for (const auto& entry : bad) {
        f.put_entry(id, entry.empty() ? std::vector<std::byte>{std::byte{0}} : entry);
        auto m = restart(f, f.key);
        const auto st = m.bytecode_cache_stats();
        CHECK(st.discarded == 1);
        CHECK(st.loaded == 0);
        CHECK(st.compiled == 2);
        REQUIRE(st.last_discarded.has_value());
        CHECK(st.last_discarded->code == errc::kIntegrity);
        CHECK(m.sandbox("lvl.main")->stats().bytecode_rejected == 0); // nothing unauthenticated reached Lua
    }
    auto m = restart(f, f.key); // the last one was replaced by a good entry
    CHECK(m.bytecode_cache_stats().loaded == 2);
}

TEST_CASE("release bytecode: an entry another Lua build made is thrown away", "[release][bytecode]") {
    fixture f;
    const auto id = f.applied(f.key);
    auto opened = Rhp::release::open_compiled(*f.entry(id), f.key);
    REQUIRE(opened.has_value());
    CHECK(opened->build == Rhp::release::compiled_build());
    CHECK(opened->release == id);
    REQUIRE(opened->modules.size() == 2);

    SECTION("its build differs") {
        auto other = *opened;
        other.build[0] ^= std::byte{1};
        f.put_entry(id, *Rhp::release::seal_compiled(other, f.key));
        auto m = restart(f, f.key);
        const auto st = m.bytecode_cache_stats();
        CHECK(st.discarded == 1);
        REQUIRE(st.last_discarded.has_value());
        CHECK(st.last_discarded->code == errc::kOutOfScope);
        CHECK(st.loaded == 0);
        CHECK(m.sandbox("lvl.main")->stats().bytecode_rejected == 0);
    }
    SECTION("its bytecode's header differs: Lua refuses it") {
        auto other = *opened;
        other.modules[1].code[4] ^= std::byte{0x10}; // the version byte of "\x1bLua" + version
        f.put_entry(id, *Rhp::release::seal_compiled(other, f.key));
        {
            auto m = restart(f, f.key);
            const auto st = m.bytecode_cache_stats();
            CHECK(st.loaded == 1); // lvl.a
            CHECK(st.discarded == 1);
            CHECK(st.stored == 1); // made again
            CHECK(m.sandbox("lvl.main")->stats().bytecode_rejected == 1);
        }
        auto m = restart(f, f.key);
        CHECK(m.bytecode_cache_stats().loaded == 2);
    }
    SECTION("it holds another release's modules") {
        auto other = *opened;
        other.modules[0].hash[0] ^= std::byte{1};
        f.put_entry(id, *Rhp::release::seal_compiled(other, f.key));
        auto m = restart(f, f.key);
        CHECK(m.bytecode_cache_stats().discarded == 1);
        CHECK(m.bytecode_cache_stats().last_discarded->code == errc::kIntegrity);
    }
}

TEST_CASE("release bytecode: a swap reuses the bytecode of unchanged modules", "[release][bytecode]") {
    fixture f;
    auto m = f.make(f.key);
    REQUIRE(m.restore());
    REQUIRE(m.apply(envelope("lvl.main", 1, kModules, f.dev)));
    auto next = kModules;
    next[1].source = "bclevel.value = 7\nreturn {get = function() return 'B' end}\n";
    const auto env = envelope("lvl.main", 2, next, f.dev);
    REQUIRE(m.apply(env));
    const auto st = m.bytecode_cache_stats();
    CHECK(st.compiled == 3); // two for the first release, lvl.b again
    CHECK(st.stored == 2);
    auto again = restart(f, f.key);
    CHECK(again.bytecode_cache_stats().loaded == 2);
    auto* box = again.sandbox("lvl.main");
    CHECK(*box->call(*box->find("lvl.b"), "get") == Rhp::value_list{Rhp::value{"B"}});
}

TEST_CASE("release bytecode: entries go with the releases they belong to", "[release][bytecode]") {
    fixture f;
    auto m = f.make(f.key);
    REQUIRE(m.restore());
    std::vector<Rhp::release::release_id> ids;
    for (std::uint64_t seq = 1; seq <= 3; ++seq) {
        auto mods = kModules;
        mods[1].source += std::format("-- {}\n", seq);
        const auto env = envelope("lvl.main", seq, mods, f.dev);
        REQUIRE(m.apply(env));
        ids.push_back(id_of(env));
    }
    CHECK_FALSE(f.entry(ids[0]).has_value()); // neither active nor previous any more
    CHECK(f.entry(ids[1]).has_value());
    CHECK(f.entry(ids[2]).has_value());
    CHECK(f.entries() == 2);
}

TEST_CASE("release bytecode: bytecode sent as a release's source is refused", "[release][bytecode]") {
    fixture f;
    Rhp::script::sandbox maker;
    const auto code = maker.compile_module("lvl.a", "bclevel.value = 99");
    REQUIRE(code.has_value());
    auto m = f.make(f.key);
    REQUIRE(m.restore());
    const auto applied = m.apply(envelope("lvl.main", 1, {{"lvl.a", *code}}, f.dev));
    REQUIRE_FALSE(applied.has_value());
    CHECK(applied.error().code == errc::kCompile);
    CHECK(fx::g_level == 0);
    CHECK(f.entries() == 0);
}

TEST_CASE("release bytecode: the directory store keeps it across restarts", "[release][bytecode]") {
    const auto dir = std::filesystem::temp_directory_path() / std::format("rhp_release_bytecode_test_{}", std::random_device{}());
    std::filesystem::remove_all(dir);
    fixture f;
    f.store = Rhp::release::directory_store{dir};
    const auto id = f.applied(f.key);
    CHECK(std::filesystem::exists(dir / "bytecode" / (Rhp::release::to_hex(id) + ".rhp")));
    {
        auto m = restart(f, f.key);
        CHECK(m.bytecode_cache_stats().loaded == 2);
        CHECK(m.bytecode_cache_stats().discarded == 0);
    }
    std::filesystem::remove_all(dir);
}

// Compiled chunks: what a sandbox spends loading modules of realistic size from source against
// loading their bytecode (what every --isolation test sandbox of the test runner does), and what a
// release manager's restore (a boot) spends with and without its compiled-chunk cache. The raw twins
// compile the same sources (text, then bytecode) on a plain lua_State.
#include <cstddef>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include "bench_support.hpp"
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include <rhp/release/bytecode.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/release/release.hpp>
#include <rhp/release/store.hpp>
#include <rhp/release/trust.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>

namespace bench_release_fixture {

constexpr std::size_t kModules = 8;
constexpr int kFunctions = 20; // about 15 lines each: 300-line modules

inline int g_level = 0;
using level_lib = Rhp::lib<"benchrel">::var<"level", &g_level>;

// A module of the kind a release carries: a config table and functions with branches, loops and
// string work; its top level only defines them.
std::string module_source(std::size_t index) {
    std::string out = std::format("local M = {{}}\nlocal config = {{name = \"module_{}\", weights = {{1, 2, 3, 4.5}}, flags = {{fast = true, slow = false}}}}\n", index);
    for (int f = 0; f < kFunctions; ++f) {
        out += std::format(R"(function M.f_{0}(a, b, c)
    local t = {{}}
    for i = 1, a do
        if i % 3 == 0 then
            t[#t + 1] = string.format("%s:%d", config.name, i * b + {0})
        elseif i % 5 == 0 then
            t[#t + 1] = (b or 0) + i * 0.5 + config.weights[{1}]
        elseif config.flags.fast and benchrel.level > {0} then
            t[#t + 1] = c and c[i] or i
        else
            t[#t + 1] = tostring(i) .. "_{0}"
        end
    end
    return t, #t
end
)",
                           f, f % 4 + 1);
    }
    out += "return M\n";
    return out;
}

struct release_fixture {
    std::vector<std::string> names;
    std::vector<std::string> sources;
    Rhp::security::ed25519_secret_key secret = *Rhp::security::ed25519_secret_key::generate();
    Rhp::security::key key = *Rhp::security::key::generate();

    release_fixture() {
        for (std::size_t i = 0; i < kModules; ++i) {
            names.push_back(std::format("bench.rel.m{}", i));
            sources.push_back(module_source(i));
        }
    }

    [[nodiscard]] Rhp::release::trust trust() const {
        Rhp::release::trust t;
        REQUIRE(t.add("dev", secret.public_key(), {"*"}));
        return t;
    }

    [[nodiscard]] Rhp::release::manager_options options(bool cached) const {
        Rhp::release::manager_options o;
        o.app = "bench";
        o.output = [](std::string_view, std::string_view) {};
        if (cached) {
            o.bytecode_key = key;
        }
        return o;
    }

    // A store holding one applied release of every module (and, with `cached`, its bytecode).
    [[nodiscard]] Rhp::release::memory_store applied(bool cached) const {
        Rhp::release::manifest m;
        m.channel = "bench.rel";
        m.seq = 1;
        for (const std::string& n : names) {
            m.modules.push_back(Rhp::release::module_entry{n, {}});
        }
        auto r = Rhp::release::make_release(m, sources);
        REQUIRE(r);
        REQUIRE(Rhp::release::sign(*r, Rhp::security::signing_key{"dev", secret}));
        const auto envelope = Rhp::release::encode_release(*r);
        REQUIRE(envelope);
        Rhp::release::memory_store store;
        Rhp::release::manager mgr{trust(), options(cached), store};
        REQUIRE(mgr.install<level_lib>());
        REQUIRE(mgr.restore());
        REQUIRE(mgr.apply(*envelope));
        return store;
    }

    // A boot: a manager over the store restores the release. Returns the modules running.
    [[nodiscard]] std::size_t boot(const Rhp::release::memory_store& store, bool cached) const {
        Rhp::release::manager mgr{trust(), options(cached), store};
        REQUIRE(mgr.install<level_lib>());
        const auto report = mgr.restore();
        if (!report || report->restored.size() != 1 || (cached && mgr.bytecode_cache_stats().loaded != kModules)) {
            FAIL("the release didn't restore as expected");
        }
        return mgr.status().front().modules.size();
    }
};

} // namespace bench_release_fixture

using namespace bench_release_fixture;

TEST_CASE("bench release: modules from source or from bytecode", "[bench][release]") {
    const release_fixture f;
    std::vector<std::string> code;
    {
        Rhp::script::sandbox maker{rhp_bench::quiet()};
        for (std::size_t i = 0; i < kModules; ++i) {
            auto c = maker.compile_module(f.names[i], f.sources[i]);
            REQUIRE(c);
            code.push_back(std::move(*c));
        }
    }
    std::size_t source_bytes = 0;
    std::size_t code_bytes = 0;
    for (std::size_t i = 0; i < kModules; ++i) {
        source_bytes += f.sources[i].size();
        code_bytes += code[i].size();
    }
    WARN(std::format("{} modules: {} bytes of source, {} bytes of bytecode", kModules, source_bytes, code_bytes));

    BENCHMARK("module-load raw: compile 8 modules of 300 lines (text)") {
        rhp_bench::raw_lua raw;
        int ok = 0;
        for (std::size_t i = 0; i < kModules; ++i) {
            ok += luaL_loadbufferx(raw.get(), f.sources[i].data(), f.sources[i].size(), "=m", "t") == LUA_OK ? 1 : 0;
            lua_pop(raw.get(), 1);
        }
        return ok;
    };
    BENCHMARK("module-load raw: compile 8 modules of 300 lines (bytecode)") {
        rhp_bench::raw_lua raw;
        int ok = 0;
        for (std::size_t i = 0; i < kModules; ++i) {
            ok += luaL_loadbufferx(raw.get(), code[i].data(), code[i].size(), "=m", "b") == LUA_OK ? 1 : 0;
            lua_pop(raw.get(), 1);
        }
        return ok;
    };
    BENCHMARK("module-load rhp: a sandbox loading 8 modules of 300 lines (text)") {
        Rhp::script::sandbox box{rhp_bench::quiet()};
        REQUIRE(box.install<level_lib>());
        for (std::size_t i = 0; i < kModules; ++i) {
            (void)rhp_bench::load(box, f.names[i], f.sources[i]);
        }
        return box.list().size();
    };
    BENCHMARK("module-load rhp: a sandbox loading 8 modules of 300 lines (bytecode)") {
        Rhp::script::sandbox box{rhp_bench::quiet()};
        REQUIRE(box.install<level_lib>());
        for (std::size_t i = 0; i < kModules; ++i) {
            if (!box.load(f.names[i], f.sources[i], Rhp::script::trusted_bytecode{code[i]})) {
                FAIL("a module didn't load");
            }
        }
        return box.list().size();
    };
}

TEST_CASE("bench release: a boot restoring a release of 8 modules", "[bench][release]") {
    const release_fixture f;
    const auto parsed = f.applied(false);
    const auto cached = f.applied(true);
    REQUIRE(f.boot(parsed, false) == kModules);
    REQUIRE(f.boot(cached, true) == kModules);

    BENCHMARK("restore rhp: a release of 8 modules of 300 lines (sources parsed)") {
        return f.boot(parsed, false);
    };
    BENCHMARK("restore rhp: a release of 8 modules of 300 lines (cached bytecode)") {
        return f.boot(cached, true);
    };
}

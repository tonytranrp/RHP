// The sandbox's allocator: the small-object slabs (puc_lua/small_alloc) and what the sandbox keeps
// on top of them (memory accounting, the memory limit, the pmr resource), and the collector
// controls (sandbox_options::gc, collect_idle).
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory_resource>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/script_support.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/role.hpp>
#include <rhp/script/puc_lua/small_alloc.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/utils/units.hpp>

using Rhp::errc;
using Rhp::script::gc_mode;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;
using Rhp::script::detail::small_alloc;

namespace allocator_fixture {

using rhp_test::counting_resource;

sandbox make_box(sandbox_options options = {}) {
    options.output = [](std::string_view) {};
    return sandbox{std::move(options)};
}

bool aligned(const void* p) noexcept {
    return reinterpret_cast<std::uintptr_t>(p) % alignof(std::max_align_t) == 0;
}

} // namespace allocator_fixture

using namespace allocator_fixture;

TEST_CASE("small_alloc: every size gets an aligned block of its own", "[script][allocator]") {
    if constexpr (!small_alloc::kPools) {
        SKIP("no pooling under a sanitizer");
    } else {
        small_alloc pool{nullptr};
        std::vector<std::pair<unsigned char*, std::size_t>> blocks;
        for (int round = 0; round < 50; ++round) {
            for (std::size_t size = 1; size <= small_alloc::kMaxSize; ++size) {
                auto* p = static_cast<unsigned char*>(pool.allocate(size));
                REQUIRE(p != nullptr);
                CHECK(aligned(p));
                std::memset(p, static_cast<int>(size), size);
                blocks.emplace_back(p, size);
            }
        }
        // No two blocks overlap: each still holds its own pattern.
        for (const auto& [p, size] : blocks) {
            CHECK(std::all_of(p, p + size, [size](unsigned char c) { return c == static_cast<unsigned char>(size); }));
        }
        CHECK(pool.regions() >= 1);
        for (const auto& [p, size] : blocks) {
            pool.deallocate(p);
        }
    }
}

TEST_CASE("small_alloc: a freed block is reused and empty regions go back", "[script][allocator]") {
    if constexpr (!small_alloc::kPools) {
        SKIP("no pooling under a sanitizer");
    } else {
        counting_resource resource;
        {
            small_alloc pool{&resource};
            void* a = pool.allocate(40);
            pool.deallocate(a);
            CHECK(pool.allocate(40) == a); // last in, first out
            pool.deallocate(a);

            // Far more than one region's worth, then all of it back.
            std::vector<void*> blocks;
            for (int i = 0; i < 20'000; ++i) {
                blocks.push_back(pool.allocate(static_cast<std::size_t>(16 + (i % 7) * 16)));
                REQUIRE(blocks.back() != nullptr);
            }
            const std::size_t peak = pool.regions();
            CHECK(peak > 4);
            CHECK(resource.allocations() == peak); // regions come from the resource
            for (void* p : blocks) {
                pool.deallocate(p);
            }
            CHECK(pool.regions() <= 2); // a spare region's worth of empty slabs may stay
            CHECK(resource.live_bytes() == pool.regions() * small_alloc::kRegionSize);

            // Allocating again reuses what is left before asking for more.
            const std::size_t before = resource.allocations();
            for (int i = 0; i < 100; ++i) {
                blocks[static_cast<std::size_t>(i)] = pool.allocate(48);
            }
            CHECK(resource.allocations() == before);
            for (int i = 0; i < 100; ++i) {
                pool.deallocate(blocks[static_cast<std::size_t>(i)]);
            }
        }
        CHECK(resource.live_bytes() == 0); // the destructor gives back every region
    }
}

TEST_CASE("small_alloc: a region still in use when the allocator goes is given back", "[script][allocator]") {
    if constexpr (!small_alloc::kPools) {
        SKIP("no pooling under a sanitizer");
    } else {
        counting_resource resource;
        {
            small_alloc pool{&resource};
            for (int i = 0; i < 1000; ++i) {
                REQUIRE(pool.allocate(64) != nullptr);
            }
            CHECK(resource.live_bytes() > 0);
        }
        CHECK(resource.live_bytes() == 0);
    }
}

TEST_CASE("sandbox allocator: blocks keep their contents across size classes and the heap", "[script][allocator]") {
    sandbox box = make_box();
    // Tables grow their array and hash parts from a few bytes to kilobytes (small classes, then the
    // heap) and shrink back on rehash; strings and closures of every small size come and go.
    const auto r = box.exec<bool>(R"lua(
        local ok = true
        for n = 1, 300 do
            local t, h = {}, {}
            for i = 1, n do t[i] = i * 3 h["k" .. i] = i end
            for i = 1, n do ok = ok and t[i] == i * 3 and h["k" .. i] == i end
            for i = n, 2, -1 do t[i] = nil h["k" .. i] = nil end
            h.extra = n
            ok = ok and t[1] == 3 and h.k1 == 1 and h.extra == n
            local s = string.rep("ab", n)
            ok = ok and #s == 2 * n and s:sub(-2) == "ab"
            local f = function() return n, s, t end
            local a, b = f()
            ok = ok and a == n and b == s
        end
        return ok
    )lua");
    REQUIRE(r);
    CHECK(*r);
    REQUIRE(box.collect_garbage());
    CHECK(box.exec<int>("local t = {} for i = 1, 1000 do t[i] = {i} end return t[1000][1]") == 1000);
}

TEST_CASE("sandbox allocator: accounting and the memory limit cover small objects", "[script][allocator]") {
    using namespace Rhp::literals;
    sandbox_options options;
    options.limits.memory = 1_MiB;
    sandbox box = make_box(std::move(options));
    const std::size_t baseline = box.memory_used();
    CHECK(box.meter().memory == baseline);

    // Only small objects: tables, short strings, closures.
    const auto hog = box.exec(R"lua(
        local t = {}
        for i = 1, 1e7 do t[i] = {i, tostring(i % 1000)} end
    )lua");
    REQUIRE_FALSE(hog.has_value());
    CHECK(hog.error().code == errc::kMemoryExceeded);
    CHECK(box.memory_used() <= 1_MiB);

    REQUIRE(box.collect_garbage());
    CHECK(box.memory_used() < baseline + 256_KiB);
    const Rhp::script::run_meter m = box.meter();
    CHECK(m.memory == box.memory_used());
    CHECK(m.frees > 10'000);
    CHECK(box.exec<int>("return 2 + 2") == 4);
}

TEST_CASE("sandbox allocator: a memory resource gets every region back", "[script][allocator]") {
    counting_resource resource;
    {
        sandbox_options options;
        options.memory = &resource;
        sandbox box = make_box(std::move(options));
        REQUIRE(box.exec("t = {} for i = 1, 20000 do t[i] = {x = i, s = 'k' .. i} end"));
        CHECK(resource.live_bytes() > 20'000 * 48);
        REQUIRE(box.exec("t = nil"));
        REQUIRE(box.collect_garbage());
    }
    CHECK(resource.live_bytes() == 0);
}

TEST_CASE("sandbox gc: the collector mode is an option", "[script][allocator][gc]") {
    for (const gc_mode mode : {gc_mode::kIncremental, gc_mode::kGenerational}) {
        sandbox_options options;
        options.caller_role = Rhp::role::kAdmin; // collectgarbage() reports the mode it replaces
        options.gc = mode;
        sandbox box = make_box(std::move(options));
        const auto previous = box.exec<std::string>("return collectgarbage('incremental')");
        REQUIRE(previous);
        CHECK(*previous == (mode == gc_mode::kGenerational ? "generational" : "incremental"));
    }
}

TEST_CASE("sandbox gc: collect_idle steps the collector within its budget", "[script][allocator][gc]") {
    for (const gc_mode mode : {gc_mode::kIncremental, gc_mode::kGenerational}) {
        CAPTURE(mode == gc_mode::kGenerational);
        sandbox_options options;
        options.gc = mode;
        sandbox box = make_box(std::move(options));
        REQUIRE(box.exec("keep = {} for i = 1, 20000 do keep[i] = {i} end"));
        REQUIRE(box.exec("keep = nil local junk = {} for i = 1, 20000 do junk[i] = {i} end"));

        CHECK(box.collect_idle(std::chrono::microseconds{0}) == false); // no budget: no work

        // Incremental: freed memory comes back through idle steps alone (no full collection).
        // Generational: each call is one minor collection (or one step of a major one).
        const std::size_t before = box.memory_used();
        bool ended = false;
        for (int i = 0; i < 200; ++i) {
            const auto r = box.collect_idle(std::chrono::microseconds{200});
            REQUIRE(r);
            ended = ended || *r;
        }
        if (mode == gc_mode::kIncremental) {
            CHECK(ended);
            CHECK(box.memory_used() <= before / 2);
        }
        CHECK(box.exec<int>("return 1 + 1") == 2);
    }
}

TEST_CASE("sandbox gc: set_gc_mode switches what collect_idle does", "[script][allocator][gc]") {
    sandbox box = make_box();
    REQUIRE(box.set_gc_mode(gc_mode::kGenerational));
    REQUIRE(box.collect_idle(std::chrono::microseconds{100}));
    REQUIRE(box.set_gc_mode(gc_mode::kIncremental));
    REQUIRE(box.exec("local junk = {} for i = 1, 5000 do junk[i] = {i} end"));
    bool ended = false;
    for (int i = 0; i < 10'000 && !ended; ++i) {
        const auto r = box.collect_idle(std::chrono::microseconds{500});
        REQUIRE(r);
        ended = *r;
    }
    CHECK(ended);
}

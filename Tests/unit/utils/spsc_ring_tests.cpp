#include <cstddef>
#include <memory>
#include <string>
#include <thread>

#include <catch2/catch_test_macros.hpp>

#include <rhp/utils/spsc_ring.hpp>

using Rhp::utils::spsc_ring;

TEST_CASE("spsc_ring capacity rounds up to a power of two", "[utils][spsc_ring]") {
    REQUIRE(spsc_ring<int>{0}.capacity() == 2);
    REQUIRE(spsc_ring<int>{3}.capacity() == 4);
    REQUIRE(spsc_ring<int>{8}.capacity() == 8);
}

TEST_CASE("spsc_ring is FIFO and reports full/empty", "[utils][spsc_ring]") {
    spsc_ring<int> ring{4};
    REQUIRE_FALSE(ring.try_pop().has_value());
    REQUIRE(ring.try_push(1));
    REQUIRE(ring.try_push(2));
    REQUIRE(ring.try_push(3));
    REQUIRE(ring.try_push(4));
    REQUIRE_FALSE(ring.try_push(5));
    REQUIRE(ring.size_approx() == 4);
    REQUIRE(ring.try_pop() == 1);
    REQUIRE(ring.try_push(5));
    REQUIRE(ring.try_pop() == 2);
    REQUIRE(ring.try_pop() == 3);
    REQUIRE(ring.try_pop() == 4);
    REQUIRE(ring.try_pop() == 5);
    REQUIRE_FALSE(ring.try_pop().has_value());
}

TEST_CASE("spsc_ring holds move-only types and destroys leftovers", "[utils][spsc_ring]") {
    auto counter = std::make_shared<int>(0);
    {
        spsc_ring<std::shared_ptr<int>> ring{4};
        REQUIRE(ring.try_push(counter));
        REQUIRE(ring.try_push(counter));
        REQUIRE(counter.use_count() == 3);
    }
    REQUIRE(counter.use_count() == 1);

    spsc_ring<std::unique_ptr<std::string>> ring{2};
    REQUIRE(ring.try_emplace(std::make_unique<std::string>("frame")));
    auto out = ring.try_pop();
    REQUIRE(out.has_value());
    REQUIRE(**out == "frame");
}

TEST_CASE("spsc_ring: a push into a full ring leaves the value with the caller", "[utils][spsc_ring]") {
    spsc_ring<std::unique_ptr<std::string>> ring{2};
    REQUIRE(ring.try_push(std::make_unique<std::string>("a")));
    REQUIRE(ring.try_push(std::make_unique<std::string>("b")));
    auto kept = std::make_unique<std::string>("kept");
    REQUIRE_FALSE(ring.try_push(std::move(kept)));
    REQUIRE(kept != nullptr); // not moved from: the caller can retry later
    REQUIRE(*kept == "kept");
    REQUIRE_FALSE(ring.try_emplace(std::move(kept)));
    REQUIRE(kept != nullptr);

    spsc_ring<std::string> strings{2};
    std::string text = "a long string that would be moved out of a by-value parameter";
    REQUIRE(strings.try_push(text));
    REQUIRE(strings.try_push(text)); // copies
    REQUIRE_FALSE(strings.try_push(std::move(text)));
    REQUIRE(text == "a long string that would be moved out of a by-value parameter");
}

TEST_CASE("spsc_ring transfers every item in order across threads", "[utils][spsc_ring]") {
    constexpr std::size_t kCount = 200'000;
    spsc_ring<std::size_t> ring{64};

    std::jthread producer{[&] {
        for (std::size_t i = 0; i < kCount; ++i) {
            while (!ring.try_push(i)) {
                std::this_thread::yield();
            }
        }
    }};

    std::size_t expected = 0;
    bool in_order = true;
    while (expected < kCount) {
        if (auto v = ring.try_pop()) {
            in_order = in_order && (*v == expected);
            ++expected;
        } else {
            std::this_thread::yield();
        }
    }
    REQUIRE(in_order);
    REQUIRE_FALSE(ring.try_pop().has_value());
}

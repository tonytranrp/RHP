#pragma once

// The program's API: what the game exposes to its Lua scripts. The game and its Lua test
// executable install the same lib, so the tests run the scripts against the real bindings.

#include <cstdint>
#include <map>
#include <string>

#include <rhp/rhp.hpp>

namespace shop {

struct customer_id {
    std::uint32_t value = 0;
    bool operator==(const customer_id&) const = default;
};

struct state {
    std::map<std::string, int> prices{{"sword", 120}, {"shield", 80}, {"potion", 15}};
    std::map<std::uint32_t, int> gold;
    std::uint32_t next_customer = 1;
};

inline state& world() {
    static state s;
    return s;
}

inline double g_discount = 0.0; // scripts set it (0 to 50 %)

inline int price(std::string item) {
    const auto it = world().prices.find(item);
    return it != world().prices.end() ? it->second : 0;
}

inline customer_id customer(int gold) {
    const customer_id id{world().next_customer++};
    world().gold[id.value] = gold;
    return id;
}

inline bool present(const customer_id& c) {
    return world().gold.contains(c.value);
}

inline int gold_of(customer_id c) {
    return world().gold[c.value];
}

// Takes gold from a customer (undone when the script's effects are reverted).
inline Rhp::result<int> pay(customer_id c, int amount) {
    int& g = world().gold[c.value];
    if (amount < 0 || amount > g) {
        return Rhp::fail(Rhp::errc::kOutOfRange, "not enough gold");
    }
    g -= amount;
    return g;
}

inline void refund(customer_id c, int amount) {
    world().gold[c.value] += amount;
}

using lib = Rhp::lib<"shop">                                  //
    ::fn<"price", &price>                                     //
    ::fn<"visit", &customer>                                  //
    ::var<"discount", &g_discount, Rhp::range<0.0, 0.5>> //
    ::handle<"customer", customer_id, &present>               //
    ::method<"pay", &pay, Rhp::undo<&refund>>                 //
    ::property<"gold", &gold_of>;

// Called by the game for every sale; scripts may patch it (a holiday tax, say).
inline int default_tax(int amount) {
    return amount / 10;
}
inline constexpr Rhp::patch_point<"shop.tax", &default_tax> tax{};

// Fired by the game when the shop opens for the day.
inline constexpr Rhp::lua_event<"shop.opened", int> opened{};

} // namespace shop

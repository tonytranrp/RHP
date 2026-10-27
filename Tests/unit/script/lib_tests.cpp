#include <concepts>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/convert.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/detail/lib_builder.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/marshal.hpp>
#include <rhp/utils/type_list.hpp>

// Fixtures referenced only as template arguments: a named namespace with inline definitions, so no
// compiler flags them as unneeded internal declarations.
namespace lib_tests_fixtures {

struct entity_id {
    int v = 0;
    bool operator==(const entity_id&) const = default;
};

struct other_id {
    int v = 0;
    bool operator==(const other_id&) const = default;
};

struct vec2 {
    float x = 0;
    float y = 0;
};

struct opaque {};

inline entity_id spawn(float x, float y) {
    return entity_id{static_cast<int>(x + y)};
}
inline void despawn(entity_id) {}
inline bool is_alive(const entity_id& e) {
    return e.v != 0;
}
inline bool is_other_alive(const other_id& o) {
    return o.v != 0;
}
inline int find(std::string_view) {
    return 0;
}
inline void set_x(int) {}
inline void unset_x(int) {}
inline void explode() {}
inline void wipe() {}
inline Rhp::result<int> checked(int x) {
    return x;
}
inline void uncheck(int) {}
inline std::tuple<int, std::string> pair() {
    return {1, "a"};
}
inline std::optional<entity_id> nearest(std::optional<entity_id> e) {
    return e;
}
inline vec2 midpoint(vec2 a, vec2) {
    return a;
}
inline void take_opaque(opaque) {}
inline opaque make_opaque() {
    return {};
}
inline void mutate(int&) {}
inline int& reference_out() {
    static int x = 0;
    return x;
}
inline void const_ref_ok(const std::string&) {}
inline int dump(Rhp::value) {
    return 0;
}

inline float g_gravity = -9.8f;
inline int g_score = 0;
inline const int g_tick = 0;
inline opaque g_opaque{};

using game_lib = Rhp::lib<"game">                                                        //
    ::fn<"spawn", &spawn, Rhp::undo<&despawn>>                                           //
    ::fn<"find", &find>                                                                  //
    ::fn<"set_x", &set_x, Rhp::undo<&unset_x>>                                           //
    ::fn<"explode", &explode, Rhp::irreversible>                                         //
    ::fn<"wipe", &wipe, Rhp::requires_role<Rhp::role::kAdmin>>                           //
    ::fn<"forced", &explode, Rhp::irreversible, Rhp::requires_role<Rhp::role::kObserve>> //
    ::fn<"twice", [](int x) { return 2 * x; }>                                           //
    ::var<"gravity", &g_gravity>                                                         //
    ::ro<"tick", &g_tick>                                                                //
    ::handle<"entity", entity_id, &is_alive>                                             //
    ::sub<Rhp::lib<"debug">::fn<"dump", &dump>>;

} // namespace lib_tests_fixtures

template <>
struct Rhp::convert<lib_tests_fixtures::vec2> {
    static Rhp::value to_value(const lib_tests_fixtures::vec2& v) { return Rhp::value{Rhp::value::array{v.x, v.y}}; }
    static Rhp::result<lib_tests_fixtures::vec2> from_value(const Rhp::value&) { return lib_tests_fixtures::vec2{}; }
};

namespace lib_tests_fixtures {

using Rhp::script::detail::entry_kind;
using Rhp::script::detail::undo_feed;

template <class L, std::size_t I>
using entry_t = Rhp::utils::at_t<typename L::entries, I>;

// Whether a DSL member can be formed at all (the constraints on lib's member aliases).
template <class L, auto F>
concept can_add_fn_spawn = requires { typename L::template fn<"spawn", F>; };

template <class L, auto F>
concept can_add_fn_bad_name = requires { typename L::template fn<"9lives", F>; };

template <class L, auto F, class Tag>
concept can_add_tagged_fn = requires { typename L::template fn<"tagged", F, Tag>; };

template <class L, auto F, class Tag1, class Tag2>
concept can_add_twice_tagged_fn = requires { typename L::template fn<"tagged", F, Tag1, Tag2>; };

template <class L, auto Ptr>
concept can_add_var = requires { typename L::template var<"v", Ptr>; };

template <class L, auto Ptr>
concept can_add_ro = requires { typename L::template ro<"r", Ptr>; };

template <class L, class H, auto IsAlive>
concept can_add_handle = requires { typename L::template handle<"h", H, IsAlive>; };

template <class L, class Sub>
concept can_add_sub = requires { typename L::template sub<Sub>; };

} // namespace lib_tests_fixtures

namespace fx = lib_tests_fixtures;

TEST_CASE("lib records its name and entries in declaration order", "[script][lib]") {
    using L = fx::game_lib;
    STATIC_REQUIRE(L::name == "game");
    STATIC_REQUIRE(Rhp::utils::size_v<L::entries> == 11);
    STATIC_REQUIRE(Rhp::script::lib_type<L>);
    STATIC_REQUIRE_FALSE(Rhp::script::lib_type<int>);

    STATIC_REQUIRE(fx::entry_t<L, 0>::kind == fx::entry_kind::kFn);
    STATIC_REQUIRE(fx::entry_t<L, 0>::name == "spawn");
    STATIC_REQUIRE(fx::entry_t<L, 6>::kind == fx::entry_kind::kFn);
    STATIC_REQUIRE(fx::entry_t<L, 6>::name == "twice");
    STATIC_REQUIRE(fx::entry_t<L, 7>::kind == fx::entry_kind::kVar);
    STATIC_REQUIRE(fx::entry_t<L, 7>::name == "gravity");
    STATIC_REQUIRE(fx::entry_t<L, 8>::kind == fx::entry_kind::kRo);
    STATIC_REQUIRE(fx::entry_t<L, 8>::name == "tick");
    STATIC_REQUIRE(fx::entry_t<L, 9>::kind == fx::entry_kind::kHandle);
    STATIC_REQUIRE(fx::entry_t<L, 9>::name == "entity");
    STATIC_REQUIRE(fx::entry_t<L, 10>::kind == fx::entry_kind::kSub);
    STATIC_REQUIRE(fx::entry_t<L, 10>::name == "debug");

    using debug = fx::entry_t<L, 10>::lib;
    STATIC_REQUIRE(debug::name == "debug");
    STATIC_REQUIRE(fx::entry_t<debug, 0>::name == "dump");
}

TEST_CASE("lib derives the role each binding needs", "[script][lib]") {
    using L = fx::game_lib;
    using Rhp::role;
    STATIC_REQUIRE(fx::entry_t<L, 0>::required == role::kPatch);   // undo
    STATIC_REQUIRE(fx::entry_t<L, 1>::required == role::kObserve); // pure
    STATIC_REQUIRE(fx::entry_t<L, 2>::required == role::kPatch);   // undo with args
    STATIC_REQUIRE(fx::entry_t<L, 3>::required == role::kPatch);   // irreversible
    STATIC_REQUIRE(fx::entry_t<L, 4>::required == role::kAdmin);   // requires_role
    STATIC_REQUIRE(fx::entry_t<L, 5>::required == role::kObserve); // requires_role overrides irreversible
    STATIC_REQUIRE(fx::entry_t<L, 6>::required == role::kObserve); // lambda

    STATIC_REQUIRE(fx::entry_t<L, 3>::is_irreversible);
    STATIC_REQUIRE(fx::entry_t<L, 5>::is_irreversible);
    STATIC_REQUIRE_FALSE(fx::entry_t<L, 0>::is_irreversible);
}

TEST_CASE("lib picks how an undo is fed", "[script][lib]") {
    using L = fx::game_lib;
    STATIC_REQUIRE(fx::entry_t<L, 0>::feed == fx::undo_feed::kResult); // despawn(entity_id)
    STATIC_REQUIRE(fx::entry_t<L, 1>::feed == fx::undo_feed::kNone);
    STATIC_REQUIRE(fx::entry_t<L, 2>::feed == fx::undo_feed::kArgs); // unset_x(int) with void set_x(int)
    STATIC_REQUIRE(fx::entry_t<L, 3>::feed == fx::undo_feed::kNone);

    // Rhp::result<int> is peeled: uncheck(int) receives the value.
    using checked_lib = Rhp::lib<"c">::fn<"checked", &fx::checked, Rhp::undo<&fx::uncheck>>;
    STATIC_REQUIRE(fx::entry_t<checked_lib, 0>::feed == fx::undo_feed::kResult);
    STATIC_REQUIRE(std::same_as<Rhp::script::detail::undo_input_t<&fx::checked>, int>);
}

TEST_CASE("lib member constraints reject bad declarations", "[script][lib]") {
    using L = fx::game_lib;
    using empty = Rhp::lib<"empty">;

    // Names: Lua identifiers, unique within the lib.
    STATIC_REQUIRE(fx::can_add_fn_spawn<empty, &fx::find>);
    STATIC_REQUIRE_FALSE(fx::can_add_fn_spawn<L, &fx::find>);
    STATIC_REQUIRE_FALSE(fx::can_add_fn_bad_name<empty, &fx::find>);
    STATIC_REQUIRE_FALSE(fx::can_add_sub<L, Rhp::lib<"spawn">>);
    STATIC_REQUIRE(fx::can_add_sub<L, Rhp::lib<"extra">>);

    // Tags.
    STATIC_REQUIRE(fx::can_add_tagged_fn<empty, &fx::set_x, Rhp::undo<&fx::unset_x>>);
    STATIC_REQUIRE_FALSE(fx::can_add_tagged_fn<empty, &fx::spawn, Rhp::undo<&fx::unset_x>>); // undo can't take entity_id or (float, float)
    STATIC_REQUIRE_FALSE(fx::can_add_twice_tagged_fn<empty, &fx::set_x, Rhp::undo<&fx::unset_x>, Rhp::irreversible>);
    STATIC_REQUIRE_FALSE(fx::can_add_twice_tagged_fn<empty, &fx::wipe, Rhp::requires_role<Rhp::role::kAdmin>,
                                                     Rhp::requires_role<Rhp::role::kPatch>>);
    STATIC_REQUIRE(fx::can_add_twice_tagged_fn<empty, &fx::wipe, Rhp::irreversible, Rhp::requires_role<Rhp::role::kAdmin>>);
    STATIC_REQUIRE_FALSE(fx::can_add_tagged_fn<empty, &fx::wipe, int>); // not a tag

    // Variables: writable and copyable; ro accepts const.
    STATIC_REQUIRE(fx::can_add_var<empty, &fx::g_score>);
    STATIC_REQUIRE_FALSE(fx::can_add_var<empty, &fx::g_tick>);
    STATIC_REQUIRE(fx::can_add_ro<empty, &fx::g_tick>);
    STATIC_REQUIRE(fx::can_add_ro<empty, &fx::g_score>);

    // Handles: distinct value types, not arithmetic or pointers.
    STATIC_REQUIRE(fx::can_add_handle<empty, fx::entity_id, &fx::is_alive>);
    STATIC_REQUIRE_FALSE(fx::can_add_handle<empty, fx::entity_id, &fx::is_other_alive>);
}

TEST_CASE("installable checks every type crossing the boundary", "[script][lib]") {
    using Rhp::script::installable;
    STATIC_REQUIRE(installable<fx::game_lib>);
    STATIC_REQUIRE(installable<Rhp::lib<"empty">>);

    // Handles may be declared after the functions using them, optional handles included.
    STATIC_REQUIRE(installable<Rhp::lib<"h">::fn<"nearest", &fx::nearest>::handle<"entity", fx::entity_id, &fx::is_alive>>);
    // ... but a handle type used without being declared doesn't cross.
    STATIC_REQUIRE_FALSE(installable<Rhp::lib<"h">::fn<"nearest", &fx::nearest>>);
    // A handle declared in a sub lib is visible to the whole tree.
    STATIC_REQUIRE(installable<Rhp::lib<"h">::fn<"nearest", &fx::nearest>::sub<
                       Rhp::lib<"types">::handle<"entity", fx::entity_id, &fx::is_alive>>>);

    // Types with an Rhp::convert specialization work; others don't.
    STATIC_REQUIRE(installable<Rhp::lib<"m">::fn<"midpoint", &fx::midpoint>>);
    STATIC_REQUIRE_FALSE(installable<Rhp::lib<"m">::fn<"take", &fx::take_opaque>>);
    STATIC_REQUIRE_FALSE(installable<Rhp::lib<"m">::fn<"make", &fx::make_opaque>>);
    STATIC_REQUIRE_FALSE(installable<Rhp::lib<"m">::var<"o", &fx::g_opaque>>);
    STATIC_REQUIRE_FALSE(installable<Rhp::lib<"m">::sub<Rhp::lib<"inner">::fn<"take", &fx::take_opaque>>>);

    // Reference rules: const& in, nothing by mutable reference, no reference results.
    STATIC_REQUIRE(installable<Rhp::lib<"r">::fn<"ok", &fx::const_ref_ok>>);
    STATIC_REQUIRE_FALSE(installable<Rhp::lib<"r">::fn<"mutate", &fx::mutate>>);
    STATIC_REQUIRE_FALSE(installable<Rhp::lib<"r">::fn<"ref", &fx::reference_out>>);

    // Multiple results and Rhp::result.
    STATIC_REQUIRE(installable<Rhp::lib<"t">::fn<"pair", &fx::pair>::fn<"checked", &fx::checked>>);

    // Handle names and types are unique across the tree.
    STATIC_REQUIRE_FALSE(installable<Rhp::lib<"d">::handle<"entity", fx::entity_id, &fx::is_alive>::sub<
                             Rhp::lib<"s">::handle<"entity", fx::other_id, &fx::is_other_alive>>>);
    STATIC_REQUIRE_FALSE(installable<Rhp::lib<"d">::handle<"entity", fx::entity_id, &fx::is_alive>::sub<
                             Rhp::lib<"s">::handle<"thing", fx::entity_id, &fx::is_alive>>>);
    STATIC_REQUIRE(installable<Rhp::lib<"d">::handle<"entity", fx::entity_id, &fx::is_alive>::sub<
                       Rhp::lib<"s">::handle<"other", fx::other_id, &fx::is_other_alive>>>);
}

TEST_CASE("convertible pushable and pullable", "[script][lib]") {
    using Rhp::convertible;
    using Rhp::script::pullable;
    using Rhp::script::pushable;

    STATIC_REQUIRE(convertible<bool>);
    STATIC_REQUIRE(convertible<int>);
    STATIC_REQUIRE(convertible<std::int64_t>);
    STATIC_REQUIRE(convertible<std::uint8_t>);
    STATIC_REQUIRE(convertible<std::uint64_t>);
    STATIC_REQUIRE(convertible<float>);
    STATIC_REQUIRE(convertible<double>);
    STATIC_REQUIRE(convertible<std::string>);
    STATIC_REQUIRE(convertible<std::string_view>);
    STATIC_REQUIRE(convertible<const std::string&>);
    STATIC_REQUIRE(convertible<std::optional<int>>);
    STATIC_REQUIRE(convertible<std::optional<std::string>>);
    STATIC_REQUIRE(convertible<Rhp::value>);
    STATIC_REQUIRE(convertible<std::vector<int>>);
    STATIC_REQUIRE(convertible<std::map<std::string, double>>);
    STATIC_REQUIRE(convertible<fx::vec2>);

    STATIC_REQUIRE(pushable<const char*>);
    STATIC_REQUIRE_FALSE(pullable<const char*>);
    STATIC_REQUIRE_FALSE(convertible<const char*>);

    STATIC_REQUIRE_FALSE(pushable<fx::opaque>);
    STATIC_REQUIRE_FALSE(pullable<fx::opaque>);
    STATIC_REQUIRE_FALSE(convertible<std::optional<fx::opaque>>);
    // Handles cross only through a lib's handle entry, never on their own.
    STATIC_REQUIRE_FALSE(convertible<fx::entity_id>);
}

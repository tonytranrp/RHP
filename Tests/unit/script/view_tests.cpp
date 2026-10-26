#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <numeric>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/script/stubs.hpp>

using Rhp::errc;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;
using Rhp::script::value_list;

namespace view_tests_fixtures {

inline std::vector<float> g_samples;
inline std::array<std::int32_t, 4> g_ints{};
inline std::array<std::uint8_t, 8> g_bytes{};
inline std::vector<float> g_undo_seen;

inline std::span<float> samples() {
    return g_samples;
}

inline std::span<std::int32_t> ints() {
    return g_ints;
}

inline std::span<const std::int32_t> ints_ro() {
    return g_ints;
}

inline std::span<std::uint8_t> bytes() {
    return g_bytes;
}

inline double sum(std::span<const float> v) {
    return std::accumulate(v.begin(), v.end(), 0.0);
}

inline std::int64_t sum_ints(std::span<const std::int32_t> v) {
    return std::accumulate(v.begin(), v.end(), std::int64_t{0});
}

inline std::size_t byte_count(std::span<const std::byte> b) {
    return b.size();
}

inline int first_byte(std::span<const std::byte> b) {
    return b.empty() ? -1 : static_cast<int>(b[0]);
}

inline void scale(std::span<float> v, float by) {
    for (float& x : v) {
        x *= by;
    }
}

// Remembers what it was given (the undo receives a copy of the span's elements).
inline void add_all(std::span<const float> v) {
    g_undo_seen.assign(v.begin(), v.end());
}

inline void remove_all(std::span<const float> v) {
    g_undo_seen.insert(g_undo_seen.end(), v.begin(), v.end());
}

struct vec3 {
    float x = 0;
    float y = 0;
    float z = 0;
};

enum class layer_kind : std::uint8_t {
    kGround = 1,
    kAir = 2
};

struct transform {
    vec3 pos{};
    float m[4]{};
    std::int32_t layer = 0;
    std::uint32_t id = 0;
    bool visible = true;
    layer_kind kind = layer_kind::kGround;
    std::array<std::uint16_t, 3> tags{};
};

struct body_id {
    std::uint32_t v = 0;
    bool operator==(const body_id&) const = default;
};

inline std::map<std::uint32_t, transform> g_bodies;
inline std::uint32_t g_next = 1;
inline transform g_main{};

inline bool body_alive(const body_id& b) {
    return g_bodies.contains(b.v);
}

inline body_id make_body() {
    const body_id id{g_next++};
    transform t{};
    t.id = id.v;
    g_bodies[id.v] = t;
    return id;
}

inline void kill_body(body_id b) {
    g_bodies.erase(b.v);
}

inline transform* transform_of(body_id b) {
    const auto it = g_bodies.find(b.v);
    return it != g_bodies.end() ? &it->second : nullptr;
}

inline const transform* transform_ro(body_id b) {
    return transform_of(b);
}

inline transform& main_transform() {
    return g_main;
}

inline transform* nothing() {
    return nullptr;
}

inline double length2(const vec3& v) {
    return static_cast<double>(v.x) * v.x + static_cast<double>(v.y) * v.y + static_cast<double>(v.z) * v.z;
}

inline int maybe_layer(const transform* t) {
    return t != nullptr ? t->layer : -1;
}

inline void reset() {
    g_samples = {1.0f, 2.0f, 3.0f, 4.0f};
    g_ints = {10, 20, 30, 40};
    g_bytes = {1, 2, 3, 4, 5, 6, 7, 8};
    g_bodies.clear();
    g_next = 1;
    g_main = transform{};
    g_undo_seen.clear();
}

using view_lib = Rhp::lib<"vt">                                                                      //
    ::fn<"samples", &samples>::fn<"ints", &ints>::fn<"ints_ro", &ints_ro>::fn<"bytes", &bytes>       //
    ::fn<"sum", &sum>::fn<"sum_ints", &sum_ints>::fn<"byte_count", &byte_count>                      //
    ::fn<"first_byte", &first_byte>::fn<"scale", &scale>                                             //
    ::fn<"add_all", &add_all, Rhp::undo<&remove_all>>                                                //
    ::handle<"body", body_id, &body_alive>::fn<"make_body", &make_body>::fn<"kill_body", &kill_body> //
    ::view<"vec3", vec3>::field<"x", &vec3::x>::field<"y", &vec3::y>::field<"z", &vec3::z>           //
    ::view<"transform", transform>                                                                   //
    ::field<"pos", &transform::pos>::field<"m", &transform::m>                                       //
    ::field<"layer", &transform::layer, Rhp::range<0, 31>, Rhp::doc<"render layer">>                 //
    ::ro_field<"id", &transform::id>::field<"visible", &transform::visible>                          //
    ::field<"kind", &transform::kind>::field<"tags", &transform::tags>                               //
    ::method<"transform", &transform_of>::property<"tf", &transform_of>                              //
    ::fn<"transform_ro", &transform_ro>::fn<"main", &main_transform>::fn<"nothing", &nothing>        //
    ::fn<"length2", &length2>::fn<"maybe_layer", &maybe_layer>;

static_assert(Rhp::script::installable<view_lib>);

} // namespace view_tests_fixtures

namespace {

namespace fx = view_tests_fixtures;

sandbox make_box(Rhp::role role = Rhp::role::kPatch) {
    fx::reset();
    sandbox_options options;
    options.caller_role = role;
    options.output = [](std::string_view) {};
    sandbox box{std::move(options)};
    REQUIRE(box.install<fx::view_lib>());
    return box;
}

value_list run(sandbox& box, std::string_view source) {
    auto r = box.exec(source);
    if (!r) {
        FAIL(r.error().where << ": " << r.error().message);
    }
    return *r;
}

Rhp::error fails(sandbox& box, std::string_view source) {
    auto r = box.exec(source);
    REQUIRE_FALSE(r.has_value());
    return r.error();
}

bool has(const std::string& text, std::string_view part) {
    return text.find(part) != std::string::npos;
}

} // namespace

// ---- typed views --------------------------------------------------------------------------------

TEST_CASE("a span result reads C++ memory in place", "[script][views]") {
    sandbox box = make_box();
    CHECK(run(box, "local v = vt.samples() return #v, v[1], v[4], v:get(2)") ==
          value_list{Rhp::value{4}, Rhp::value{1.0}, Rhp::value{4.0}, Rhp::value{2.0}});
    fx::g_samples[0] = 9.5f; // C++ changes it: the view sees it
    CHECK(run(box, "return vt.samples()[1]") == value_list{Rhp::value{9.5}});
    CHECK(run(box, "local v = vt.ints() return v[3], math.type(v[3]), v:kind()") ==
          value_list{Rhp::value{30}, Rhp::value{"integer"}, Rhp::value{"i32"}});
}

TEST_CASE("span indexing is bounds-checked", "[script][views]") {
    sandbox box = make_box();
    auto err = fails(box, "return vt.samples()[5]");
    CHECK(err.code == errc::kOutOfRange);
    CHECK(err.where == "vt.samples");
    CHECK(has(err.message, "index 5 out of range [1, 4]"));
    CHECK(fails(box, "return vt.samples()[0]").code == errc::kOutOfRange);
    CHECK(fails(box, "vt.samples()[5] = 1").code == errc::kOutOfRange);
    CHECK(fails(box, "return vt.samples()[1.5]").code == errc::kInvalidArgument);
    CHECK(run(box, "return vt.samples().nothing == nil") == value_list{Rhp::value{true}});
}

TEST_CASE("span writes convert and check every element", "[script][views]") {
    sandbox box = make_box();
    run(box, "local v = vt.ints() v[1] = 7 v[2] = 8.0");
    CHECK(fx::g_ints[0] == 7);
    CHECK(fx::g_ints[1] == 8);
    CHECK(fails(box, "vt.ints()[1] = 1.5").code == errc::kOutOfRange);
    CHECK(fails(box, "vt.ints()[1] = 'x'").code == errc::kTypeMismatch);
    CHECK(fails(box, "vt.bytes()[1] = 256").code == errc::kOutOfRange);
    CHECK(fails(box, "vt.bytes()[1] = -1").code == errc::kOutOfRange);
    CHECK(fails(box, "vt.ints_ro()[1] = 1").code == errc::kInvalidArgument);
    CHECK(fx::g_ints[0] == 7);
}

TEST_CASE("pairs walks a span in order", "[script][views]") {
    sandbox box = make_box();
    CHECK(run(box, "local s, n = 0, 0 for i, x in pairs(vt.ints()) do s = s + i * x n = n + 1 end return s, n") ==
          value_list{Rhp::value{300}, Rhp::value{4}});
    CHECK(run(box, "local s = 0 local v = vt.samples() for i = 1, #v do s = s + v[i] end return s") == value_list{Rhp::value{10.0}});
}

TEST_CASE("a script's span writes are undone with its module", "[script][views]") {
    sandbox box = make_box();
    const auto mod = box.load("tests.views.writer", "local v = vt.samples() for i = 1, #v do v[i] = v[i] * 10 end v[1] = 5");
    REQUIRE(mod.has_value());
    CHECK(fx::g_samples == std::vector<float>{5.0f, 20.0f, 30.0f, 40.0f});
    REQUIRE(box.revert(*mod));
    CHECK(fx::g_samples == std::vector<float>{1.0f, 2.0f, 3.0f, 4.0f});
}

TEST_CASE("one journal entry per span per request, not per element", "[script][views]") {
    sandbox box = make_box();
    const std::size_t before = box.effects().size();
    run(box, "local v = vt.samples() for k = 1, 100 do for i = 1, #v do v[i] = k end end");
    CHECK(box.effects().size() == before + 1);
    run(box, "vt.samples()[1] = 3"); // another request: another entry
    CHECK(box.effects().size() == before + 2);
    CHECK(box.revert_all().undone == 2);
    CHECK(fx::g_samples == std::vector<float>{1.0f, 2.0f, 3.0f, 4.0f});
}

TEST_CASE("span writes of two modules reverted out of order leave the right values", "[script][views]") {
    sandbox box = make_box();
    const auto a = box.load("tests.views.a", "local v = vt.ints() v[1] = 100 v[2] = 200");
    const auto b = box.load("tests.views.b", "local v = vt.ints() v[2] = 222 v[3] = 333");
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    CHECK(fx::g_ints == std::array<std::int32_t, 4>{100, 222, 333, 40});
    REQUIRE(box.revert(*a)); // b's writes stay; a's own element goes back
    CHECK(fx::g_ints == std::array<std::int32_t, 4>{10, 222, 333, 40});
    REQUIRE(box.revert(*b)); // b's element 2 goes back to what was there before a
    CHECK(fx::g_ints == std::array<std::int32_t, 4>{10, 20, 30, 40});
}

TEST_CASE("a span write in a failed exec is undone with it", "[script][views]") {
    sandbox box = make_box();
    CHECK(fails(box, "vt.samples()[2] = 99 error('boom')").message.find("boom") != std::string::npos);
    CHECK(fx::g_samples[1] == 2.0f);
}

TEST_CASE("checkpoint and revert_to restore span bytes", "[script][views]") {
    sandbox box = make_box();
    run(box, "vt.ints()[1] = 1");
    REQUIRE(box.checkpoint("before"));
    run(box, "vt.ints()[1] = 2 vt.ints()[4] = 4");
    CHECK(fx::g_ints == std::array<std::int32_t, 4>{2, 20, 30, 4});
    REQUIRE(box.revert_to("before"));
    CHECK(fx::g_ints == std::array<std::int32_t, 4>{1, 20, 30, 40});
}

TEST_CASE("a view follows memory that moved and its writes are restored there", "[script][views]") {
    sandbox box = make_box();
    const auto mod = box.load("tests.views.moving", "keep = vt.samples() keep[1] = 50");
    REQUIRE(mod.has_value());
    fx::g_samples.reserve(1000); // reallocates: the old memory is gone
    fx::g_samples.push_back(5.0f);
    REQUIRE(box.exec("local v = require('tests.views.moving').keep return #v, v[1]").value() == value_list{Rhp::value{5}, Rhp::value{50.0}});
    REQUIRE(box.revert(*mod));
    CHECK(fx::g_samples == std::vector<float>{1.0f, 2.0f, 3.0f, 4.0f, 5.0f});
}

TEST_CASE("writing host memory needs the patch role", "[script][views]") {
    sandbox box = make_box(Rhp::role::kObserve);
    CHECK(run(box, "return vt.samples()[1]") == value_list{Rhp::value{1.0}});
    const auto err = fails(box, "vt.samples()[1] = 2");
    CHECK(err.code == errc::kForbidden);
    CHECK(fx::g_samples[0] == 1.0f);
    CHECK(fails(box, "vt.scale(vt.samples(), 2)").code == errc::kForbidden);
}

TEST_CASE("slices share memory and stay bounded", "[script][views]") {
    sandbox box = make_box();
    CHECK(run(box, "local s = vt.ints():slice(2, 3) s[1] = 21 return #s, s[2]") == value_list{Rhp::value{2}, Rhp::value{30}});
    CHECK(fx::g_ints[1] == 21);
    CHECK(fails(box, "return vt.ints():slice(2, 3)[3]").code == errc::kOutOfRange);
    CHECK(fails(box, "return vt.ints():slice(2, 9)").code == errc::kOutOfRange);
    CHECK(run(box, "return #vt.ints():slice(5)") == value_list{Rhp::value{0}});
    // A slice of memory that shrank reports it instead of reading past the end.
    CHECK(run(box, "keep = vt.samples():slice(3, 4) return keep[2]") == value_list{Rhp::value{4.0}});
    fx::g_samples.resize(2);
    CHECK(fails(box, "return keep[1]").code == errc::kOutOfRange);
    REQUIRE(box.revert_all().clean());
    CHECK(fx::g_ints[1] == 20);
}

TEST_CASE("bulk helpers fill, copy and totable", "[script][views]") {
    sandbox box = make_box();
    run(box, "vt.ints():fill(5, 2, 3)");
    CHECK(fx::g_ints == std::array<std::int32_t, 4>{10, 5, 5, 40});
    run(box, "vt.ints():copy({1, 2}, 3)");
    CHECK(fx::g_ints == std::array<std::int32_t, 4>{10, 5, 1, 2});
    run(box, "vt.samples():copy(vt.ints())"); // converted element by element
    CHECK(fx::g_samples == std::vector<float>{10.0f, 5.0f, 1.0f, 2.0f});
    CHECK(fails(box, "vt.ints():copy({1, 2, 3}, 3)").code == errc::kOutOfRange);
    CHECK(fails(box, "vt.ints():copy({1, 'x'})").code == errc::kTypeMismatch);
    CHECK(fx::g_ints[0] == 10); // nothing written by a failed copy
    CHECK(run(box, "local t = vt.ints():totable(2, 3) return #t, t[1], t[2]") == value_list{Rhp::value{2}, Rhp::value{5}, Rhp::value{1}});
    REQUIRE(box.revert_all().clean());
    CHECK(fx::g_ints == std::array<std::int32_t, 4>{10, 20, 30, 40});
    CHECK(fx::g_samples == std::vector<float>{1.0f, 2.0f, 3.0f, 4.0f});
}

// ---- spans as parameters ----------------------------------------------------------------------------

TEST_CASE("a span parameter takes a typed view without copying", "[script][views]") {
    sandbox box = make_box();
    CHECK(run(box, "return vt.sum(vt.samples()), vt.sum_ints(vt.ints():slice(2, 3))") == value_list{Rhp::value{10.0}, Rhp::value{50}});
    const auto err = fails(box, "return vt.sum(vt.ints())");
    CHECK(err.code == errc::kTypeMismatch);
    CHECK(err.where == "vt.sum (argument 1)");
    CHECK(has(err.message, "expected span<f32>"));
}

TEST_CASE("a read-only span parameter takes a table copied for the call", "[script][views]") {
    sandbox box = make_box();
    CHECK(run(box, "return vt.sum({1, 2, 3.5}), vt.sum({})") == value_list{Rhp::value{6.5}, Rhp::value{0.0}});
    const auto err = fails(box, "return vt.sum({1, 'x'})");
    CHECK(err.code == errc::kTypeMismatch);
    CHECK(has(err.message, "element 2"));
}

TEST_CASE("a byte span parameter takes strings, buffers and byte views", "[script][views]") {
    sandbox box = make_box();
    CHECK(run(box, "return vt.byte_count('hello'), vt.byte_count(rhp.buffer.new(7)), vt.byte_count(vt.bytes()), vt.first_byte('A')") ==
          value_list{Rhp::value{5}, Rhp::value{7}, Rhp::value{8}, Rhp::value{65}});
    CHECK(run(box, "local b = rhp.buffer.from('xyz') return vt.first_byte(b:slice(2))") == value_list{Rhp::value{121}});
    CHECK(fails(box, "return vt.byte_count(vt.ints())").code == errc::kTypeMismatch);
}

TEST_CASE("a mutable span parameter journals the host memory it is given", "[script][views]") {
    sandbox box = make_box();
    const auto mod = box.load("tests.views.scaler", "vt.scale(vt.samples(), 2)");
    REQUIRE(mod.has_value());
    CHECK(fx::g_samples == std::vector<float>{2.0f, 4.0f, 6.0f, 8.0f});
    REQUIRE(box.revert(*mod));
    CHECK(fx::g_samples == std::vector<float>{1.0f, 2.0f, 3.0f, 4.0f});
    // A buffer's own memory: nothing to journal.
    CHECK(run(box, "local b = rhp.buffer.new(8) local f = b:view('f32') f[1] = 3 f[2] = 4 vt.scale(f, 0.5) return f[1], f[2]") ==
          value_list{Rhp::value{1.5}, Rhp::value{2.0}});
    CHECK(fails(box, "vt.scale(vt.ints_ro(), 2)").code == errc::kTypeMismatch);
    CHECK(fails(box, "vt.scale({1, 2}, 2)").code == errc::kTypeMismatch);
}

TEST_CASE("an undo fed with a span gets a copy of its elements", "[script][views]") {
    sandbox box = make_box();
    const auto mod = box.load("tests.views.undo", "vt.add_all({1, 2}) vt.add_all(vt.samples())");
    REQUIRE(mod.has_value());
    CHECK(fx::g_undo_seen == std::vector<float>{1.0f, 2.0f, 3.0f, 4.0f});
    fx::g_samples = {0.0f}; // the undo must not read the memory as it is now
    fx::g_undo_seen.clear();
    REQUIRE(box.revert(*mod));
    CHECK(fx::g_undo_seen == std::vector<float>{1.0f, 2.0f, 3.0f, 4.0f, 1.0f, 2.0f});
}

// ---- struct views ------------------------------------------------------------------------------------

TEST_CASE("a struct view reads and writes fields in place", "[script][views]") {
    sandbox box = make_box();
    CHECK(run(box, R"(
        local b = vt.make_body()
        local t = b:transform()
        t.layer = 3
        t.pos.x = 1.5
        t.m[2] = 7
        t.visible = false
        t.kind = 2
        t.tags[3] = 9
        return t.layer, t.pos.x, t.m[2], #t.m, t.id, t.visible, t.kind, b.tf.layer
    )") == value_list{Rhp::value{3}, Rhp::value{1.5}, Rhp::value{7.0}, Rhp::value{4}, Rhp::value{1}, Rhp::value{false}, Rhp::value{2},
                      Rhp::value{3}});
    const fx::transform& t = fx::g_bodies.at(1);
    CHECK(t.layer == 3);
    CHECK(t.pos.x == 1.5f);
    CHECK(t.m[1] == 7.0f);
    CHECK_FALSE(t.visible);
    CHECK(t.kind == fx::layer_kind::kAir);
    CHECK(t.tags[2] == 9);
}

TEST_CASE("struct view fields check their tags, types and writability", "[script][views]") {
    sandbox box = make_box();
    run(box, "body = vt.make_body() t = body:transform()");
    auto err = fails(box, "t.layer = 32");
    CHECK(err.code == errc::kOutOfRange);
    CHECK(err.where == "transform.layer");
    CHECK(fails(box, "t.id = 5").code == errc::kInvalidArgument);
    CHECK(fails(box, "t.visible = 1").code == errc::kTypeMismatch);
    CHECK(fails(box, "t.layer = 1.5").code == errc::kOutOfRange);
    CHECK(fails(box, "t.pos = 1").code == errc::kInvalidArgument);
    CHECK(fails(box, "t.nothing = 1").code == errc::kInvalidArgument);
    CHECK(run(box, "return t.nothing == nil") == value_list{Rhp::value{true}});
    CHECK(fails(box, "vt.transform_ro(body).layer = 1").code == errc::kInvalidArgument);
    CHECK(fails(box, "vt.transform_ro(body).pos.x = 1").code == errc::kInvalidArgument);
    CHECK(fails(box, "vt.transform_ro(body).m[1] = 1").code == errc::kInvalidArgument);
    CHECK(fx::g_bodies.at(1).layer == 0);
}

TEST_CASE("a struct view's writes are undone with its module", "[script][views]") {
    sandbox box = make_box();
    const fx::body_id b = fx::make_body();
    (void)b;
    const auto mod = box.load("tests.views.mover", "local t = vt.main() t.pos.y = 4 t.layer = 2 t.m[4] = 1 t.tags[1] = 3");
    REQUIRE(mod.has_value());
    CHECK(fx::g_main.pos.y == 4.0f);
    CHECK(fx::g_main.layer == 2);
    fx::g_main.pos.x = 9.0f; // C++'s own change to another field stays
    REQUIRE(box.revert(*mod));
    CHECK(fx::g_main.pos.y == 0.0f);
    CHECK(fx::g_main.layer == 0);
    CHECK(fx::g_main.m[3] == 0.0f);
    CHECK(fx::g_main.tags[0] == 0);
    CHECK(fx::g_main.pos.x == 9.0f);
}

TEST_CASE("a kept view raises once its object is gone, and a null pointer is nil", "[script][views]") {
    sandbox box = make_box();
    const auto mod = box.load("tests.views.keeper", "body = vt.make_body() tf = body:transform() tf.layer = 4 m = tf.m");
    REQUIRE(mod.has_value());
    CHECK(fx::g_bodies.at(1).layer == 4);
    fx::kill_body(fx::body_id{1});
    auto err = box.exec("return require('tests.views.keeper').tf.layer");
    REQUIRE_FALSE(err.has_value());
    CHECK(err.error().code == errc::kStaleHandle);
    CHECK(box.exec("return require('tests.views.keeper').m[1]").error().code == errc::kStaleHandle);
    // Undoing a write to an object that is gone has nothing to restore.
    REQUIRE(box.revert(*mod));
    CHECK(run(box, "return vt.nothing() == nil") == value_list{Rhp::value{true}});
}

TEST_CASE("a struct view stands in for its type as a parameter", "[script][views]") {
    sandbox box = make_box();
    CHECK(run(box, "local t = vt.main() t.pos.x = 1 t.pos.y = 2 t.pos.z = 2 return vt.length2(t.pos)") == value_list{Rhp::value{9.0}});
    CHECK(run(box, "local b = vt.make_body() b:transform().layer = 5 return vt.maybe_layer(b.tf), vt.maybe_layer(nil)") ==
          value_list{Rhp::value{5}, Rhp::value{-1}});
    CHECK(fails(box, "return vt.length2(vt.main())").code == errc::kTypeMismatch);
}

TEST_CASE("pairs walks a struct view's fields and views compare by object", "[script][views]") {
    sandbox box = make_box();
    CHECK(run(box, "local n = 0 local names = {} for k, v in pairs(vt.main().pos) do n = n + 1 names[n] = k end return n, names[1], names[3]") ==
          value_list{Rhp::value{3}, Rhp::value{"x"}, Rhp::value{"z"}});
    CHECK(run(box, "return vt.main() == vt.main(), vt.main().pos == vt.main().pos, rawequal(vt.main(), vt.main())") ==
          value_list{Rhp::value{true}, Rhp::value{true}, Rhp::value{false}});
}

// ---- buffers -------------------------------------------------------------------------------------

TEST_CASE("buffers hold bytes a script owns", "[script][views][buffer]") {
    sandbox box = make_box();
    CHECK(run(box, "local b = rhp.buffer.new(4, 7) b[2] = 255 return #b, b[1], b[2], b:tostring(1, 2)") ==
          value_list{Rhp::value{4}, Rhp::value{7}, Rhp::value{255}, Rhp::value{std::string{"\x07\xff"}}});
    CHECK(run(box, "local b = rhp.buffer.from('abc') return b:tostring(), b:slice(2):tostring(), tostring(b)") ==
          value_list{Rhp::value{"abc"}, Rhp::value{"bc"}, Rhp::value{"buffer: 3 bytes"}});
    CHECK(fails(box, "rhp.buffer.new(2)[3] = 1").code == errc::kOutOfRange);
    CHECK(fails(box, "rhp.buffer.new(-1)").code == errc::kOutOfRange);
    const std::size_t effects = box.effects().size();
    run(box, "local b = rhp.buffer.new(16) b:write_u32(1, 5) b[16] = 1");
    CHECK(box.effects().size() == effects); // never journaled
}

TEST_CASE("buffers read and write numbers at byte positions in either byte order", "[script][views][buffer]") {
    sandbox box = make_box();
    CHECK(run(box, R"(
        local b = rhp.buffer.new(16)
        local p = b:write_u16(1, 0x0102, "be")
        p = b:write_i32(p, -2)
        p = b:write_f64(p, 1.25)
        return p, b[1], b[2], b:read_u16(1), b:read_u16(1, "be"), b:read_i32(3), b:read_f64(7), b:read_u8(3)
    )") == value_list{Rhp::value{15}, Rhp::value{1}, Rhp::value{2}, Rhp::value{0x0201}, Rhp::value{0x0102}, Rhp::value{-2}, Rhp::value{1.25},
                      Rhp::value{0xfe}});
    CHECK(fails(box, "rhp.buffer.new(3):read_u32(1)").code == errc::kOutOfRange);
    CHECK(fails(box, "rhp.buffer.new(4):write_u8(1, 300)").code == errc::kOutOfRange);
    CHECK(fails(box, "rhp.buffer.new(4):write_u8(1, 3, 'middle')").code == errc::kInvalidArgument);
    CHECK(run(box, "local b = rhp.buffer.new(8) b:write_i64(1, math.mininteger) return b:read_i64(1) == math.mininteger") ==
          value_list{Rhp::value{true}});
}

TEST_CASE("buffers pack and unpack with string.pack formats", "[script][views][buffer]") {
    sandbox box = make_box();
    CHECK(run(box, R"(
        local b = rhp.buffer.new(32)
        local p = b:pack(1, "<i4 s1 d", 42, "hey", 0.5)
        local n, s, d, next = b:unpack(1, "<i4 s1 d")
        return p, n, s, d, next
    )") == value_list{Rhp::value{17}, Rhp::value{42}, Rhp::value{"hey"}, Rhp::value{0.5}, Rhp::value{17}});
    CHECK(run(box, "local b = rhp.buffer.new(8) b:pack(5, '>I2', 513) return b:unpack(5, '>I2')") == value_list{Rhp::value{513}, Rhp::value{7}});
    CHECK(fails(box, "rhp.buffer.new(2):pack(1, 'i4', 1)").code == errc::kOutOfRange);
    CHECK_FALSE(box.exec("rhp.buffer.new(2):unpack(1, 'i4')").has_value());
}

TEST_CASE("typed views of a buffer share its bytes", "[script][views][buffer]") {
    sandbox box = make_box();
    CHECK(run(box, R"(
        local b = rhp.buffer.new(9)
        local f = b:view("f32", 2)
        f[1] = 1.5
        f[2] = -2
        return #f, f[1], b:read_f32(2), b:read_f32(6), f:kind(), vt.sum(f)
    )") == value_list{Rhp::value{2}, Rhp::value{1.5}, Rhp::value{1.5}, Rhp::value{-2.0}, Rhp::value{"f32"}, Rhp::value{-0.5}});
    CHECK(fails(box, "rhp.buffer.new(4):view('f64')[1] = 1").code == errc::kOutOfRange);
    CHECK(fails(box, "rhp.buffer.new(4):view('f16')").code == errc::kInvalidArgument);
    CHECK(fails(box, "rhp.buffer.new(4):view('u8', 2, 4)").code == errc::kOutOfRange);
    CHECK(run(box, "local b = rhp.buffer.from(vt.ints()) return #b, b:read_i32(5)") == value_list{Rhp::value{16}, Rhp::value{20}});
}

TEST_CASE("a buffer's memory counts against the memory limit", "[script][views][buffer]") {
    fx::reset();
    sandbox_options options;
    options.limits.memory = 1 << 20;
    options.output = [](std::string_view) {};
    sandbox box{std::move(options)};
    REQUIRE(box.install<fx::view_lib>());
    const auto r = box.exec("return rhp.buffer.new(4 * 1024 * 1024)");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == errc::kMemoryExceeded);
}

// ---- the guide's example (Docs/guide/views-and-buffers.md), as written there ---------------------

namespace view_tests_guide {
namespace game {

struct vec3 {
    float x = 0;
    float y = 0;
    float z = 0;
};

struct transform { // a view type: standard layout
    vec3 position;
    float scale[3] = {1, 1, 1};
    std::int32_t layer = 0;
    std::uint32_t id = 0;
};

struct entity_id {
    std::uint32_t value = 0;
    bool operator==(const entity_id&) const = default;
};

std::unordered_set<std::uint32_t> entities;
std::unordered_map<std::uint32_t, transform> transforms;
std::array<float, 256> heights{};

bool is_alive(const entity_id& e) {
    return entities.contains(e.value);
}

entity_id find(std::uint32_t id) {
    return entity_id{id};
}

transform* transform_of(entity_id e) { // nullptr when there is none: the script gets nil
    const auto it = transforms.find(e.value);
    return it != transforms.end() ? &it->second : nullptr;
}

std::span<float> height_map() {
    return heights;
}

float average(std::span<const float> values) {
    return values.empty() ? 0.0f : std::accumulate(values.begin(), values.end(), 0.0f) / static_cast<float>(values.size());
}

using lib = Rhp::lib<"game">::handle<"entity", entity_id, &is_alive>::fn<"find", &find>::view<"vec3", vec3>::field<"x", &vec3::x>::field<"y", &vec3::y>::field<"z", &vec3::z>::view<"transform", transform>::field<"position", &transform::position> // a nested view
    ::field<"scale", &transform::scale>                                                                                                                                                                                                              // an array: a typed view
    ::field<"layer", &transform::layer, Rhp::range<0, 31>>::ro_field<"id", &transform::id>::property<"transform", &transform_of>                                                                                                                     // e.transform
    ::fn<"height_map", &height_map>                                                                                                                                                                                                                  // a typed view of the array
    ::fn<"average", &average>;                                                                                                                                                                                                                       // takes a view, a buffer view or a table

} // namespace game
} // namespace view_tests_guide

TEST_CASE("the guide's views example runs and reverts", "[script][views][guide]") {
    namespace game = view_tests_guide::game;
    game::entities = {7, 8};
    game::transforms = {{7, game::transform{}}};
    game::heights.fill(2.0f);
    sandbox_options options;
    options.output = [](std::string_view) {};
    sandbox box{std::move(options)};
    REQUIRE(box.install<game::lib>());
    const auto mod = box.load("tests.views.guide", R"(
local t = game.find(7).transform      -- nil if entity 7 has no transform
t.position.y = t.position.y + 1       -- in place, journaled
t.scale[2] = 2
t.layer = 3                           -- t.layer = 40 raises: [out_of_range] transform.layer: must lie in [0, 31]

local h = game.height_map()
for i = 1, #h do h[i] = h[i] * 0.5 end -- 256 writes, one journal entry
print(game.average(h))                -- C++ reads the same memory: no copy

local b = rhp.buffer.new(16)          -- bytes this script owns
local pos = b:write_u32(1, 0xCAFE, "be")
local f = b:view("f32", pos, 2)       -- two floats over bytes 5..12
f[1], f[2] = 1.5, 2.5
print(game.average(f), b:read_u16(3, "be"))
result = {game.average(h), game.average(f), b:read_u16(3, "be"), game.find(8).transform == nil}
)");
    REQUIRE(mod.has_value());
    CHECK(box.exec("local r = require('tests.views.guide').result return r[1], r[2], r[3], r[4]").value() ==
          value_list{Rhp::value{1.0}, Rhp::value{2.0}, Rhp::value{0xCAFE}, Rhp::value{true}});
    CHECK(box.exec("game.find(7).transform.layer = 40").error().where == "transform.layer");
    const game::transform& t = game::transforms.at(7);
    CHECK(t.position.y == 1.0f);
    CHECK(t.scale[1] == 2.0f);
    CHECK(game::heights[0] == 1.0f);
    REQUIRE(box.unload(*mod));
    CHECK(t.position.y == 0.0f);
    CHECK(t.scale[1] == 1.0f);
    CHECK(t.layer == 0);
    CHECK(game::heights[255] == 2.0f);
}

// ---- tools ---------------------------------------------------------------------------------------

TEST_CASE("a test swaps a view binding like any lib function", "[script][views][testing]") {
    sandbox box = make_box();
    REQUIRE(box.enable_testing());
    REQUIRE(box.checkpoint("before"));
    CHECK(run(box, "local real = __rhp_test.swap(vt, 'samples', function() return {7, 8} end) "
                   "local fake = vt.samples() local v = real() v[1] = 6 return fake[1], #fake, v[1], #v") ==
          value_list{Rhp::value{7}, Rhp::value{2}, Rhp::value{6.0}, Rhp::value{4}});
    CHECK(fx::g_samples[0] == 6.0f);
    REQUIRE(box.revert_to("before"));
    CHECK(fx::g_samples[0] == 1.0f);
    CHECK(run(box, "return vt.samples():kind()") == value_list{Rhp::value{"f32"}});
}

TEST_CASE("stubs describe spans, view types and buffers", "[script][views][stubs]") {
    const std::string patch = Rhp::script::stubs::generate<fx::view_lib>(Rhp::role::kPatch);
    CHECK(has(patch, "---@return rhp.span<number>\nfunction vt.samples() end"));
    CHECK(has(patch, "---@param arg1 rhp.span<integer>\n---@return integer\nfunction vt.sum_ints(arg1) end"));
    CHECK(has(patch, "---@class transform\n---@field pos vec3 read-only\n---@field m rhp.span<number> read-only\n---@field layer integer [0, 31]: render layer\n"
                     "---@field id integer read-only\n---@field visible boolean\n---@field kind integer\n---@field tags rhp.span<integer> read-only\n"));
    CHECK(has(patch, "---@field transform fun(self: body): transform?"));
    CHECK(has(patch, "---@field tf transform? read-only"));
    CHECK(has(patch, "---@return transform\nfunction vt.main() end"));
    CHECK(has(patch, "---@param arg1 vec3\n---@return number\nfunction vt.length2(arg1) end"));
    CHECK(has(patch, "---@param arg1 transform?\n"));
    const std::string observe = Rhp::script::stubs::generate<fx::view_lib>(Rhp::role::kObserve);
    CHECK(has(observe, "---@field x number read-only\n"));
    const std::string api = Rhp::script::stubs::rhp_api(Rhp::role::kObserve);
    CHECK(has(api, "function rhp.buffer.new(size, fill) end"));
    CHECK(has(api, "---@class rhp.span<T>: { [integer]: T }"));
    CHECK(has(api, "function buffer:read_u32(pos, order) end"));
}

TEST_CASE("api() lists view types with their fields", "[script][views][stubs]") {
    const Rhp::value desc = Rhp::script::api::describe<fx::view_lib>(Rhp::role::kPatch);
    const auto* views = desc.find("views");
    REQUIRE(views != nullptr);
    const auto* list = views->get_if<Rhp::value::array>();
    REQUIRE(list != nullptr);
    REQUIRE(list->size() == 2);
    CHECK((*list)[1].find("name")->get_if<std::string>() != nullptr);
    CHECK(*(*list)[1].find("name")->get_if<std::string>() == "transform");
}

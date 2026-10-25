#include <cstdint>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/wire/codec/msgpack.hpp>
#include <rhp/wire/messages.hpp>

using Rhp::errc;
using Rhp::value;
namespace wire = Rhp::wire;

namespace {

// Through the codec too, as the session sends it.
template <class T>
T roundtrip(const T& m) {
    Rhp::utils::byte_buffer bytes;
    REQUIRE(wire::msgpack::encode(Rhp::to_value(m), bytes));
    auto v = wire::msgpack::decode(bytes.view());
    REQUIRE(v);
    auto back = Rhp::from_value<T>(*v);
    REQUIRE(back);
    return *back;
}

} // namespace

TEST_CASE("messages: handshake round trips", "[wire][messages]") {
    const wire::hello h{wire::kProtocolRevision, "linux", value{value::map{{value{"key"}, value{"dev"}}}}};
    const auto h2 = roundtrip(h);
    CHECK(h2.revision == h.revision);
    CHECK(h2.platform == "linux");
    CHECK(h2.auth == h.auth);

    const wire::welcome w{Rhp::session_id{42}, "dev", Rhp::role::kPatch, 2000, "windows"};
    const auto w2 = roundtrip(w);
    CHECK(w2.session == Rhp::session_id{42});
    CHECK(w2.identity == "dev");
    CHECK(w2.granted == Rhp::role::kPatch);
    CHECK(w2.heartbeat_ms == 2000);
}

TEST_CASE("messages: envelope keeps req / idem and body", "[wire][messages]") {
    const wire::envelope e{7, 99, value{"x"}};
    const auto e2 = roundtrip(e);
    CHECK(e2.req == 7);
    CHECK(e2.idem == 99);
    CHECK(e2.body == value{"x"});
    // idem 0 is left out entirely.
    const auto plain = Rhp::to_value(wire::envelope{1, 0, value{}});
    CHECK(plain.find("idem") == nullptr);
}

TEST_CASE("messages: module refs by id or by name", "[wire][messages]") {
    const wire::module_ref by_id{Rhp::module_id{5}};
    const wire::module_ref by_name{"combat.low_grav"};
    CHECK(Rhp::to_value(by_id) == value{5});
    CHECK(Rhp::to_value(by_name) == value{"combat.low_grav"});
    CHECK(roundtrip(by_id) == by_id);
    CHECK(roundtrip(by_name) == by_name);
}

TEST_CASE("messages: requests round trip", "[wire][messages]") {
    const auto call = roundtrip(wire::call_request{"m", "f", value::array{value{1}, value{"two"}}});
    CHECK(call.module.name == "m");
    CHECK(call.function == "f");
    CHECK(call.args.size() == 2);

    const auto exec = roundtrip(wire::exec_request{"return 1", "repl", value{}});
    CHECK(exec.source == "return 1");
    CHECK(exec.chunk == "repl");

    CHECK(roundtrip(wire::rollback_request{Rhp::module_id{3}, 2}).steps == 2);
    CHECK(roundtrip(wire::unload_request{"m", true}).force);
    CHECK(roundtrip(wire::tag_request{"before"}).tag == "before");
    CHECK(roundtrip(wire::cancel_request{11}).target == 11);
}

TEST_CASE("messages: defaults fill missing optional fields", "[wire][messages]") {
    const value minimal{value::map{{value{"source"}, value{"return 1"}}}};
    auto exec = Rhp::from_value<wire::exec_request>(minimal);
    REQUIRE(exec);
    CHECK(exec->chunk == "exec");
    auto rollback = Rhp::from_value<wire::rollback_request>(value{value::map{{value{"module"}, value{1}}}});
    REQUIRE(rollback);
    CHECK(rollback->steps == 1);
}

TEST_CASE("messages: malformed messages are protocol errors", "[wire][messages]") {
    auto not_map = Rhp::from_value<wire::exec_request>(value{"oops"});
    REQUIRE_FALSE(not_map);
    CHECK(not_map.error().code == errc::kProtocol);
    auto missing = Rhp::from_value<wire::load_request>(value{value::map{{value{"name"}, value{"m"}}}});
    REQUIRE_FALSE(missing);
    CHECK(missing.error().code == errc::kProtocol);
    auto wrong_type = Rhp::from_value<wire::load_request>(value{value::map{{value{"name"}, value{1}}, {value{"source"}, value{""}}}});
    REQUIRE_FALSE(wrong_type);
    CHECK(wrong_type.error().where == "load.name");
    auto bad_args = Rhp::from_value<wire::call_request>(value{value::map{{value{"module"}, value{1}}, {value{"function"}, value{"f"}}, {value{"args"}, value{3}}}});
    CHECK_FALSE(bad_args);
}

TEST_CASE("messages: replies round trip", "[wire][messages]") {
    wire::module_status s;
    s.id = Rhp::module_id{2};
    s.name = "tuning.moon";
    s.state = "faulted";
    s.effects = 3;
    s.revision = Rhp::revision_id{4};
    s.source_hash = 0xdeadbeef;
    s.dependencies = {Rhp::module_id{1}};
    s.fault = Rhp::make_error(errc::kRuntime, "boom", "@tuning.moon:3");
    CHECK(roundtrip(s) == s);

    const wire::revert_summary r{5, 1, {Rhp::make_error(errc::kRevertPartial, "undo threw")}, true};
    CHECK(roundtrip(r) == r);

    const auto emit = roundtrip(wire::emit_message{Rhp::module_id{9}, value{1.5}});
    CHECK(emit.module == Rhp::module_id{9});
    CHECK(emit.data == value{1.5});
}

TEST_CASE("messages: errors cross the wire / unknown codes become runtime", "[wire][messages]") {
    Rhp::error e = Rhp::make_error(errc::kForbidden, "needs patch", "game.gravity");
    e.traceback = "stack";
    auto back = Rhp::from_value<Rhp::error>(Rhp::to_value(e));
    REQUIRE(back);
    CHECK(*back == e);
    auto unknown = Rhp::from_value<Rhp::error>(value{value::map{{value{"code"}, value{"from_the_future"}}, {value{"message"}, value{"m"}}}});
    REQUIRE(unknown);
    CHECK(unknown->code == errc::kRuntime);
    CHECK(unknown->message == "m");
}

TEST_CASE("messages: Stage 4 fields: signatures / pins / blob chunks", "[wire][messages]") {
    const value sig{value::map{{value{"signer"}, value{"dev"}}, {value{"sig"}, value{value::bytes(64, std::byte{7})}}}};
    const auto exec = roundtrip(wire::exec_request{"return 1", "exec", sig});
    CHECK(exec.signature == sig);
    CHECK(roundtrip(wire::exec_request{"return 1", "exec", value{}}).signature.is_nil());
    CHECK(roundtrip(wire::load_request{"m", "return {}", sig}).signature == sig);
    CHECK(roundtrip(wire::reload_request{wire::module_ref{"m"}, "return {}", sig}).signature == sig);

    wire::module_status s;
    s.id = Rhp::module_id{3};
    s.name = "kept";
    s.state = "active";
    s.pinned = true;
    CHECK(roundtrip(s).pinned);

    const wire::blob_chunk chunk{42, "configs", "game.ini", 10, 4, value::bytes{std::byte{1}, std::byte{2}}};
    const auto back = roundtrip(chunk);
    CHECK(back.transfer == 42);
    CHECK(back.sink == "configs");
    CHECK(back.name == "game.ini");
    CHECK(back.total == 10);
    CHECK(back.offset == 4);
    CHECK(back.data == chunk.data);
    CHECK_FALSE(Rhp::from_value<wire::blob_chunk>(value{value::map{{value{"transfer"}, value{1}}}}));

    // Blobs are open to every role at the wire: each sink checks its own.
    CHECK(wire::required_role(wire::op::kBlob) == Rhp::role::kObserve);
    CHECK(wire::required_role(wire::op::kPin) == Rhp::role::kAdmin);
    CHECK(wire::required_role(wire::op::kUnpin) == Rhp::role::kAdmin);
    CHECK(wire::kProtocolRevision >= 2);
}

TEST_CASE("messages: subscribe requests and events round trip", "[wire][messages][stage7]") {
    CHECK(roundtrip(wire::subscribe_request{"game.round_over"}).name == "game.round_over");
    const wire::event_message m{"game.score", Rhp::module_id{4}, value::array{value{"red"}, value{3}, value{}}, 7};
    const auto back = roundtrip(m);
    CHECK(back.name == m.name);
    CHECK(back.module == m.module);
    CHECK(back.args == m.args);
    CHECK(back.dropped == 7);
}

TEST_CASE("messages: event fields default when missing", "[wire][messages][stage7]") {
    value::map only_name;
    only_name.emplace_back(value{"name"}, value{"game.x"});
    const auto e = Rhp::from_value<wire::event_message>(value{only_name});
    REQUIRE(e);
    CHECK(e->module == Rhp::module_id{});
    CHECK(e->args.empty());
    CHECK(e->dropped == 0);
    CHECK_FALSE(Rhp::from_value<wire::event_message>(value{value::map{}}));
    CHECK_FALSE(Rhp::from_value<wire::subscribe_request>(value{value::map{}}));
    value::map bad_args = only_name;
    bad_args.emplace_back(value{"args"}, value{5});
    CHECK(Rhp::from_value<wire::event_message>(value{bad_args}).error().code == errc::kProtocol);
}

TEST_CASE("messages: release ops need admin to change and observe to read", "[wire][messages][stage10]") {
    CHECK(wire::kProtocolRevision == 5);
    for (const auto code : {wire::op::kReleaseApply, wire::op::kReleaseConfirm, wire::op::kReleaseDeactivate}) {
        CHECK(wire::required_role(code) == Rhp::role::kAdmin);
        CHECK(wire::is_request(code));
    }
    CHECK(wire::required_role(wire::op::kReleaseStatus) == Rhp::role::kObserve);
    CHECK(wire::required_role(wire::op::kRevoke) == Rhp::role::kObserve);
    CHECK(wire::to_string(wire::op::kRevoke) == "revoke");
    CHECK(static_cast<std::uint16_t>(wire::op::kRevoke) < 48);
}

TEST_CASE("messages: release messages round-trip", "[wire][messages][stage10]") {
    const wire::release_apply_request apply{Rhp::value::bytes{std::byte{1}, std::byte{2}}, "health"};
    CHECK(*Rhp::from_value<wire::release_apply_request>(Rhp::to_value(apply)) == apply);
    const wire::release_channel_request channel{"game.balance", true, Rhp::value::bytes(32, std::byte{7})};
    CHECK(*Rhp::from_value<wire::release_channel_request>(Rhp::to_value(channel)) == channel);
    wire::channel_status_message c;
    c.channel = "game.balance";
    c.running = "candidate";
    c.active = wire::release_info_message{Rhp::value::bytes(32, std::byte{7}), 3, "three", {"dev"}};
    c.candidate = wire::release_info_message{Rhp::value::bytes(32, std::byte{8}), 4, "four", {"dev", "ops"}};
    c.previous = Rhp::value::bytes(32, std::byte{6});
    c.floor = 4;
    c.attempts = 1;
    c.confirm = "manual";
    c.modules = {"tuning"};
    wire::release_status_reply status{"mygame", "1.0", "windows", 2, {c}};
    CHECK(*Rhp::from_value<wire::release_status_reply>(Rhp::to_value(status)) == status);
    const wire::release_apply_reply reply{"game.balance", Rhp::value::bytes(32, std::byte{8}), 4, "candidate", false, Rhp::value::bytes(32, std::byte{7}), {"dev"}};
    CHECK(*Rhp::from_value<wire::release_apply_reply>(Rhp::to_value(reply)) == reply);
    CHECK_FALSE(Rhp::from_value<wire::release_apply_request>(Rhp::value{"nope"}));
}

TEST_CASE("messages: subscribe ops need observe and event is a reply", "[wire][messages][stage7]") {
    CHECK(wire::required_role(wire::op::kSubscribe) == Rhp::role::kObserve);
    CHECK(wire::required_role(wire::op::kUnsubscribe) == Rhp::role::kObserve);
    CHECK(wire::is_request(wire::op::kSubscribe));
    CHECK(wire::is_reply(wire::op::kEvent));
    CHECK(wire::is_sequenced(wire::op::kEvent));
    CHECK(wire::to_string(wire::op::kEvent) == "event");
    CHECK(wire::is_known(static_cast<std::uint16_t>(wire::op::kUnsubscribe)));
}

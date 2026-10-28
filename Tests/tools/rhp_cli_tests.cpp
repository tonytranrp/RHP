#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "dap.hpp"
#include "dev.hpp"
#include "json.hpp"
#include "release_files.hpp"
#include "shell.hpp"
#include "text.hpp"
#if !defined(_WIN32)
#include <sys/wait.h>
#endif

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/eventually.hpp>
#include <rhp_test/hardening.hpp>

#include <rhp/client/client.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/event/events.hpp>
#include <rhp/host/host.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/net/tcp/tcp.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/security/certified.hpp>
#include <rhp/security/dev_session.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/identity_file.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/operator_cert.hpp>
#include <rhp/security/psk_keyring.hpp>
#include <rhp/utils/scope_guard.hpp>

using namespace std::chrono_literals;
namespace fs = std::filesystem;

namespace cli_fixtures {

int g_level = 0;

using cli_lib = Rhp::lib<"s4cli">::var<"level", &g_level>;
using cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>;

// Separate processes start slowly: a longer default wait, polled less often.
bool eventually(const std::function<bool()>& done, std::chrono::milliseconds timeout = 20s) {
    return rhp_test::eventually(done, timeout, 5ms);
}

// What the shell printed.
struct screen {
    std::mutex mutex;
    std::vector<std::pair<rhp_cli::style, std::string>> lines;

    [[nodiscard]] rhp_cli::printer printer() {
        return [this](rhp_cli::style s, std::string_view text) {
            const std::scoped_lock lock{mutex};
            lines.emplace_back(s, std::string{text});
        };
    }
    [[nodiscard]] bool has(std::string_view text) {
        const std::scoped_lock lock{mutex};
        for (const auto& [s, line] : lines) {
            if (line.find(text) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
    [[nodiscard]] std::string all() {
        const std::scoped_lock lock{mutex};
        std::string out;
        for (const auto& [s, line] : lines) {
            out += line;
            out += '\n';
        }
        return out;
    }
    [[nodiscard]] std::string last() {
        const std::scoped_lock lock{mutex};
        return lines.empty() ? std::string{} : lines.back().second;
    }
};

// A fresh scratch folder, removed afterwards.
struct scratch_dir {
    fs::path path;

    scratch_dir() {
        const auto r = *Rhp::platform::random_array<6>();
        std::string suffix;
        for (const std::byte b : r) {
            suffix += std::format("{:02x}", std::to_integer<unsigned>(b));
        }
        path = fs::temp_directory_path() / ("rhp_cli_" + suffix);
        fs::create_directories(path);
    }
    ~scratch_dir() {
        // The processes' own logs (server.log, ...): ctest shows them with a failing case's output,
        // the only way to see why a spawned host failed on a machine we can't log into (CI).
        std::error_code ec;
        for (const auto& entry : fs::directory_iterator{path, ec}) {
            if (entry.is_regular_file(ec) && (entry.path().extension() == ".log" || entry.path().extension() == ".txt")) {
                const auto text = read(entry.path().filename().string());
                std::cout << "---- " << entry.path().filename().string() << " ----\n"
                          << text.substr(0, 8192)
                          << (text.size() > 8192 ? "\n[...]\n" : "\n");
            }
        }
        fs::remove_all(path, ec);
    }
    scratch_dir(const scratch_dir&) = delete;
    scratch_dir& operator=(const scratch_dir&) = delete;

    [[nodiscard]] std::string file(std::string_view name) const { return (path / name).string(); }
    void write(std::string_view name, std::string_view text) const { std::ofstream{path / name, std::ios::binary} << text; }
    [[nodiscard]] std::string read(std::string_view name) const {
        std::ifstream in{path / name, std::ios::binary};
        return {std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
    }
};

// Whether this process can open a TCP connection to 127.0.0.1:port at all: tells "the spawned
// host isn't reachable" from "rhp-cli can't reach it" when a process test fails.
[[nodiscard]] std::string probe_tcp(std::uint16_t port) {
    Rhp::net::io_context io;
    std::optional<std::string> outcome;
    Rhp::net::tcp::dial(io, Rhp::endpoint::dial("127.0.0.1", port), [&](Rhp::result<std::unique_ptr<Rhp::net::link>> r) {
        outcome = r ? std::string{"connected"} : std::format("{}", r.error());
    });
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!outcome && std::chrono::steady_clock::now() < deadline) {
        io.run_one_for(std::chrono::milliseconds{10});
    }
    return outcome.value_or("timed out");
}

} // namespace cli_fixtures

using namespace cli_fixtures;

// ---- text helpers -----------------------------------------------------------------------------------------

TEST_CASE("rhp-cli: endpoints", "[cli][text]") {
    auto ep = rhp_cli::parse_endpoint("127.0.0.1:7777", false, false);
    REQUIRE(ep);
    CHECK(*ep == Rhp::endpoint::dial("127.0.0.1", 7777));
    CHECK(*rhp_cli::parse_endpoint("[::1]:80", true, false) == Rhp::endpoint::listen("::1", 80));
    CHECK(rhp_cli::parse_endpoint("10.0.0.5:1", false, true)->insecure_lan);
    CHECK_FALSE(rhp_cli::parse_endpoint("localhost", false, false));
    CHECK_FALSE(rhp_cli::parse_endpoint("localhost:http", false, false));
    CHECK_FALSE(rhp_cli::parse_endpoint("::1:80", false, false));
    CHECK_FALSE(rhp_cli::parse_endpoint("host:70000", false, false));
}

TEST_CASE("rhp-cli: rollout stages parse whole", "[cli][text]") {
    const auto stage = rhp_cli::parse_stage("0.25:3000");
    REQUIRE(stage.has_value());
    CHECK(stage->fraction == 0.25);
    CHECK(stage->observe == std::chrono::milliseconds{3000});
    CHECK(rhp_cli::parse_stage("1")->observe == std::chrono::milliseconds{0});
    for (const char* bad : {"", "0.5abc:30", "0.5:30x", "nan:10", "inf", "1.5:0", "-0.1:0", ":10", "0.5:"}) {
        CHECK_FALSE(rhp_cli::parse_stage(bad).has_value());
    }
}

TEST_CASE("rhp-cli: JSON round trips and rejects what isn't JSON", "[cli][text]") {
    const auto v = rhp_cli::parse_json(R"( {"seq": 3, "ok": true, "x": -1.5e2, "s": "a\"b\\n\u00e9\ud83d\ude00", "list": [1, null, {}], "e": []} )");
    REQUIRE(v.has_value());
    CHECK(*v->find("seq") == Rhp::value{3});
    CHECK(*v->find("ok") == Rhp::value{true});
    CHECK(*v->find("x") == Rhp::value{-150.0});
    CHECK(*v->find("s") == Rhp::value{"a\"b\\n\xc3\xa9\xf0\x9f\x98\x80"});
    CHECK(v->find("list")->get_if<Rhp::value::array>()->size() == 3);
    CHECK(rhp_cli::parse_json(rhp_cli::to_json(*v)) == v);
    CHECK(rhp_cli::to_json(Rhp::value{"tab\there"}) == R"("tab\there")");
    for (const char* bad : {"", "{", "[1,]", "{\"a\" 1}", "tru", "\"unterminated", "01x", "{\"a\":1}}", "\"\x01\"", "nan", R"("\ud83d")", R"("\ude00")", R"("\ud83dx")",
                            R"("\ud83dA")"}) {
        CHECK_FALSE(rhp_cli::parse_json(bad).has_value());
    }
    std::string deep(100, '[');
    deep += std::string(100, ']');
    CHECK_FALSE(rhp_cli::parse_json(deep).has_value());
}

TEST_CASE("rhp-cli: source paths map to module names", "[cli][text]") {
    const rhp_cli::source_map plain{""};
    CHECK(plain.module_for("C:/work/game/combat.lua") == "combat");
    CHECK_FALSE(plain.path_for("game.combat").has_value()); // no root: no file to show
    const std::string root = (fs::temp_directory_path() / "rhp_src").string();
    const rhp_cli::source_map rooted{root};
    CHECK(rooted.module_for((fs::path{root} / "game" / "combat.lua").string()) == "game.combat");
    std::error_code ec;
    fs::remove_all(root, ec);
    CHECK_FALSE(rooted.path_for("game.combat").has_value()); // not there (yet)
    fs::create_directories(fs::path{root} / "game");
    std::ofstream{fs::path{root} / "game" / "combat.lua"} << "return 1\n";
    CHECK(rooted.path_for("game.combat") == (fs::path{root} / "game" / "combat.lua").make_preferred().string());
    fs::remove_all(root, ec);
}

TEST_CASE("rhp-cli: DAP messages are read by their length and refused when malformed", "[cli][dap]") {
    const auto read_all = [](std::string_view bytes) {
        std::vector<std::optional<std::string>> out;
        std::istringstream in{std::string{bytes}};
        while (true) {
            auto m = rhp_cli::read_dap_message([&in] { return in.get(); });
            const bool end = !m;
            out.push_back(std::move(m));
            if (end) {
                break;
            }
        }
        return out;
    };
    const auto ok = read_all("Content-Length: 2\r\n\r\n{}\r\nContent-Length:3\r\nContent-Type: application/json\r\n\r\nabcContent-Length: 0 \r\n\r\n");
    REQUIRE(ok.size() == 4);
    CHECK(ok[0] == "{}");
    CHECK(ok[1] == "abc");
    CHECK(ok[2] == "");
    CHECK_FALSE(ok[3].has_value());
    std::string long_header = "X-Junk: ";
    long_header += std::string(4000, 'a');
    std::string many_headers;
    for (int i = 0; i < 40; ++i) {
        many_headers += "X: y\r\n";
    }
    many_headers += "Content-Length: 2\r\n\r\n{}";
    for (const std::string& bad : {std::string{"X: y\r\n\r\n{}"}, std::string{"Content-Length: 2x\r\n\r\n{}"}, std::string{"Content-Length: -1\r\n\r\n"},
                                   std::string{"Content-Length:\r\n\r\n"}, std::string{"Content-Length: 99999999999999999999999\r\n\r\n"},
                                   std::string{"Content-Length: 70000000\r\n\r\n"}, std::string{"Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}"},
                                   std::string{"Content-Length: 5\r\n\r\n{}"}, long_header, many_headers}) {
        const auto got = read_all(bad);
        CHECK(got.size() == 1);
        CHECK_FALSE(got.front().has_value());
    }
}

TEST_CASE("rhp-cli: unfinished Lua keeps the REPL reading", "[cli][text]") {
    CHECK_FALSE(rhp_cli::lua_incomplete("return 1"));
    CHECK(rhp_cli::lua_incomplete("for i = 1, 3 do"));
    CHECK_FALSE(rhp_cli::lua_incomplete("for i = 1, 3 do x = i end"));
    CHECK(rhp_cli::lua_incomplete("if x then\n y = 1\nelseif z then"));
    CHECK_FALSE(rhp_cli::lua_incomplete("if x then y = 1 elseif z then y = 2 else y = 3 end"));
    CHECK(rhp_cli::lua_incomplete("local t = {"));
    CHECK(rhp_cli::lua_incomplete("f("));
    CHECK(rhp_cli::lua_incomplete("repeat x = x + 1"));
    CHECK_FALSE(rhp_cli::lua_incomplete("repeat x = x + 1 until x > 3"));
    CHECK(rhp_cli::lua_incomplete("s = [[long"));
    CHECK(rhp_cli::lua_incomplete("--[==[ comment"));
    CHECK_FALSE(rhp_cli::lua_incomplete("s = 'do' -- function"));
    CHECK_FALSE(rhp_cli::lua_incomplete("t.end_ = 1 x = [=[ do ]=]"));
    CHECK_FALSE(rhp_cli::lua_incomplete("x = 'unterminated\n")); // an error for the compiler, not more input
    CHECK(rhp_cli::lua_incomplete("local f = function(a)\n return a"));
}

TEST_CASE("rhp-cli: values / words / literals / stubs / module names", "[cli][text]") {
    using Rhp::value;
    CHECK(rhp_cli::format_value(value{}) == "nil");
    CHECK(rhp_cli::format_value(value{std::int64_t{3}}) == "3");
    CHECK(rhp_cli::format_value(value{2.5}) == "2.5");
    CHECK(rhp_cli::format_value(value{"a\"b\n"}) == "\"a\\\"b\\n\"");
    CHECK(rhp_cli::format_value(value{value::array{value{1}, value{true}}}) == "{1, true}");
    CHECK(rhp_cli::format_value(value{value::map{{value{"x"}, value{1}}, {value{"not ok"}, value{2}}}}) == "{x = 1, [\"not ok\"] = 2}");
    CHECK(rhp_cli::format_value(value{value::bytes(5)}) == "<5 bytes>");
    CHECK(rhp_cli::format_values({value{1}, value{"a"}}) == "1\t\"a\"");

    CHECK(rhp_cli::split_words(R"(load  low "my file.lua" x\y)") == std::vector<std::string>{"load", "low", "my file.lua", "x\\y"});
    CHECK(rhp_cli::split_words(R"(call m f "say \"hi\"")") == std::vector<std::string>{"call", "m", "f", "say \"hi\""});
    CHECK(rhp_cli::split_words(R"(load m "C:\dir\x.lua")") == std::vector<std::string>{"load", "m", R"(C:\dir\x.lua)"});

    CHECK(rhp_cli::parse_literal("42") == value{std::int64_t{42}});
    CHECK(rhp_cli::parse_literal("-1.5") == value{-1.5});
    CHECK(rhp_cli::parse_literal("2.5e3") == value{2500.0});
    CHECK(rhp_cli::parse_literal("1.5x") == value{std::string{"1.5x"}}); // not a whole number: a string
    CHECK(rhp_cli::parse_literal("true") == value{true});
    CHECK(rhp_cli::parse_literal("nil").is_nil());
    CHECK(rhp_cli::parse_literal("'x y'") == value{"x y"});
    CHECK(rhp_cli::parse_literal("word") == value{"word"});

    const auto names = rhp_cli::names_from_stubs("---@meta\n---@class game\n---@field gravity number\ngame = {}\nfunction game.spawn(arg1) end\n");
    CHECK(names == std::vector<std::string>{"game", "game.gravity", "game.spawn"});
    CHECK(rhp_cli::module_name_for("scripts/Low_Grav.lua") == "low_grav");
    CHECK(rhp_cli::module_name_for("C:\\x\\tune.v.lua") == "tune.v");
    CHECK(rhp_cli::parse_module("#4").id == Rhp::module_id{4});
    CHECK(rhp_cli::parse_module("tune").name == "tune");
    CHECK(rhp_cli::parse_module("123456789012345678901234").name == "123456789012345678901234"); // too long for an id
    CHECK(rhp_cli::split_words(R"(call m f "42" 42)", true) == std::vector<std::string>{"call", "m", "f", R"("42")", "42"});
    CHECK(rhp_cli::parse_literal(R"("42")") == value{"42"});
}

TEST_CASE("rhp-cli: connect --dev picks the one dev session or the named one", "[cli][dev]") {
    scratch_dir dir;
    const fs::path sessions = dir.path / "dev";
    CHECK(rhp_cli::pick_dev_session(sessions, "").error().code == Rhp::errc::kNotFound); // no folder yet
    fs::create_directories(sessions);
    dir.write("dev/notes.txt", "not a session");
    CHECK(rhp_cli::pick_dev_session(sessions, "").error().code == Rhp::errc::kNotFound);

    dir.write("dev/game.rhpdev", "");
    CHECK(*rhp_cli::pick_dev_session(sessions, "") == sessions / "game.rhpdev");
    CHECK(*rhp_cli::pick_dev_session(sessions, "game") == sessions / "game.rhpdev");
    CHECK(rhp_cli::pick_dev_session(sessions, "editor").error().code == Rhp::errc::kNotFound);
    CHECK(rhp_cli::pick_dev_session(sessions, "../dev/game").error().code == Rhp::errc::kInvalidArgument);

    dir.write("dev/editor.rhpdev", "");
    const auto several = rhp_cli::pick_dev_session(sessions, "");
    REQUIRE_FALSE(several);
    CHECK(several.error().code == Rhp::errc::kInvalidArgument);
    CHECK(several.error().message.find("editor, game") != std::string::npos);
    CHECK(*rhp_cli::pick_dev_session(sessions, "editor") == sessions / "editor.rhpdev");
}

TEST_CASE("rhp-cli: a dev session must be on loopback or local IPC", "[cli][dev]") {
    Rhp::security::dev_session s;
    s.app = "game";
    s.transport = "tcp";
    s.port = 7777;
    for (const char* host : {"127.0.0.1", "::1", "localhost"}) {
        s.host = host;
        const auto target = rhp_cli::dev_endpoint(s);
        REQUIRE(target);
        CHECK_FALSE(target->ipc);
        CHECK(target->ep == Rhp::endpoint::dial(host, 7777));
    }
    for (const char* host : {"10.0.0.5", "0.0.0.0", "example.com", "cafe1"}) {
        s.host = host;
        CHECK(rhp_cli::dev_endpoint(s).error().code == Rhp::errc::kForbidden);
    }
    s.transport = "websocket"; // not a transport rhp-cli dials for dev sessions, even on loopback
    s.host = "127.0.0.1";
    CHECK(rhp_cli::dev_endpoint(s).error().code == Rhp::errc::kForbidden);
    s.transport = "local_ipc";
    s.host = "game";
    s.port = 0;
    const auto ipc = rhp_cli::dev_endpoint(s);
    REQUIRE(ipc);
    CHECK(ipc->ipc);
    CHECK(ipc->ep == Rhp::endpoint::dial("game", 0));
}

// ---- the shell, in-process ----------------------------------------------------------------------------------

TEST_CASE("rhp-cli: the shell drives the whole module lifecycle", "[cli][shell]") {
    const auto dev = *Rhp::security::ed25519_secret_key::generate();
    const auto psk = *Rhp::security::key::generate();
    const auto at = Rhp::endpoint::listen("cli.shell", 1);
    Rhp::host<cfg> host{at, Rhp::security::keyring{{"dev", psk, Rhp::role::kAdmin}}, Rhp::security::trusted_signers{{"dev", dev.public_key()}}};
    REQUIRE(host.install<cli_lib>());
    std::vector<std::byte> blob;
    std::mutex blob_mutex;
    REQUIRE(host.on_blob("files", [&](const Rhp::blob_view& b) -> Rhp::result<void> {
        const std::scoped_lock lock{blob_mutex};
        blob.assign(b.bytes.begin(), b.bytes.end());
        return {};
    }));
    std::jthread game{[&host](std::stop_token stop) {
        while (!stop.stop_requested()) {
            host.pump();
            std::this_thread::sleep_for(1ms);
        }
    }};

    screen out;
    Rhp::client_options opts;
    auto print = out.printer();
    opts.on_output = [print](std::uint64_t, std::string_view line) { print(rhp_cli::style::kOutput, line); };
    Rhp::client<cfg> c{at.reversed(), Rhp::security::psk_identity{"dev", psk}, Rhp::security::signing_key{"dev", dev}, opts};
    std::atomic<int> polls{0};
    std::atomic<bool> interrupt{false};
    rhp_cli::shell<cfg> sh{c, out.printer(), [&] { return interrupt.load() && ++polls > 2; }};
    scratch_dir dir;

    CHECK(sh.feed("return 1 + 1"));
    CHECK(out.last() == "2");
    CHECK(sh.feed("exec print('hi from lua') return 'x'"));
    CHECK(eventually([&] { return out.has("hi from lua"); }));

    // Multi-line Lua.
    CHECK(sh.feed("for i = 1, 3 do"));
    CHECK(sh.continuing());
    CHECK(sh.feed("  s4cli.level = s4cli.level + i"));
    CHECK(sh.feed("end"));
    CHECK_FALSE(sh.continuing());
    CHECK(sh.feed("return s4cli.level"));
    CHECK(out.last() == "6");

    dir.write("tune.lua", "s4cli.level = 10 return {get = function() return s4cli.level end}");
    dir.write("tune2.lua", "s4cli.level = 20 return {get = function() return s4cli.level * 2 end}");
    CHECK(sh.feed(std::format("load tune \"{}\"", dir.file("tune.lua"))));
    CHECK(out.has("loaded tune #"));
    CHECK(sh.feed("call tune get"));
    CHECK(out.last() == "10");
    CHECK(sh.feed(std::format("reload tune \"{}\"", dir.file("tune2.lua"))));
    CHECK(out.has("reloaded tune (revision 2)"));
    CHECK(sh.feed("call tune get"));
    CHECK(out.last() == "40");
    CHECK(sh.feed("rollback tune"));
    CHECK(out.has("rolled back tune to revision 3"));
    CHECK(sh.feed("status tune"));
    CHECK(out.last().find("tune [active] revision 3") != std::string::npos);
    CHECK(sh.feed("pin tune"));
    CHECK(sh.feed("list"));
    CHECK(out.has("pinned"));
    CHECK(sh.feed("unload tune"));
    CHECK(out.has("is pinned: unpin it first"));
    CHECK(sh.feed("unpin tune"));
    CHECK(sh.feed("checkpoint before"));
    CHECK(sh.feed("s4cli.level = 99"));
    CHECK(sh.feed("revert_to before"));
    CHECK(out.has("reverted to before: 1 effects undone"));
    CHECK(sh.feed("revert tune"));
    CHECK(sh.feed("unload tune"));
    CHECK(out.has("unloaded: "));
    CHECK(sh.feed("whoami"));
    CHECK(out.last().starts_with("dev (admin)"));
    CHECK(sh.feed(std::format("stubs > \"{}\"", dir.file("api.lua"))));
    CHECK(dir.read("api.lua").find("---@class s4cli") != std::string::npos);
    dir.write("data.bin", "hello blob");
    CHECK(sh.feed(std::format("blob files \"{}\"", dir.file("data.bin"))));
    {
        const std::scoped_lock lock{blob_mutex};
        CHECK(std::string(reinterpret_cast<const char*>(blob.data()), blob.size()) == "hello blob");
    }
    CHECK(sh.feed("help"));
    CHECK(sh.feed("rollback"));
    CHECK(out.last().starts_with("usage: rollback"));

    const int failed_before = sh.failures();
    CHECK(sh.feed("error('boom')"));
    CHECK(out.last().find("boom") != std::string::npos);
    CHECK(sh.failures() == failed_before + 1);

    // Ctrl+C: the running script is cancelled on the host.
    interrupt = true;
    CHECK(sh.feed("while true do end"));
    CHECK(out.last().find("cancelled") != std::string::npos);
    interrupt = false;

    // Tab completion: commands, then lib names and modules from the host.
    const auto re = sh.complete("re");
    CHECK(std::find(re.begin(), re.end(), "reload") != re.end());
    CHECK(std::find(re.begin(), re.end(), "revert_all") != re.end());
    const auto lib = sh.complete("s4cli.");
    CHECK(lib == std::vector<std::string>{"s4cli.level"});

    // Unfinished Lua: Ctrl+C drops it; at the end of input it is an error, never silently skipped.
    CHECK(sh.feed("if true then"));
    CHECK(sh.continuing());
    sh.reset();
    CHECK_FALSE(sh.continuing());
    CHECK(sh.feed("return 'after reset'"));
    CHECK(out.last() == "\"after reset\"");
    CHECK(sh.feed("while false do"));
    const int failed = sh.failures();
    CHECK_FALSE(sh.finish());
    CHECK(sh.failures() == failed + 1);
    CHECK(sh.finish()); // nothing left

    CHECK_FALSE(sh.feed("quit"));
}

TEST_CASE("rhp-cli: watch reloads a saved file", "[cli][shell]") {
    const auto dev = *Rhp::security::ed25519_secret_key::generate();
    const auto psk = *Rhp::security::key::generate();
    const auto at = Rhp::endpoint::listen("cli.watch", 1);
    Rhp::host<cfg> host{at, Rhp::security::keyring{{"dev", psk, Rhp::role::kPatch}}, Rhp::security::trusted_signers{{"dev", dev.public_key()}}};
    REQUIRE(host.install<cli_lib>());
    std::jthread game{[&host](std::stop_token stop) {
        while (!stop.stop_requested()) {
            host.pump();
            std::this_thread::sleep_for(1ms);
        }
    }};
    Rhp::client<cfg> c{at.reversed(), Rhp::security::psk_identity{"dev", psk}, Rhp::security::signing_key{"dev", dev}};
    screen out;
    rhp_cli::shell<cfg> sh{c, out.printer()};
    scratch_dir dir;
    dir.write("live.lua", "s4cli.level = 1 return {}");
    CHECK(sh.feed("watch \"" + dir.path.string() + "\""));
    CHECK(out.has("watching"));
    std::this_thread::sleep_for(300ms);
    dir.write("live.lua", "s4cli.level = 2 return {}");
    fs::last_write_time(dir.path / "live.lua", fs::file_time_type::clock::now() + 2s); // a coarse clock still sees a change
    CHECK(eventually([&] { return out.has("loaded live #"); }));
    CHECK(eventually([&] { return c.exec<int>("return s4cli.level") == 2; })); // through the client: the pump thread owns it
    CHECK(sh.feed("unwatch"));
    CHECK(sh.feed("watch nowhere/at/all"));
    CHECK(out.last().find("is not a folder") != std::string::npos);
}

TEST_CASE("rhp-cli: a watched reload leaves the shell's Ctrl+C alone", "[cli][shell]") {
    const auto dev = *Rhp::security::ed25519_secret_key::generate();
    const auto psk = *Rhp::security::key::generate();
    const auto at = Rhp::endpoint::listen("cli.watch_interrupt", 1);
    Rhp::host<cfg> host{at, Rhp::security::keyring{{"dev", psk, Rhp::role::kPatch}}, Rhp::security::trusted_signers{{"dev", dev.public_key()}}};
    REQUIRE(host.install<cli_lib>());
    std::atomic<bool> hold{false}; // the game stops pumping: a reload waits (and polls) on the watcher's thread
    std::jthread game{[&](std::stop_token stop) {
        while (!stop.stop_requested()) {
            if (!hold.load()) {
                host.pump();
            }
            std::this_thread::sleep_for(1ms);
        }
    }};
    Rhp::client<cfg> c{at.reversed(), Rhp::security::psk_identity{"dev", psk}, Rhp::security::signing_key{"dev", dev}};
    screen out;
    const auto reader = std::this_thread::get_id();
    std::atomic<int> polls_elsewhere{0};
    rhp_cli::shell<cfg> sh{c, out.printer(), [&] {
                               if (std::this_thread::get_id() != reader) {
                                   ++polls_elsewhere;
                               }
                               return false;
                           }};
    scratch_dir dir;
    dir.write("held.lua", "s4cli.level = 1 return {}");
    CHECK(sh.feed("watch \"" + dir.path.string() + "\""));
    std::this_thread::sleep_for(300ms);
    hold = true;
    dir.write("held.lua", "s4cli.level = 3 return {}");
    fs::last_write_time(dir.path / "held.lua", fs::file_time_type::clock::now() + 2s);
    std::this_thread::sleep_for(600ms); // the watcher sees the change and waits for the host
    std::jthread release{[&hold] {
        std::this_thread::sleep_for(400ms);
        hold = false;
    }};
    CHECK(sh.feed("return 'reader still works'")); // ends once the host pumps again
    CHECK(eventually([&] { return out.has("loaded held #"); }));
    CHECK(out.has("\"reader still works\""));
    CHECK(polls_elsewhere.load() == 0);
    sh.unwatch();
}

TEST_CASE("rhp-cli: subscribe prints host events and unsubscribe stops them", "[cli][shell]") {
    const auto dev = *Rhp::security::ed25519_secret_key::generate();
    const auto psk = *Rhp::security::key::generate();
    const auto at = Rhp::endpoint::listen("cli.subscribe", 1);
    Rhp::host<cfg> host{at, Rhp::security::keyring{{"dev", psk, Rhp::role::kPatch}}, Rhp::security::trusted_signers{{"dev", dev.public_key()}}};
    REQUIRE(host.install<cli_lib>());
    std::jthread game{[&host](std::stop_token stop) {
        while (!stop.stop_requested()) {
            host.pump();
            std::this_thread::sleep_for(1ms);
        }
    }};
    screen out;
    Rhp::client<cfg> c{at.reversed(), Rhp::security::psk_identity{"dev", psk}, Rhp::security::signing_key{"dev", dev}};
    rhp_cli::shell<cfg> sh{c, out.printer()};
    CHECK(sh.feed("subscribe game.score"));
    CHECK(out.has("subscribed to game.score"));
    CHECK(sh.feed("exec rhp.publish('game.score', 'red', 3)"));
    CHECK(eventually([&] { return out.has("event game.score [#"); })); // the publishing module (the scratch one here)
    CHECK(out.has("\"red\"	3"));
    CHECK(sh.feed("unsubscribe game.score"));
    CHECK(out.has("unsubscribed from game.score"));
    CHECK(sh.feed("exec rhp.publish('game.score', 'blue', 1)"));
    CHECK(sh.feed("return 1"));
    std::this_thread::sleep_for(50ms);
    CHECK_FALSE(out.has("blue"));
    const int failed = sh.failures();
    CHECK(sh.feed("unsubscribe game.score"));
    CHECK(sh.failures() == failed + 1);
    CHECK(sh.feed("subscribe Bad Name"));
    CHECK(sh.failures() == failed + 2);
}

// ---- the real binaries ---------------------------------------------------------------------------------------

#if defined(RHP_CLI_EXE) && defined(RHP_HEADLESS_EXE)

namespace {

// Runs a command line; its exit code.
int run(const std::string& command) {
#if defined(_WIN32)
    // cmd /c strips the outer quotes of a line that starts with one: add a pair it can strip.
    return std::system(("\"" + command + "\"").c_str());
#else
    const int status = std::system(command.c_str());
    return status == -1 ? -1 : WEXITSTATUS(status);
#endif
}

std::string q(const std::string& s) {
    return "\"" + s + "\"";
}

std::string q(const fs::path& p) {
    return q(p.string());
}

const std::string kCli = q(std::string{RHP_CLI_EXE});
const std::string kHost = q(std::string{RHP_HEADLESS_EXE});

} // namespace

TEST_CASE("rhp-cli: the full lifecycle against a headless_server process", "[cli][process]") {
    scratch_dir dir;
    const auto id = dir.path / "dev.rhpid";
    REQUIRE(run(std::format("{} keygen dev --out {} > {}", kCli, q(id), q(dir.path / "keygen.txt"))) == 0);
    CHECK(run(std::format("{} keygen dev --out {} > {} 2>&1", kCli, q(id), q(dir.path / "again.txt"))) == 1); // never overwrites
    REQUIRE(run(std::format("{} pubkey -i {} --role admin > {}", kCli, q(id), q(dir.path / "lines.txt"))) == 0);
    const std::string lines = dir.read("lines.txt");
    const auto nl = lines.find('\n');
    REQUIRE(nl != std::string::npos);
    dir.write("keys.txt", lines.substr(0, nl + 1));
    dir.write("signers.pub", lines.substr(nl + 1));
    dir.write("patch.lua", "game.gravity = -1.6\nreturn {}\n");
    dir.write("data.bin", "level data");

    std::jthread server{[&] {
        (void)run(std::format("{} --port 0 --keys {} --signers {} --audit {} --blobs {} --port-file {} --stop-file {} --seconds 120 > {} 2>&1", kHost,
                              q(dir.path / "keys.txt"), q(dir.path / "signers.pub"), q(dir.path / "audit.log"), q(dir.path / "blobs"),
                              q(dir.path / "port.txt"), q(dir.path / "stop"), q(dir.path / "server.log")));
    }};
    REQUIRE(eventually([&] { return fs::exists(dir.path / "port.txt") && !dir.read("port.txt").empty(); }));
    const std::string port = std::to_string(std::stoi(dir.read("port.txt")));
    const std::string at = "127.0.0.1:" + port;
    const std::string who = std::format("-c {} -i {}", at, q(id));
    const std::string probe = probe_tcp(static_cast<std::uint16_t>(std::stoi(port)));
    INFO("in-process TCP probe of " << at << ": " << probe);

    const bool first_exec = run(std::format("{} exec \"return game.gravity\" {} > {} 2>&1", kCli, who, q(dir.path / "exec1.txt"))) == 0;
    if (!first_exec) {
        // Diagnostics for a host this process reaches but the CLI process doesn't: is it still listening?
        INFO("in-process TCP probe after the CLI failed: " << probe_tcp(static_cast<std::uint16_t>(std::stoi(port))));
#if !defined(_WIN32)
        (void)run(std::format("lsof -nP -iTCP:{} > {} 2>&1", port, q(dir.path / "lsof.txt")));
#endif
        CHECK(first_exec);
    }
    CHECK(dir.read("exec1.txt").find("-9.81") != std::string::npos);

    // A pinned patch outlives the rhp-cli process that applied it.
    CHECK(run(std::format("{} run {} --pin {} > {}", kCli, q(dir.path / "patch.lua"), who, q(dir.path / "run.txt"))) == 0);
    CHECK(dir.read("run.txt").find("pinned patch") != std::string::npos);
    CHECK(run(std::format("{} exec \"return game.gravity\" {} > {}", kCli, who, q(dir.path / "exec2.txt"))) == 0);
    CHECK(dir.read("exec2.txt").find("-1.6") != std::string::npos);

    // The REPL reading commands from a file: unpin and unload it, gravity is back.
    dir.write("cmds.txt", "list\nunpin patch\nunload patch\nreturn game.gravity\nfor i = 1, 2 do\n  print('line ' .. i)\nend\nquit\n");
    CHECK(run(std::format("{} connect {} -i {} < {} > {}", kCli, at, q(id), q(dir.path / "cmds.txt"), q(dir.path / "repl.txt"))) == 0);
    const std::string repl = dir.read("repl.txt");
    CHECK(repl.find("patch [active]") != std::string::npos);
    CHECK(repl.find("pinned") != std::string::npos);
    CHECK(repl.find("-9.81") != std::string::npos);
    CHECK(repl.find("line 2") != std::string::npos);

    CHECK(run(std::format("{} blob files {} {} > {}", kCli, q(dir.path / "data.bin"), who, q(dir.path / "blob.txt"))) == 0);
    CHECK(dir.read("blobs/data.bin") == "level data");
    CHECK(run(std::format("{} stubs -o {} {} > {}", kCli, q(dir.path / "api.lua"), who, q(dir.path / "stubs.txt"))) == 0);
    CHECK(dir.read("api.lua").find("---@class game") != std::string::npos);

    // An identity without a signing key can't patch.
    const std::string psk_only = dir.read("dev.rhpid").substr(0, dir.read("dev.rhpid").find("signing_key"));
    dir.write("unsigned.rhpid", psk_only);
    CHECK(run(std::format("{} exec \"game.gravity = 0\" -c {} -i {} > {} 2>&1", kCli, at, q(dir.path / "unsigned.rhpid"), q(dir.path / "unsigned.txt"))) == 1);
    CHECK(dir.read("unsigned.txt").find("bad_signature") != std::string::npos);

    dir.write("stop", "");
    server.join();
    const std::string audit = dir.read("audit.log");
    CHECK(audit.find(R"("op":"load","module":"patch")") != std::string::npos);
    CHECK(audit.find(R"("signer":"dev")") != std::string::npos);
    CHECK(audit.find(R"("event":"blob_received")") != std::string::npos);
    CHECK(audit.find(R"("code":"bad_signature")") != std::string::npos);
    CHECK(audit.find(R"("pinned":1)") != std::string::npos);
}

TEST_CASE("rhp-cli: keygen keeps the PSK in the file and makes patch identities", "[cli][process]") {
    scratch_dir dir;
    const auto id = dir.path / "dev.rhpid";
    REQUIRE(run(std::format("{} keygen dev --out {} > {}", kCli, q(id), q(dir.path / "keygen.txt"))) == 0);
    const auto identity = Rhp::security::identity_file::load(id.string());
    REQUIRE(identity);
    CHECK(dir.read("keygen.txt").find(identity->psk.to_base64()) == std::string::npos); // not printed unless asked
    CHECK(dir.read("keygen.txt").find("dev patch <psk from") != std::string::npos);     // patch unless admin is asked for
    REQUIRE(run(std::format("{} pubkey -i {} > {}", kCli, q(id), q(dir.path / "lines.txt"))) == 0);
    CHECK(dir.read("lines.txt").starts_with(identity->keyring_line(Rhp::role::kPatch))); // pubkey is patch too

    const auto shown = dir.path / "shown.rhpid";
    REQUIRE(run(std::format("{} keygen shown --role admin --show-secret --out {} > {} 2> {}", kCli, q(shown), q(dir.path / "shown.txt"), q(dir.path / "shown_err.txt"))) == 0);
    CHECK(dir.read("shown.txt").find(Rhp::security::identity_file::load(shown.string())->keyring_line(Rhp::role::kAdmin)) != std::string::npos);
    CHECK(dir.read("shown_err.txt").find("warning: an admin identity") != std::string::npos);
}

TEST_CASE("rhp-cli: ca init and cert issue make what a certified host takes", "[cli][process][certified]") {
    scratch_dir dir;
    const auto id = dir.path / "alice.rhpid";
    REQUIRE(run(std::format("{} keygen alice --out {} > {}", kCli, q(id), q(dir.path / "keygen.txt"))) == 0);
    REQUIRE(run(std::format("{} ca init ops --env prod --out {} > {}", kCli, q(dir.path / "ops.rhpca"), q(dir.path / "ca.txt"))) == 0);
    const std::string ca_out = dir.read("ca.txt");
    constexpr std::string_view kLine = "trusted CA file:   ";
    const auto at_line = ca_out.find(kLine);
    REQUIRE(at_line != std::string::npos);
    std::string trusted = ca_out.substr(at_line + kLine.size(), ca_out.find('\n', at_line) - at_line - kLine.size());
    if (trusted.ends_with('\r')) {
        trusted.pop_back();
    }
    CHECK(trusted.ends_with("env=prod"));
    dir.write("cas.txt", trusted + "\n");
    const auto cert = dir.path / "alice.rhpcert";
    REQUIRE(run(std::format("{} cert issue --ca {} --principal alice --key {} --hours 1 --max-role patch --app game --serial 5 -o {} > {}", kCli,
                            q(dir.path / "ops.rhpca"), q(id), q(cert), q(dir.path / "issue.txt"))) == 0);
    CHECK(dir.read("issue.txt").find("alice#5") != std::string::npos);
    REQUIRE(run(std::format("{} cert show {} --trusted {} > {}", kCli, q(cert), q(dir.path / "cas.txt"), q(dir.path / "show.txt"))) == 0);
    CHECK(dir.read("show.txt").find("valid now, signed by CA 'ops'") != std::string::npos);
    CHECK(dir.read("show.txt").find("max role     patch") != std::string::npos);

    // A host with signer<certified> that trusts the CA.
    using cert_host_cfg = Rhp::config<>::logger<Rhp::core::null_logger>::signer<Rhp::security::certified>;
    const auto identity = Rhp::security::identity_file::load(id.string());
    REQUIRE(identity);
    auto cas = Rhp::security::trusted_cas::from_file((dir.path / "cas.txt").string());
    REQUIRE(cas);
    Rhp::host<cert_host_cfg> host{Rhp::endpoint::listen("127.0.0.1", 0), Rhp::security::keyring{{"alice", identity->psk, Rhp::role::kPatch}},
                                  Rhp::security::certified::trust{std::move(*cas)}, {.app = "game"}};
    std::string signer;
    std::mutex signer_mutex;
    auto audit = host.on<Rhp::event::script_executed>([&](const Rhp::event::script_executed& e) {
        const std::scoped_lock lock{signer_mutex};
        signer = e.signer;
    });
    std::jthread pump{[&](std::stop_token stop) {
        while (!stop.stop_requested()) {
            host.pump();
            std::this_thread::sleep_for(1ms);
        }
    }};
    const std::string who = std::format("-c 127.0.0.1:{} -i {}", *host.port(), q(id));
    CHECK(run(std::format("{} exec \"return 6 * 7\" {} --cert-file {} --claim-app game > {} 2>&1", kCli, who, q(cert), q(dir.path / "exec.txt"))) == 0);
    CHECK(dir.read("exec.txt").find("42") != std::string::npos);
    CHECK(dir.read("exec.txt").find("signing as alice#5") != std::string::npos);
    {
        const std::scoped_lock lock{signer_mutex};
        CHECK(signer == "alice#5");
    }
    // Claims for another app, and a plain Ed25519 signature, are refused.
    CHECK(run(std::format("{} exec \"return 1\" {} --cert-file {} --claim-app editor > {} 2>&1", kCli, who, q(cert), q(dir.path / "editor.txt"))) == 1);
    CHECK(dir.read("editor.txt").find("out_of_scope") != std::string::npos);
    CHECK(run(std::format("{} exec \"return 1\" {} > {} 2>&1", kCli, who, q(dir.path / "plain.txt"))) == 1);
    CHECK(dir.read("plain.txt").find("bad_signature") != std::string::npos);
    pump.request_stop();
}

TEST_CASE("rhp-cli: keygen splits identity and signing key and tags them", "[cli][process]") {
    scratch_dir dir;
    const auto id = dir.path / "dev.rhpid";
    const auto signing = dir.path / "dev.rhpsign";
    REQUIRE(run(std::format("{} keygen dev --env prod --out {} > {}", kCli, q(id), q(dir.path / "keygen.txt"))) == 0);
    CHECK(fs::exists(signing));
    CHECK(dir.read("dev.rhpid").find("signing_key") == std::string::npos);
    CHECK(dir.read("dev.rhpsign").find("psk") == std::string::npos);
    CHECK_FALSE(Rhp::platform::readable_by_others(signing));
    const auto identity = Rhp::security::identity_file::load(id.string());
    REQUIRE(identity);
    CHECK(identity->env == Rhp::security::key_env::kProd);
    REQUIRE(identity->signers_line());
    CHECK(dir.read("keygen.txt").find(*identity->signers_line()) != std::string::npos);
    CHECK(identity->signers_line()->ends_with(" env=prod"));
    // Neither file is replaced without --force; a bad env is refused.
    fs::remove(id);
    CHECK(run(std::format("{} keygen dev --out {} > {} 2>&1", kCli, q(id), q(dir.path / "again.txt"))) == 1);
    CHECK(dir.read("again.txt").find("dev.rhpsign exists") != std::string::npos);
    CHECK(run(std::format("{} keygen x --env staging --out {} > {} 2>&1", kCli, q(dir.path / "x.rhpid"), q(dir.path / "bad_env.txt"))) == 2);

    // --passphrase seals the signing key; RHP_PASSPHRASE opens it again (no terminal here to ask on).
#if defined(_WIN32)
    const auto with_passphrase = [](std::string_view pw) { return std::format("set \"RHP_PASSPHRASE={}\" && ", pw); };
#else
    const auto with_passphrase = [](std::string_view pw) { return std::format("RHP_PASSPHRASE='{}' ", pw); };
#endif
    const auto sealed = dir.path / "ci.rhpid";
    REQUIRE(run(with_passphrase("open sesame") + std::format("{} keygen ci --passphrase --out {} > {}", kCli, q(sealed), q(dir.path / "sealed.txt"))) == 0);
    CHECK(dir.read("ci.rhpsign").find("signing_key = \"argon2i:") != std::string::npos);
    CHECK(run(with_passphrase("open sesame") + std::format("{} sign {} -i {} > {}", kCli, q(dir.path / "keygen.txt"), q(sealed), q(dir.path / "sig.txt"))) == 0);
    CHECK(dir.read("sig.txt").starts_with("ci "));
    CHECK(run(with_passphrase("wrong") + std::format("{} sign {} -i {} > {} 2>&1", kCli, q(dir.path / "keygen.txt"), q(sealed), q(dir.path / "wrong.txt"))) == 1);
    CHECK(dir.read("wrong.txt").find("auth") != std::string::npos);
    // Without one there is nothing to sign with.
    CHECK(run(std::format("{} sign {} -i {} > {} 2>&1", kCli, q(dir.path / "keygen.txt"), q(sealed), q(dir.path / "none.txt"))) == 1);
    CHECK(dir.read("none.txt").find("sealed with a passphrase") != std::string::npos);
    CHECK(run(std::format("{} keygen ci2 --passphrase --out {} > {} 2>&1 < {}", kCli, q(dir.path / "ci2.rhpid"), q(dir.path / "no_tty.txt"), q(dir.path / "sealed.txt"))) == 1);

    // --device: a device key instead of the PSK, and its allow-list line.
    const auto phone = dir.path / "phone.rhpid";
    REQUIRE(run(std::format("{} keygen phone --device --role observe --out {} > {}", kCli, q(phone), q(dir.path / "device.txt"))) == 0);
    const auto device = Rhp::security::identity_file::load(phone.string());
    REQUIRE(device);
    CHECK(device->psk.empty());
    REQUIRE(device->device_line(Rhp::role::kObserve));
    CHECK(dir.read("device.txt").find("device allow-list: " + *device->device_line(Rhp::role::kObserve)) != std::string::npos);
    CHECK(dir.read("phone.rhpid").find("alg         = \"ed25519\"") != std::string::npos);
}

TEST_CASE("rhp-cli: connect --dev reads a dev session file", "[cli][process]") {
    scratch_dir dir;
    const auto id = dir.path / "dev.rhpid";
    REQUIRE(run(std::format("{} keygen dev --out {} > {}", kCli, q(id), q(dir.path / "keygen.txt"))) == 0);
    auto identity = Rhp::security::identity_file::load(id.string());
    REQUIRE(identity);
    REQUIRE(run(std::format("{} pubkey -i {} > {}", kCli, q(id), q(dir.path / "lines.txt"))) == 0);
    const std::string lines = dir.read("lines.txt");
    const auto nl = lines.find('\n');
    REQUIRE(nl != std::string::npos);
    dir.write("keys.txt", lines.substr(0, nl + 1));
    dir.write("signers.pub", lines.substr(nl + 1));
    std::jthread server{[&] {
        (void)run(std::format("{} --port 0 --keys {} --signers {} --port-file {} --stop-file {} --seconds 120 > {} 2>&1", kHost, q(dir.path / "keys.txt"),
                              q(dir.path / "signers.pub"), q(dir.path / "port.txt"), q(dir.path / "stop"), q(dir.path / "server.log")));
    }};
    REQUIRE(eventually([&] { return fs::exists(dir.path / "port.txt") && !dir.read("port.txt").empty(); }));

    // The program's dev session file, where rhp-cli looks for it with the user config folder moved here.
#if defined(_WIN32)
    const std::string env = std::format("set \"APPDATA={}\" && ", (dir.path / "config").string());
    const fs::path sessions = dir.path / "config" / "rhp" / "dev";
#elif defined(__APPLE__)
    const std::string env = std::format("HOME={} ", q(dir.path));
    const fs::path sessions = dir.path / "Library" / "Application Support" / "rhp" / "dev";
#else
    const std::string env = std::format("XDG_CONFIG_HOME={} ", q(dir.path / "config"));
    const fs::path sessions = dir.path / "config" / "rhp" / "dev";
#endif
    Rhp::security::dev_session session;
    session.app = "game";
    session.transport = "tcp";
    session.host = "127.0.0.1";
    session.port = static_cast<std::uint16_t>(std::stoi(dir.read("port.txt")));
    session.identity = std::move(*identity);
    REQUIRE(Rhp::security::write_dev_session(sessions / "game.rhpdev", session));
    dir.write("cmds.txt", "return 6 * 7\nquit\n");
    const auto connect_dev = [&](std::string_view app, std::string_view out) {
        return run(std::format("{}{} connect --dev {} < {} > {} 2>&1", env, kCli, app, q(dir.path / "cmds.txt"), q(dir.path / out)));
    };
    CHECK(connect_dev("", "dev.txt") == 0);
    CHECK(dir.read("dev.txt").find("dev session of game at tcp://127.0.0.1:") != std::string::npos);
    CHECK(dir.read("dev.txt").find("42") != std::string::npos);

    // With two, name one; one that isn't on this machine is refused.
    session.app = "far";
    session.host = "10.1.2.3";
    REQUIRE(Rhp::security::write_dev_session(sessions / "far.rhpdev", session));
    CHECK(connect_dev("", "several.txt") == 1);
    CHECK(dir.read("several.txt").find("(far, game)") != std::string::npos);
    CHECK(connect_dev("far", "far.txt") == 1);
    CHECK(dir.read("far.txt").find("loopback") != std::string::npos);
    CHECK(connect_dev("game", "game.txt") == 0);
    CHECK(dir.read("game.txt").find("42") != std::string::npos);

    dir.write("stop", "");
    server.join();
}

TEST_CASE("rhp-cli: test runs Lua tests offline and with a host's API faked", "[cli][process]") {
    scratch_dir dir;
    const auto id = dir.path / "dev.rhpid";
    REQUIRE(run(std::format("{} keygen dev --out {} > {}", kCli, q(id), q(dir.path / "keygen.txt"))) == 0);
    REQUIRE(run(std::format("{} pubkey -i {} --role admin > {}", kCli, q(id), q(dir.path / "lines.txt"))) == 0);
    const std::string lines = dir.read("lines.txt");
    const auto nl = lines.find('\n');
    REQUIRE(nl != std::string::npos);
    dir.write("keys.txt", lines.substr(0, nl + 1));
    dir.write("signers.pub", lines.substr(nl + 1));
    dir.write("game_spec.lua", "it('gravity is a number', function()\n"
                               "    assert.is_number(game.gravity)\n"
                               "    game.gravity = 2\n"
                               "    assert.equals(2, game.gravity)\n"
                               "end)\n");

    // Offline with nothing faked: `game` doesn't exist.
    CHECK(run(std::format("{} test {} --no-color > {} 2>&1", kCli, q(dir.path / "game_spec.lua"), q(dir.path / "offline.txt"))) == 1);
    CHECK(dir.read("offline.txt").find("1 error") != std::string::npos);
    CHECK(run(std::format("{} test --bogus > {} 2>&1", kCli, q(dir.path / "bogus.txt"))) == 2);

    std::jthread server{[&] {
        (void)run(std::format("{} --port 0 --keys {} --signers {} --port-file {} --stop-file {} --seconds 120 > {} 2>&1", kHost, q(dir.path / "keys.txt"),
                              q(dir.path / "signers.pub"), q(dir.path / "port.txt"), q(dir.path / "stop"), q(dir.path / "server.log")));
    }};
    REQUIRE(eventually([&] { return fs::exists(dir.path / "port.txt") && !dir.read("port.txt").empty(); }));
    const std::string at = "127.0.0.1:" + std::to_string(std::stoi(dir.read("port.txt")));

    // The host describes its libs; the tests run here against fakes of them.
    CHECK(run(std::format("{} test {} --api-from {} --api-identity {} --no-color -r junit:{} > {} 2>&1", kCli, q(dir.path / "game_spec.lua"), at, q(id),
                          q(dir.path / "junit.xml"), q(dir.path / "faked.txt"))) == 0);
    INFO(dir.read("faked.txt"));
    CHECK(dir.read("faked.txt").find("1 passed") != std::string::npos);
    CHECK(dir.read("junit.xml").find("gravity is a number") != std::string::npos);

    dir.write("stop", "");
    server.join();
}

TEST_CASE("rhp-cli: reverse mode: rhp-cli listens / the server dials in", "[cli][process]") {
    scratch_dir dir;
    const auto id = dir.path / "dev.rhpid";
    REQUIRE(run(std::format("{} keygen dev --out {} > {}", kCli, q(id), q(dir.path / "keygen.txt"))) == 0);
    REQUIRE(run(std::format("{} pubkey -i {} --role patch > {}", kCli, q(id), q(dir.path / "lines.txt"))) == 0);
    const std::string lines = dir.read("lines.txt");
    const auto nl = lines.find('\n');
    dir.write("keys.txt", lines.substr(0, nl + 1));
    dir.write("signers.pub", lines.substr(nl + 1));

    int cli_rc = -1;
    std::jthread cli{[&] {
        cli_rc = run(std::format("{} exec \"return game.tick >= 0, 'reversed'\" -c 127.0.0.1:0 --listen --timeout 60000 -i {} > {} 2>&1", kCli, q(id),
                                 q(dir.path / "cli.txt")));
    }};
    std::string port;
    REQUIRE(eventually([&] {
        const std::string text = dir.read("cli.txt");
        const auto at = text.find("listening on 127.0.0.1:");
        if (at == std::string::npos) {
            return false;
        }
        const auto start = at + std::string_view{"listening on 127.0.0.1:"}.size();
        port = text.substr(start, text.find(';', start) - start);
        return !port.empty();
    }));
    std::jthread server{[&] {
        (void)run(std::format("{} --reverse 127.0.0.1:{} --keys {} --signers {} --stop-file {} --seconds 60 > {} 2>&1", kHost, port, q(dir.path / "keys.txt"),
                              q(dir.path / "signers.pub"), q(dir.path / "stop"), q(dir.path / "server.log")));
    }};
    cli.join();
    dir.write("stop", "");
    server.join();
    CHECK(cli_rc == 0);
    CHECK(dir.read("cli.txt").find("true\t\"reversed\"") != std::string::npos);
}

TEST_CASE("rhp-cli: TLS against a headless_server that requires it", "[cli][process][tls]") {
    scratch_dir dir;
    const auto id = dir.path / "dev.rhpid";
    REQUIRE(run(std::format("{} keygen dev --out {} > {}", kCli, q(id), q(dir.path / "keygen.txt"))) == 0);
    REQUIRE(run(std::format("{} pubkey -i {} --role patch > {}", kCli, q(id), q(dir.path / "lines.txt"))) == 0);
    const std::string lines = dir.read("lines.txt");
    const auto nl = lines.find('\n');
    dir.write("keys.txt", lines.substr(0, nl + 1));
    dir.write("signers.pub", lines.substr(nl + 1));

    std::jthread server{[&] {
        (void)run(std::format("{} --port 0 --tls --keys {} --signers {} --audit {} --port-file {} --stop-file {} --seconds 120 > {} 2>&1", kHost,
                              q(dir.path / "keys.txt"), q(dir.path / "signers.pub"), q(dir.path / "audit.log"), q(dir.path / "port.txt"), q(dir.path / "stop"),
                              q(dir.path / "server.log")));
    }};
    REQUIRE(eventually([&] { return fs::exists(dir.path / "port.txt") && !dir.read("port.txt").empty(); }));
    const std::string at = "127.0.0.1:" + std::to_string(std::stoi(dir.read("port.txt")));

    CHECK(run(std::format("{} exec \"return 6 * 7\" --tls -c {} -i {} > {} 2>&1", kCli, at, q(id), q(dir.path / "tls.txt"))) == 0);
    CHECK(dir.read("tls.txt").find("42") != std::string::npos);
    // Without --tls the CLI speaks plaintext on loopback, and this host refuses it.
    CHECK(run(std::format("{} exec \"return 1\" --timeout 3000 -c {} -i {} > {} 2>&1", kCli, at, q(id), q(dir.path / "plain.txt"))) == 1);

    dir.write("stop", "");
    server.join();
    CHECK(dir.read("server.log").find("TLS") != std::string::npos);
    CHECK(dir.read("audit.log").find(R"("tls":true)") != std::string::npos);
}

TEST_CASE("stage6: the CLI discovers separate hosts and broadcasts a signed script", "[cli][process][stage6][multicast]") {
    rhp_test::needs(Rhp::hardening::kLan, "advertising (headless_server --advertise)");
    std::string listen = "127.0.0.1";
    SECTION("constrained publication") {}
    SECTION("native wildcard publication") {
        listen = "0.0.0.0";
    }
    scratch_dir dir;
    const auto id = dir.path / "fleet.rhpid";
    REQUIRE(run(std::format("{} keygen fleet --out {} > {}", kCli, q(id), q(dir.path / "keygen.txt"))) == 0);
    REQUIRE(run(std::format("{} pubkey -i {} --role patch > {}", kCli, q(id), q(dir.path / "lines.txt"))) == 0);
    const auto lines = dir.read("lines.txt");
    const auto nl = lines.find('\n');
    REQUIRE(nl != std::string::npos);
    dir.write("keys.txt", lines.substr(0, nl + 1));
    dir.write("signers.pub", lines.substr(nl + 1));
    dir.write("broadcast.lua", "return 42\n");
    const auto app = "process-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const auto start = [&](std::string name) {
        return std::jthread{[&, name] {
            (void)run(std::format("{} --host {} --port 0 --tls --keys {} --signers {} --advertise --name {} --app {} --port-file {} --stop-file {} --seconds 90 > {} 2>&1",
                                  kHost, listen, q(dir.path / "keys.txt"), q(dir.path / "signers.pub"), name, app,
                                  q(dir.path / (name + ".port")), q(dir.path / (name + ".stop")), q(dir.path / (name + ".log"))));
        }};
    };
    // Instance names unique per run: another run on the same network must not conflict with these.
    const auto stamp = app.substr(app.find('-') + 1);
    const auto first_name = "stage6-first-" + stamp;
    const auto second_name = "stage6-second-" + stamp;
    auto first = start(first_name);
    auto second = start(second_name);
    const Rhp::utils::scope_guard stop{[&] {
        dir.write(first_name + ".stop", "");
        dir.write(second_name + ".stop", "");
    }};
    REQUIRE(eventually([&] { return !dir.read(first_name + ".port").empty() && !dir.read(second_name + ".port").empty(); }));
    bool found = false;
    for (int attempt = 0; attempt < 10 && !found; ++attempt) {
        // Short waits, tried again (10 s in all): on loopback the answers come at once; a wildcard
        // listener's arrive on the network interfaces, some seconds later.
        REQUIRE(run(std::format("{} discover --app {} --wait 1000 > {} 2>&1", kCli, app, q(dir.path / "discover.txt"))) == 0);
        const auto text = dir.read("discover.txt");
        found = text.find(first_name) != std::string::npos && text.find(second_name) != std::string::npos;
    }
    INFO(dir.read("discover.txt"));
    INFO(dir.read(first_name + ".log"));
    INFO(dir.read(second_name + ".log"));
    REQUIRE(found);
    const auto exit = run(std::format("{} fleet {} -i {} --tls --timeout 10000 --app {} --wait 2000 > {} 2>&1", kCli, q(dir.path / "broadcast.lua"), q(id), app, q(dir.path / "fleet.txt")));
    INFO(dir.read("discover.txt"));
    INFO(dir.read("fleet.txt"));
    INFO(dir.read(first_name + ".log"));
    INFO(dir.read(second_name + ".log"));
    REQUIRE(exit == 0);
    const auto results = dir.read("fleet.txt");
    CHECK(results.find(first_name + ": {42}") != std::string::npos);
    CHECK(results.find(second_name + ": {42}") != std::string::npos);
}

TEST_CASE("rhp-cli: releases are built and applied then kept across a restart and revoked", "[cli][process][releases]") {
    scratch_dir dir;
    const auto id = dir.path / "dev.rhpid";
    REQUIRE(run(std::format("{} keygen dev --out {} > {}", kCli, q(id), q(dir.path / "keygen.txt"))) == 0);
    REQUIRE(run(std::format("{} pubkey -i {} --role admin > {}", kCli, q(id), q(dir.path / "lines.txt"))) == 0);
    const std::string lines = dir.read("lines.txt");
    const auto nl = lines.find('\n');
    REQUIRE(nl != std::string::npos);
    dir.write("keys.txt", lines.substr(0, nl + 1));
    dir.write("signers.pub", lines.substr(nl + 1)); // the same key signs scripts and releases here
    dir.write("tuning.lua", "game.gravity = -3\n");

    REQUIRE(run(std::format("{} release build --channel game.balance --seq 1 --module {} -i {} -o {} > {} 2>&1", kCli, q(dir.path / "tuning.lua"), q(id),
                            q(dir.path / "balance.rhprel"), q(dir.path / "build.txt"))) == 0);
    REQUIRE(run(std::format("{} release inspect {} > {}", kCli, q(dir.path / "balance.rhprel"), q(dir.path / "inspect.txt"))) == 0);
    const std::string inspect = dir.read("inspect.txt");
    CHECK(inspect.find("channel    game.balance") != std::string::npos);
    CHECK(inspect.find("signed by  dev") != std::string::npos);
    REQUIRE(inspect.starts_with("release "));
    const std::string release_id = inspect.substr(8, 64);

    const auto start = [&](std::string_view tag) {
        return std::jthread{[&dir, tag = std::string{tag}] {
            (void)run(std::format("{} --port 0 --keys {} --signers {} --releases {} --release-signers {} --port-file {} --stop-file {} --seconds 120 > {} 2>&1", kHost,
                                  q(dir.path / "keys.txt"), q(dir.path / "signers.pub"), q(dir.path / "releases"), q(dir.path / "signers.pub"),
                                  q(dir.path / (tag + ".port")), q(dir.path / (tag + ".stop")), q(dir.path / (tag + ".log"))));
        }};
    };
    const auto port_of = [&](std::string_view tag) {
        const std::string file = std::string{tag} + ".port";
        REQUIRE(eventually([&] { return fs::exists(dir.path / file) && !dir.read(file).empty(); }));
        return std::format("-c 127.0.0.1:{} -i {}", std::stoi(dir.read(file)), q(id));
    };
    {
        auto server = start("first");
        const std::string who = port_of("first");
        REQUIRE(run(std::format("{} release apply {} {} > {} 2>&1", kCli, q(dir.path / "balance.rhprel"), who, q(dir.path / "apply.txt"))) == 0);
        INFO(dir.read("apply.txt"));
        REQUIRE(run(std::format("{} exec \"return game.gravity\" {} > {}", kCli, who, q(dir.path / "g1.txt"))) == 0);
        CHECK(dir.read("g1.txt").find("-3") != std::string::npos);
        REQUIRE(run(std::format("{} release status {} > {}", kCli, who, q(dir.path / "status.txt"))) == 0);
        CHECK(dir.read("status.txt").find("game.balance") != std::string::npos);
        dir.write("first.stop", "");
    }
    {
        auto server = start("second"); // restores what it ran from --releases
        const std::string who = port_of("second");
        REQUIRE(run(std::format("{} exec \"return game.gravity\" {} > {}", kCli, who, q(dir.path / "g2.txt"))) == 0);
        INFO(dir.read("second.log"));
        CHECK(dir.read("g2.txt").find("-3") != std::string::npos);
        REQUIRE(run(std::format("{} revoke build --seq 1 --release {} -i {} -o {} > {} 2>&1", kCli, release_id, q(id), q(dir.path / "rev.rhprev"),
                                q(dir.path / "revoke.txt"))) == 0);
        REQUIRE(run(std::format("{} revoke apply {} {} > {} 2>&1", kCli, q(dir.path / "rev.rhprev"), who, q(dir.path / "revoked.txt"))) == 0);
        CHECK(dir.read("revoked.txt").find("1 channel(s) changed") != std::string::npos);
        REQUIRE(run(std::format("{} exec \"return game.gravity\" {} > {}", kCli, who, q(dir.path / "g3.txt"))) == 0);
        CHECK(dir.read("g3.txt").find("-9.81") != std::string::npos);
        CHECK(run(std::format("{} release apply {} {} > {} 2>&1", kCli, q(dir.path / "balance.rhprel"), who, q(dir.path / "again.txt"))) == 1);
        CHECK(dir.read("again.txt").find("revoked") != std::string::npos);
        dir.write("second.stop", "");
    }
}

#endif

TEST_CASE("rhp-cli: the shell tunes profiles and debugs", "[cli][shell]") {
    rhp_test::needs(Rhp::hardening::kLan, "the remote debugger");
    g_level = 0;
    const auto dev = *Rhp::security::ed25519_secret_key::generate();
    const auto psk = *Rhp::security::key::generate();
    const auto at = Rhp::endpoint::listen("cli.tools", 1);
    Rhp::host<cfg> host{at, Rhp::security::keyring{{"dev", psk, Rhp::role::kAdmin}}, Rhp::security::trusted_signers{{"dev", dev.public_key()}}};
    REQUIRE(host.install<cli_lib>());
    std::jthread game{[&host](std::stop_token stop) {
        while (!stop.stop_requested()) {
            host.pump();
            std::this_thread::sleep_for(1ms);
        }
    }};
    screen out;
    Rhp::client<cfg> c{at.reversed(), Rhp::security::psk_identity{"dev", psk}, Rhp::security::signing_key{"dev", dev}};
    rhp_cli::shell<cfg> sh{c, out.printer()};

    CHECK(sh.feed("tunables"));
    CHECK(out.has("s4cli.level = 0 (integer)"));
    CHECK(sh.feed("tune s4cli.level 4"));
    CHECK(g_level == 4);
    CHECK(sh.feed("profile start 200"));
    CHECK(sh.feed("local s = 0 for i = 1, 30000 do s = s + i end return s"));
    CHECK(sh.feed("profile stop"));
    CHECK(out.has("samples every 200 instructions"));
    CHECK(sh.failures() == 0);

    scratch_dir dir;
    dir.write("dbg.lua", "function twice(n)\n  local d = n * 2\n  return d\nend");
    CHECK(sh.feed(std::format("load cli.dbg {}", dir.file("dbg.lua"))));
    CHECK(sh.feed("break cli.dbg 3"));
    CHECK(out.has("breakpoints in cli.dbg: 3"));
    CHECK(sh.feed("local r = require('cli.dbg').twice(21) return r")); // not a tail call: Lua keeps the callee's name
    CHECK(eventually([&] { return out.has("paused at cli.dbg:3"); }));
    CHECK(sh.feed("stack"));
    CHECK(out.has("#0 twice (cli.dbg:3)"));
    CHECK(sh.feed("locals"));
    CHECK(out.has("d = 42"));
    CHECK(sh.feed("print n"));
    CHECK(out.has("n = 21 (number)"));
    CHECK(sh.feed("continue"));
    CHECK(eventually([&] {
        (void)sh.feed("paused");
        return out.has("nothing is paused");
    }));
    {
        const std::scoped_lock lock{out.mutex};
        CHECK(std::ranges::any_of(out.lines, [](const auto& l) { return l.second == "42"; })); // the paused exec's own result line
    }
    // A call that pauses goes to the background too.
    CHECK(sh.feed("break cli.dbg 2"));
    CHECK(sh.feed("call cli.dbg twice 5"));
    CHECK(eventually([&] { return out.has("paused at cli.dbg:2"); }));
    CHECK(sh.feed("continue"));
    CHECK(eventually([&] {
        const std::scoped_lock lock{out.mutex};
        return std::ranges::any_of(out.lines, [](const auto& l) { return l.second == "10"; });
    }));
    CHECK(sh.failures() == 0);
}

TEST_CASE("rhp-cli: the DAP server drives the debugger", "[cli][dap]") {
    rhp_test::needs(Rhp::hardening::kLan, "the remote debugger");
    const auto dev = *Rhp::security::ed25519_secret_key::generate();
    const auto psk = *Rhp::security::key::generate();
    const auto at = Rhp::endpoint::listen("cli.dap", 1);
    Rhp::host<cfg> host{at, Rhp::security::keyring{{"dev", psk, Rhp::role::kAdmin}}, Rhp::security::trusted_signers{{"dev", dev.public_key()}}};
    std::jthread game{[&host](std::stop_token stop) {
        while (!stop.stop_requested()) {
            host.pump();
            std::this_thread::sleep_for(1ms);
        }
    }};
    Rhp::client<cfg> c{at.reversed(), Rhp::security::psk_identity{"dev", psk}, Rhp::security::signing_key{"dev", dev}};
    Rhp::client<cfg> runner{at.reversed(), Rhp::security::psk_identity{"dev", psk}, Rhp::security::signing_key{"dev", dev}};
    REQUIRE(runner.load("game.dap", "function f(a)\n  local b = {x = a}\n  return b.x + 1\nend"));
    std::mutex mutex;
    std::vector<Rhp::value> sent;
    const std::string root = (fs::temp_directory_path() / "rhp_dap_src").string();
    rhp_cli::dap_server<cfg> server{c, root, [&](std::string_view bytes) {
                                        const auto body = bytes.substr(bytes.find("\r\n\r\n") + 4);
                                        auto v = rhp_cli::parse_json(body);
                                        REQUIRE(v.has_value());
                                        const std::scoped_lock lock{mutex};
                                        sent.push_back(std::move(*v));
                                    }};
    const auto last_body = [&](std::string_view command) -> Rhp::value {
        const std::scoped_lock lock{mutex};
        for (auto it = sent.rbegin(); it != sent.rend(); ++it) {
            const Rhp::value* cmd = it->find("command");
            if (cmd != nullptr && *cmd == Rhp::value{std::string{command}}) {
                const Rhp::value* ok = it->find("success");
                REQUIRE(ok != nullptr);
                CHECK(*ok == Rhp::value{true});
                const Rhp::value* body = it->find("body");
                return body != nullptr ? *body : Rhp::value{};
            }
        }
        FAIL_CHECK("no response to " << command);
        return Rhp::value{};
    };
    const auto request = [&](std::string_view command, std::string_view args) {
        server.handle(std::format(R"({{"seq": 1, "type": "request", "command": "{}", "arguments": {}}})", command, args));
        return last_body(command);
    };
    CHECK(request("initialize", "{}").find("supportsConfigurationDoneRequest") != nullptr);
    // Nothing paused yet: one placeholder thread, with no frames.
    CHECK(rhp_cli::to_json(request("threads", "{}")) == R"j({"threads":[{"id":0,"name":"(no script paused)"}]})j");
    CHECK(rhp_cli::to_json(request("stackTrace", R"({"threadId": 0})")) == R"({"stackFrames":[],"totalFrames":0})");
    const std::string path = (fs::path{root} / "game" / "dap.lua").generic_string();
    const auto bps = request("setBreakpoints", std::format(R"({{"source": {{"path": "{}"}}, "breakpoints": [{{"line": 3}}]}})", path));
    CHECK(rhp_cli::to_json(bps) == R"({"breakpoints":[{"verified":true,"line":3}]})");
    auto call = runner.async().call("game.dap", "f", 5);
    std::int64_t thread = 0;
    REQUIRE(eventually([&] {
        const auto threads = request("threads", "{}");
        const auto* list = threads.find("threads")->get_if<Rhp::value::array>();
        if (list->empty()) {
            return false;
        }
        thread = *list->front().find("id")->get_if<std::int64_t>();
        return thread != 0;
    }));
    const auto stack = request("stackTrace", std::format(R"({{"threadId": {}}})", thread));
    const auto& frame = stack.find("stackFrames")->get_if<Rhp::value::array>()->front();
    CHECK(*frame.find("name") == Rhp::value{"f"});
    CHECK(*frame.find("line") == Rhp::value{3});
    const auto frame_id = *frame.find("id")->get_if<std::int64_t>();
    const auto scopes = request("scopes", std::format(R"({{"frameId": {}}})", frame_id));
    const auto locals_ref = *scopes.find("scopes")->get_if<Rhp::value::array>()->front().find("variablesReference")->get_if<std::int64_t>();
    const auto locals = request("variables", std::format(R"({{"variablesReference": {}}})", locals_ref));
    std::int64_t b_ref = 0;
    for (const auto& v : *locals.find("variables")->get_if<Rhp::value::array>()) {
        if (*v.find("name") == Rhp::value{"b"}) {
            b_ref = *v.find("variablesReference")->get_if<std::int64_t>();
        }
    }
    REQUIRE(b_ref != 0);
    const auto fields = request("variables", std::format(R"({{"variablesReference": {}}})", b_ref));
    CHECK(rhp_cli::to_json(fields).find(R"("name":"x","value":"5")") != std::string::npos);
    const auto eval = request("evaluate", std::format(R"({{"expression": "b.x", "frameId": {}}})", frame_id));
    CHECK(*eval.find("result") == Rhp::value{"5"});
    (void)request("continue", std::format(R"({{"threadId": {}}})", thread));
    const auto r = std::move(call).get();
    REQUIRE(r.has_value());
    CHECK(*r == Rhp::value_list{Rhp::value{6}});
    (void)request("disconnect", "{}");
    CHECK(server.done());
}

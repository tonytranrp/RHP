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
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "shell.hpp"
#include "text.hpp"
#if !defined(_WIN32)
#include <sys/wait.h>
#endif

#include <catch2/catch_test_macros.hpp>

#include <rhp/client/client.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/host/host.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/net/tcp/tcp.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/psk_keyring.hpp>
#include <rhp/utils/scope_guard.hpp>

using namespace std::chrono_literals;
namespace fs = std::filesystem;

namespace cli_fixtures {

int g_level = 0;

using cli_lib = Rhp::lib<"s4cli">::var<"level", &g_level>;
using cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>;

bool eventually(const std::function<bool()>& done, std::chrono::milliseconds timeout = 20s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!done()) {
        if (std::chrono::steady_clock::now() > deadline) {
            return false;
        }
        std::this_thread::sleep_for(5ms);
    }
    return true;
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
    for (int attempt = 0; attempt < 5 && !found; ++attempt) {
        REQUIRE(run(std::format("{} discover --app {} --wait 2000 > {} 2>&1", kCli, app, q(dir.path / "discover.txt"))) == 0);
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

#endif

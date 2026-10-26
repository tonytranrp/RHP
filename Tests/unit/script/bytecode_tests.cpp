// Compiled chunks: sandbox::compile_module and load / reload with trusted bytecode.
#include <cstdint>
#include <string>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/utils/crc32c.hpp>

using Rhp::errc;
using Rhp::script::sandbox;
using Rhp::script::trusted_bytecode;

namespace {

constexpr std::string_view kSource = "local M = {}\n"
                                     "function M.twice(x)\n"
                                     "    return x * 2\n"
                                     "end\n"
                                     "function M.boom()\n"
                                     "    error('bang')\n"
                                     "end\n"
                                     "return M\n";

std::string compiled(std::string_view name, std::string_view source) {
    sandbox maker;
    auto code = maker.compile_module(name, source);
    REQUIRE(code.has_value());
    return *code;
}

sandbox quiet() {
    Rhp::script::sandbox_options o;
    o.output = [](std::string_view) {};
    return sandbox{std::move(o)};
}

} // namespace

TEST_CASE("bytecode from compile_module loads in another sandbox without parsing", "[script][bytecode]") {
    const std::string code = compiled("bc.twice", kSource);
    CHECK(code.starts_with("\x1bLua"));
    sandbox box = quiet();
    const auto mod = box.load("bc.twice", kSource, trusted_bytecode{code});
    REQUIRE(mod.has_value());
    CHECK(box.stats().bytecode_loaded == 1);
    CHECK(box.stats().bytecode_rejected == 0);
    CHECK(*box.call(*mod, "twice", 21) == Rhp::script::value_list{Rhp::value{42}});
    // The module's source is still the source: its hash, and rollback reloads it.
    const auto info = box.status(*mod);
    REQUIRE(info.has_value());
    CHECK(info->source_hash == Rhp::utils::crc32c(Rhp::utils::bytes_view{reinterpret_cast<const std::byte*>(kSource.data()), kSource.size()}));
    REQUIRE(box.reload(*mod, "return {twice = function(x) return x * 3 end}"));
    CHECK(*box.call(*mod, "twice", 2) == Rhp::script::value_list{Rhp::value{6}});
    REQUIRE(box.rollback(*mod, 1));
    CHECK(*box.call(*mod, "twice", 2) == Rhp::script::value_list{Rhp::value{4}});
}

TEST_CASE("bytecode keeps debug information for errors and coverage", "[script][bytecode]") {
    const std::string code = compiled("bc.lines", kSource);
    sandbox box = quiet();
    REQUIRE(box.start_coverage());
    const auto mod = box.load("bc.lines", kSource, trusted_bytecode{code});
    REQUIRE(mod.has_value());
    const auto failed = box.call(*mod, "boom");
    REQUIRE_FALSE(failed.has_value());
    CHECK(failed.error().message.find("bc.lines:6:") != std::string::npos);
    const auto again = box.load("bc.lines", kSource, trusted_bytecode{code}); // faulted: reloaded
    REQUIRE(again.has_value());
    REQUIRE(box.call(*again, "twice", 1));
    const auto report = box.coverage();
    const auto* chunk = report.find("bc.lines");
    REQUIRE(chunk != nullptr);
    CHECK(chunk->extra.empty()); // every line that ran was known as executable
    CHECK_FALSE(chunk->lines.empty());
}

TEST_CASE("bytecode Lua refuses falls back to parsing the source", "[script][bytecode]") {
    const std::string code = compiled("bc.fallback", kSource);
    const std::string other_name = compiled("bc.other", kSource);
    std::string corrupt_header = code;
    corrupt_header[4] = static_cast<char>(corrupt_header[4] + 1); // the version byte
    const std::string_view truncated = std::string_view{code}.substr(0, code.size() / 2);
    for (const std::string_view bad : {std::string_view{"not bytecode"}, std::string_view{kSource}, std::string_view{other_name},
                                       std::string_view{corrupt_header}, truncated}) {
        sandbox box = quiet();
        const auto mod = box.load("bc.fallback", kSource, trusted_bytecode{bad});
        REQUIRE(mod.has_value());
        CHECK(box.stats().bytecode_loaded == 0);
        CHECK(box.stats().bytecode_rejected == 1);
        CHECK(*box.call(*mod, "twice", 4) == Rhp::script::value_list{Rhp::value{8}});
    }
}

TEST_CASE("reload takes bytecode too", "[script][bytecode]") {
    const std::string next = "return {twice = function(x) return x + x + 1 end}";
    const std::string code = compiled("bc.reload", next);
    sandbox box = quiet();
    const auto mod = box.load("bc.reload", kSource);
    REQUIRE(mod.has_value());
    const auto rev = box.reload(*mod, next, trusted_bytecode{code});
    REQUIRE(rev.has_value());
    CHECK(*rev == Rhp::revision_id{2});
    CHECK(box.stats().bytecode_loaded == 1);
    CHECK(*box.call(*mod, "twice", 4) == Rhp::script::value_list{Rhp::value{9}});
    const auto same = box.load("bc.reload", next, trusted_bytecode{code}); // an existing name reloads
    REQUIRE(same.has_value());
    CHECK(*same == *mod);
    CHECK(box.stats().bytecode_loaded == 2);
}

TEST_CASE("compile_module reports what load would and runs nothing", "[script][bytecode]") {
    sandbox box = quiet();
    CHECK(box.compile_module("Bad Name", "return 1").error().code == errc::kInvalidArgument);
    const auto syntax = box.compile_module("bc.syntax", "local x = = 1");
    REQUIRE_FALSE(syntax.has_value());
    CHECK(syntax.error().code == errc::kCompile);
    REQUIRE(box.compile_module("bc.quiet", "error('never runs')"));
    CHECK(box.list().size() == 1); // the scratch module only
}

TEST_CASE("bytecode_build names this Lua build", "[script][bytecode]") {
    const std::string_view build = Rhp::script::bytecode_build();
    CHECK(build.starts_with("rhp bytecode build: lua "));
    CHECK(build.find("\x1bLua") != std::string_view::npos);      // the probe chunk's dump, header included
    CHECK(Rhp::script::bytecode_build().data() == build.data()); // made once
}

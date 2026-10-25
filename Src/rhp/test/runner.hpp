#pragma once

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/test/options.hpp>
#include <rhp/test/report.hpp>
#include <rhp/test/reporter.hpp>

namespace Rhp::test {

// Installs what the real program installs into a test sandbox: its libs (box.install<game_lib>()),
// usually the same function the program uses for its host. Empty: no libs (the `rhp` API only, or
// fakes from an API description).
using install_fn = std::function<result<void>(script::sandbox&)>;

// Runs Lua test files against the program's API, offline: every test file gets its own sandbox (or
// every test, with isolation::kTest) with the API installed, the modules of `scripts` loaded and the
// test framework (describe / it / assert / expect / spy / stub / test.* / gen.*) in its scratch
// environment. Time is a fake clock the runner moves (test.advance, test.frames); each test runs as
// one request whose effects are undone after it, and what it cost is measured.
//
//   Rhp::test::runner r{options, [](Rhp::script::sandbox& box) { return box.install<game_lib>(); }};
//   auto report = Rhp::test::make_text_reporter(std::cout, true, false);
//   Rhp::test::run_result result = r.run(*report);
//
// One runner, one thread. With RHP_ENABLE=0 every test file reports kDisabled.
class runner {
public:
    explicit runner(run_options options, install_fn install = {});
    ~runner();

    runner(const runner&) = delete;
    runner& operator=(const runner&) = delete;
    runner(runner&&) noexcept;
    runner& operator=(runner&&) noexcept;

    // Runs every selected test.
    run_result run(reporter& out);

    // The selected tests of every file, without running them (a file that doesn't load reports its error).
    std::vector<std::pair<file_result, std::vector<test_info>>> list();

private:
    struct impl;
    std::unique_ptr<impl> impl_;
};

// What a program's libs offer, as sandbox::api describes it (for rhp-cli test --api).
[[nodiscard]] result<value> describe_api(const install_fn& install, role caller = role::kPatch);

} // namespace Rhp::test

#pragma once

#include <concepts>
#include <functional>
#include <iostream>
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/test/runner.hpp>

namespace Rhp::test {

// The whole command line of a test executable (or `rhp-cli test`): parses `args` (without the
// program name), runs or lists the tests, writes the reports and coverage files, and returns the
// exit status: 0 when everything passed, 1 when a test or a file failed, 2 for bad arguments.
int run_cli(std::span<const std::string_view> args, const install_fn& install, std::string_view program = "lua-tests", std::ostream& out = std::cout,
            std::ostream& err = std::cerr);

// main() of a test executable that installs the program's libs:
//
//   int main(int argc, char** argv) {
//       return Rhp::test::main(argc, argv, [](Rhp::script::sandbox& box) { return box.install<game_lib>(); });
//   }
template <class F>
    requires std::invocable<F&, script::sandbox&> && std::convertible_to<std::invoke_result_t<F&, script::sandbox&>, result<void>>
int main(int argc, char** argv, F install) {
    std::vector<std::string_view> args;
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
    return run_cli(args, install_fn{[install = std::move(install)](script::sandbox& box) mutable -> result<void> { return install(box); }},
                   argc > 0 ? std::string_view{argv[0]} : std::string_view{"lua-tests"});
}

} // namespace Rhp::test

#pragma once

// Rhp::test: run Lua test files against a program's API, offline (no game, no host). Start with
// Docs/guide/testing-scripts.md.
//
//   #include <rhp/test/test.hpp>
//   int main(int argc, char** argv) {
//       return Rhp::test::main(argc, argv, [](Rhp::script::sandbox& box) { return box.install<game_lib>(); });
//   }

#include <rhp/test/cli.hpp>
#include <rhp/test/fake.hpp>
#include <rhp/test/fake_registry.hpp>
#include <rhp/test/options.hpp>
#include <rhp/test/report.hpp>
#include <rhp/test/reporter.hpp>
#include <rhp/test/runner.hpp>

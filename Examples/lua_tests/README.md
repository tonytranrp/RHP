# lua_tests

Testing a game's Lua scripts offline with `Rhp::test`: no game running, no host, no network.

- `shop.hpp` is the game's API: the `shop` lib (functions, a `discount` variable with `Rhp::range<0.0, 0.5>`, a `customer` handle with a reversible `pay` method and a `gold` property), a `shop.tax` patch point and a `shop.opened` event. The game and its test executable install the same lib, so scripts run against the real bindings.
- `scripts/shop/rules.lua` is a module the game loads (`require("shop.rules")`).
- `tests/rules_spec.lua` and `tests/sales_spec.lua` test it: `describe` / `it`, `assert` and `expect`, stubs on the lib, the fake clock (`test.advance`), events (`test.fire`), patch points (`test.call_point`), a property test and an instruction budget.
- `lua_tests_main.cpp` is the whole test executable:

  ```cpp
  return Rhp::test::main(argc, argv, [](Rhp::script::sandbox& box) { return box.install<shop::lib>(); });
  ```

- `CMakeLists.txt` builds it as `lua_tests_example` and registers each spec file as a ctest test with `rhp_add_lua_tests` (JUnit reports included):

  ```cmake
  rhp_add_lua_tests(example.lua_tests TARGET lua_tests_example SCRIPTS scripts
                    FILES tests/rules_spec.lua tests/sales_spec.lua JUNIT)
  ```

## Build and run

From the repository root:

```bash
cmake --build --preset windows-msvc --target lua_tests_example
ctest --preset windows-msvc -L lua --output-on-failure
```

The ctest names are `example.lua_tests.rules_spec` and `example.lua_tests.sales_spec`. Run the executable by hand to use any runner option:

```bash
build/windows-msvc/Examples/lua_tests/Debug/lua_tests_example Examples/lua_tests/tests -s Examples/lua_tests/scripts
build/windows-msvc/Examples/lua_tests/Debug/lua_tests_example Examples/lua_tests/tests -s Examples/lua_tests/scripts -v --coverage summary
```

`rhp-cli test --exe <path to lua_tests_example> ...` runs it through the CLI. Everything the runner takes (`--coverage lcov:FILE`, `-r junit:FILE`, `--isolation test`, ...) and the VS Code extension (`clients/vscode`) are in [testing scripts](../../Docs/guide/testing-scripts.md).

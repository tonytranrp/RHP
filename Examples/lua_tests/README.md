# lua_tests

Testing a game's Lua scripts offline, with `Rhp::test`: no game running, no host, no network.

- `shop.hpp` is the game's API (the `shop` lib, a `shop.tax` patch point, a `shop.opened` event). The
  game and its test executable install the same lib, so scripts run against the real bindings.
- `scripts/shop/rules.lua` is a module the game loads (`require("shop.rules")`).
- `tests/*_spec.lua` test it: `describe` / `it`, `assert` and `expect`, stubs on the lib, the fake clock
  (`test.advance`), events (`test.fire`), patch points (`test.call_point`), a property test and an
  instruction budget.
- `lua_tests_main.cpp` is the whole test executable:

  ```cpp
  return Rhp::test::main(argc, argv, [](Rhp::script::sandbox& box) { return box.install<shop::lib>(); });
  ```

- `CMakeLists.txt` registers every spec file as a ctest test with `rhp_add_lua_tests`.

Run it by hand:

```bash
lua_tests_example Examples/lua_tests/tests -s Examples/lua_tests/scripts
```

or through ctest (`ctest -L lua`), or `rhp-cli test --exe lua_tests_example ...`. Everything the
runner takes (`--coverage lcov`, `--reporter junit:out.xml`, `--isolation test`, ...) and the VS Code
extension (`clients/vscode`) are in [the guide](../../Docs/guide/testing-scripts.md).

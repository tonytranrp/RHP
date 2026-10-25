# RHP Lua tests for VS Code

Runs [Rhp::test](../../Docs/guide/testing-scripts.md) Lua test files in VS Code's Test Explorer:

- every `*_spec.lua`, `*.spec.lua`, `*_test.lua` and `test_*.lua` file is listed with its tests (the
  runner's `--list`), refreshed when a file is saved;
- run a file, a `describe` or one test; failures show where they happened, with an expected / actual
  diff for `assert.equals`, `assert.same`, `expect(...).to.equal` and snapshots;
- what a script printed goes with its test, and every passing test notes what it cost (instructions,
  peak memory, allocations);
- the Coverage profile shows the lines of your scripts the tests ran;
- **RHP: Run Lua tests and update snapshots** stores every snapshot as it is now.

## Settings

| Setting | Default | |
|---|---|---|
| `rhpTests.command` | `["rhp-cli", "test"]` | the runner: your program's test executable (`Rhp::test::main`, its real libs) or `rhp-cli test` |
| `rhpTests.args` | `[]` | more arguments, e.g. `["-s", "scripts"]` for module folders, `["--api", "api.json"]` for fakes |
| `rhpTests.include` | `**/{*_spec,*.spec,*_test,test_*}.lua` | test files |
| `rhpTests.exclude` | `**/{node_modules,build,out,.git}/**` | folders never searched |

The runner is started in the workspace folder with `--reporter json` and `--root <folder>`, one
process per test file.

## Development

Plain JavaScript, no build step and no dependencies. `lib/protocol.js` (command lines, the runner's
JSON events) is tested with Node:

```bash
node --test test/protocol.test.js test/extension.test.js test/runner.test.js
```

`test/runner.test.js` runs a real test executable when `RHP_TEST_RUNNER` (its path) and
`RHP_TEST_EXAMPLE` (`Examples/lua_tests`) are set; RHP's ctest does that (`vscode.protocol`).
Package it with `npx @vscode/vsce package`.

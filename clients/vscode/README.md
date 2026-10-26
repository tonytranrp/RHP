# RHP Lua tests for VS Code

Runs [Rhp::test](../../Docs/guide/testing-scripts.md) Lua test files in VS Code's Test Explorer:

- every `*_spec.lua`, `*.spec.lua`, `*_test.lua` and `test_*.lua` file is listed with its tests (the runner's `--list`), refreshed when a file changes;
- run a file, a `describe` or one test; failures show where they happened, with an expected / actual diff for `assert.equals`, `assert.same`, `expect(...).to.equal` and snapshots;
- what a script printed goes with its test, and every passing test notes what it cost (instructions, peak memory, allocations);
- the Coverage profile shows the lines of your scripts the tests ran;
- **RHP: Run Lua tests and update snapshots** (`rhpTests.updateSnapshots`) stores every snapshot as it is now.

It activates in a workspace that contains a test file. It needs a runner on the machine: `rhp-cli` (built with `RHP_BUILD_TOOLS`) or your program's own test executable (`Rhp::test::main`).

## Settings

| Setting | Default | |
|---|---|---|
| `rhpTests.command` | `["rhp-cli", "test"]` | the runner and its leading arguments: your program's test executable (`["build/lua_tests"]`, its real libs) or `rhp-cli test` (the `rhp` API, or fakes with `--api`) |
| `rhpTests.args` | `[]` | more runner arguments, e.g. `["-s", "scripts"]` for module folders, `["--api", "api.json"]` for fakes, `["--isolation", "test"]` |
| `rhpTests.include` | `**/{*_spec,*.spec,*_test,test_*}.lua` | test files, relative to the workspace folder |
| `rhpTests.exclude` | `**/{node_modules,build,out,.git}/**` | folders never searched |

The runner is started in the workspace folder with `--reporter json --no-color --root <folder>`, one process per test file (plus `--coverage summary` for the Coverage profile and `--update-snapshots` for the command).

## Using it from a checkout

Plain JavaScript, no build step and no dependencies (VS Code 1.88 or newer). Start VS Code with the extension loaded:

```bash
code --extensionDevelopmentPath=clients/vscode path/to/your/project
```

## Development

`extension.js` is the VS Code glue; `lib/protocol.js` (command lines, the runner's JSON events, coverage) has no VS Code dependency. Tests run with Node's own runner:

```bash
cd clients/vscode
node --test test/protocol.test.js test/extension.test.js test/runner.test.js
```

`test/extension.test.js` drives `extension.js` against a stand-in `vscode` module. `test/runner.test.js` runs a real test executable when `RHP_TEST_RUNNER` (its path) and `RHP_TEST_EXAMPLE` (`Examples/lua_tests`) are set and is skipped otherwise. RHP's ctest runs them when Node.js is found: `vscode.unit` (protocol and extension) and, with `RHP_BUILD_EXAMPLES`, `vscode.protocol` (against the `lua_tests` example's runner).

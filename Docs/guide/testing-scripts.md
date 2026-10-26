# Testing scripts

`Rhp::test` runs Lua test files against your program's API **offline**: no game running, no host, no network. Each test runs in a real RHP sandbox with your real libs (or fakes of them), so a script under test behaves as it will in the program: the same bindings, roles, undo, scheduler and limits. Time is a fake clock the tests move, and everything a test does is undone after it.

You get:

- a **busted-style DSL** (`describe`, `it`, hooks, `pending`, `.only`, `.skip`, `.each`, tags) with **luassert-compatible `assert`** and **Jest-style `expect`**;
- **spies, stubs and mocks** on lib functions, lib variables, handle methods, module exports and plain tables, all put back after each test;
- **time control**: `test.advance`, `test.frames`, `test.run_all`, events, patch points and deferred results;
- **cost measurement**: every test's exact instruction count, allocations, peak and retained memory; `test.measure`, `test.bench` and budgets;
- **snapshots**, **property-based tests** with shrinking, and **fuzzing** with a saved corpus;
- **leak checks** (timers, subscriptions, tasks, effects, variables left behind), **line coverage** (summary, LCOV, Cobertura) and **profiles**;
- reports for people and CI: text, TAP 14, JUnit XML, JSON events, GitHub annotations;
- a test executable in four lines, `rhp-cli test`, ctest integration (`rhp_add_lua_tests`) and a VS Code extension.

`Examples/lua_tests` is a complete project using all of it.

## A first test

Your program already has a lib (see [Exposing C++ to Lua](exposing-cpp.md)). Say `shop.hpp` declares `shop::lib` with `shop.price(item)`, `shop.visit(gold)` returning a `customer` handle with a `pay` method, and a `discount` variable. A module the game loads:

```lua
-- scripts/shop/rules.lua
local M = {}

function M.total(basket)
    local sum = 0
    for _, item in ipairs(basket) do
        sum = sum + shop.price(item)
    end
    return math.floor(sum * (1 - shop.discount))
end

return M
```

A test file next to it:

```lua
-- tests/rules_spec.lua
local rules = require("shop.rules")

describe("total", function()
    it("adds the prices of a basket", function()
        assert.equals(135, rules.total({ "sword", "potion" }))
    end)

    it("applies the discount", function()
        shop.discount = 0.5 -- undone when the test ends
        expect(rules.total({ "sword" })).to.equal(60)
    end)
end)
```

The test executable installs the same lib the game installs:

```cpp
// lua_tests_main.cpp
#include <rhp/test/test.hpp>
#include "shop.hpp"

int main(int argc, char** argv) {
    return Rhp::test::main(argc, argv, [](Rhp::script::sandbox& box) { return box.install<shop::lib>(); });
}
```

```cmake
add_executable(game_lua_tests lua_tests_main.cpp)
target_link_libraries(game_lua_tests PRIVATE Rhp::test)   # plus your game's library
rhp_add_lua_tests(game TARGET game_lua_tests SCRIPTS scripts FILES tests/rules_spec.lua)
```

Run it directly, or through ctest (`ctest -L lua`):

```bash
game_lua_tests tests -s scripts
```

```text
RHP Lua tests: 1 file(s), seed 2381170092
tests/rules_spec.lua
  2 of 2 passed (3 ms)
2 passed in 9 ms (seed 2381170092)
```

A failure shows where it happened, what was expected and what came instead:

```text
  FAIL total adds the prices of a basket
      Expected objects to be equal.
      Passed in:
      (number) 135
      Expected:
      (number) 136
      at tests/rules_spec.lua:6
```

The exit status is 0 when everything passed, 1 when a test or a file failed, 2 for bad arguments.

## How tests run

- **Modules that don't load** are reported as an error of each test file, but the file's tests still run (a test that needs the module fails on its own).
- **Files.** Arguments are test files, or folders searched for `*_spec.lua`, `*.spec.lua`, `*_test.lua` and `test_*.lua`. `-s / --scripts DIR` names module folders: `DIR/shop/rules.lua` is module `shop.rules`, `DIR/shop/init.lua` is `shop`. Every module of those folders is loaded into each test sandbox (in the order their `require`s need), so tests `require` them like the program does.
- **Sandboxes.** Each test file gets one sandbox with your libs installed, the modules loaded and the framework in its scratch environment: test files see `describe`, `assert`, `spy` and the rest; the modules under test don't. With `--isolation test`, every test gets a fresh sandbox (the modules and the file load again; each module is compiled once per run and later sandboxes load its bytecode).
- **Undo.** Each test runs as one request after a checkpoint, and everything it did is reverted after it: lib effects with an `undo<>`, variable writes, patches, timers, frame callbacks, subscriptions, tasks, swapped functions. Module state that isn't an effect (a module's own table fields) lasts for the file (`--isolation test` resets it). Globals a test creates are removed after it and reported as a note.
- **Setup.** `setup` / `before_all` and `lazy_setup` of the blocks above a test run before its checkpoint: what they do lasts for the file. `teardown` / `after_all` run when the file ends.
- **Stopped tests.** A test stopped by a limit, its timeout or a cancel still gets its cleanup (`finally`, `after_each`, its globals removed) in a request of its own.
- **Leaks.** After the revert, the runner checks that nothing the test started is left: timers and frame callbacks, subscriptions, tasks, waiting requests, ledger effects and changed variables. A leak makes a passing test an error. Effects of bindings marked `Rhp::irreversible` stay and are noted; with `test.expect_undone()` (or `--strict-undo` for every test) they fail the test.
- **Limits.** Each test request runs with `--instructions N` / `--memory BYTES` limits when given, and a wall-time limit of `--timeout` (10 s by default). A test that waits on time or frames forever stops after `--max-frames` (10 000) pump calls; one that waits for an event or a result nothing can deliver (no timers, frame callbacks or tasks left, for a second) stops sooner, with a message saying so.
- **Roles.** Scripts run with `--role patch` by default (what a patching client gets). Use `--role observe` or `admin` to test what those roles may do.
- **Order.** Tests run in file order. `--shuffle` randomizes the order within each file from `--seed` (printed every run, so a failing order can be replayed); the same seed drives property and fuzz inputs.

## The DSL

```lua
describe("inventory", function()            -- context, insulate and expose are aliases
    local log = {}
    setup(function() ... end)               -- before_all: once, before the first test of the block
    teardown(function() ... end)            -- after_all: once, after the file
    before_each(function() ... end)         -- outer blocks first
    after_each(function() ... end)          -- inner blocks first

    it("stacks potions", function()
        finally(function() ... end)         -- when this test ends, pass or fail (last first)
        ...
    end)

    it("is not written yet")                -- no body: pending
    pending("trades with NPCs")             -- pending
    it("sells", function() pending("blocked on the trade lib") end)

    it.skip("is broken on Android", function() ... end)
    it.only("runs alone", function() ... end)      -- the file's other tests are skipped
    describe.skip("a whole block", function() ... end)

    it.each({ { 1, 2, 3 }, { 2, 3, 5 } })("adds %d and %d to make %d", function(a, b, sum)
        assert.equals(sum, a + b)
    end)
    it.each({ { name = "orc", hp = 5 } })("$name has hp", function(case) ... end)
    describe.each({ { 10 }, { 20 } })("level %d", function(level) ... end)

    it("loads a level #slow #io", function() ... end)   -- tags: --tags slow, --exclude-tags io
end)
```

Name templates: `%s` (text), `%d` / `%i` (integer), `%f` (number), `%j` / `%o` (value), `%#` (case number), `$key` (a field of a record case). A list case is spread into arguments; a record case is passed whole. `test(name, fn)` is `it`.

A file whose `describe` body raises reports a file error and keeps the tests declared before it; a file that doesn't compile reports its error and line.

## Assertions

`assert` follows [luassert](https://github.com/lunarmodules/luassert): words chain, `is_` / `are_` / `has_` / `was_` are fillers, `not` / `no` negate, and a last string argument is the message.

| Assertion | |
|---|---|
| `assert.equals(expected, actual)` / `equal` | `==` |
| `assert.same(expected, actual)` | deep equality (tables compared by content, cycles allowed); the first difference is named: `First difference at b.c: 3 instead of 2` |
| `assert.near(expected, actual, tolerance)` | numbers within a tolerance |
| `assert.matches(pattern, s [, init, plain])` | a Lua pattern |
| `assert.truthy(v)` / `falsy` / `is_true` / `is_false` / `is_nil` | |
| `assert.is_number(v)` (`string`, `table`, `function`, `boolean`, `userdata`, `thread`, `nil`) | types |
| `assert.unique(list [, deep])` | no repeated values |
| `assert.has_error(fn [, expected])` / `error` / `errors` | `fn` raises (an error equal to `expected`, its `file:line:` prefix ignored, or a table compared deeply) |
| `assert.error_matches(fn, pattern)` | the error matches a pattern |
| `assert.is_not.equal(...)`, `assert.has_no.errors(fn)`, `assert.not_same(...)` | negations |
| `assert.snapshot(value [, name])` | [snapshots](#snapshots) |
| `assert:register("assertion", "even", fn, positive, negative)` | your own (`assert.is_even(4)`) |

Matchers stand in for values in `same`, in spy assertions and in `on_call_with`: `match._` (anything), `match.is_number()` (and every type), `match.is_truthy()`, `match.is_falsy()`, `match.equals(v)`, `match.same(v)`, `match.near(v, tol)`, `match.matches(pattern)`, `match.ref(t)`, `match.unique()`, `match.contains(v)`, `match.table_containing(t)`, `match.all_of(...)`, `match.any_of(...)`, `match.none_of(...)`, and `match.is_not.x(...)`.

```lua
assert.same({ id = match._, name = match.is_string() }, unit)
assert.same(match.table_containing({ hp = 10 }), unit)
```

`expect` is the [Jest](https://jestjs.io/docs/expect) style over the same checks. Filler words (`to`, `be`, `been`, `have`, `has`, `a`, `an`, `is`, `that`, `and`, `does`) read as English; `to_not`, `not_to` and `never` negate.

| `expect(x)...` | |
|---|---|
| `.to.equal(y)` (`eq`, `same`) | deep equality, with the first difference |
| `.to.be(y)` | `==` |
| `.to.be_nil()`, `.to.exist()`, `.to.be_true()`, `.to.be_false()`, `.to.be.truthy()`, `.to.be.falsy()` | |
| `.to.be.a("number")` (`"integer"`, `"float"`, a metatable) | |
| `.to.be_greater_than(n)` (`above`), `be_less_than` (`below`), `be_at_least`, `be_at_most`, `.to.be.near(n, tol)` | |
| `.to.match(pattern)`, `.to.contain(v)`, `.to.have.length(n)`, `.to.have.key(k)`, `.to.satisfy(fn or matcher)` | |
| `expect(fn).to.fail([text or pattern])` (`throw`, `raise`, `error`) | |
| `expect(spy).to.have_been_called([n])`, `.to.have_been_called_with(...)` | |
| `.to.match_snapshot([name])` | |

Every assertion counts toward the test's `assertions` in the reports.

## Spies, stubs and mocks

```lua
local s = spy.on(shop, "price")              -- records calls, calls through
stub(shop, "price").returns(1)               -- replaces it
stub(shop, "price").invokes(function(item) return #item end)
local st = stub(shop, "price")
st.on_call_with("sword").returns(999)        -- argument rules, newest first; matchers allowed
st.returns(1)                                -- everything else
stub.var(shop, "discount", 0.25)             -- a lib variable read from the stub; writes kept there
mock(game.ui)                                -- every function spied, recursively (mock(t, true): stubbed)
local f = spy.new(function(x) return x * 2 end)

assert.spy(s).was.called(2)
assert.spy(s).was.called_with("sword")
assert.spy(s).was_not.called_with(match.is_number())
assert.spy(s).was.returned_with(120)
assert.stub(shop.price).was.called()
expect(shop.price).to.have_been_called_with("potion")
s:revert()                                   -- earlier than the end of the test
```

What can be replaced: **lib functions** (`shop.price`), **lib variables** (`stub.var`), **handle methods** (`spy.on(customer, "pay")` replaces the method for every handle of that type), **module exports** (`spy.on(rules, "total")`: other modules calling `rules.total` see the spy) and **plain tables**. Every replacement is journaled by the sandbox and put back when the test ends, whatever happened.

## Time, frames, events and patch points

The clock is fake: a test moves it, and nothing waits in real time.

```lua
it("discount every hour for ten minutes", function()
    rules.happy_hours(60 * 60 * 1000, 10 * 60 * 1000, 0.25)
    test.advance(60 * 60 * 1000)        -- due timers fire in order on the way
    assert.equals(0.25, shop.discount)
    test.advance(10 * 60 * 1000)
    assert.equals(0, shop.discount)
end)
```

| | |
|---|---|
| `test.advance(ms)` | moves the clock; every timer and sleeper due on the way runs at its own time |
| `test.frames(n [, {dt = ms}])` | `n` `pump()` calls (frame callbacks, `rhp.wait`, tasks), the clock moving `dt` before each |
| `test.run_pending()` | runs what is due now (not what that schedules) |
| `test.run_all({limit = 1000})` | advances to each next due time until nothing waits for time; fails after `limit` steps (an endless timer loop) |
| `test.now()`, `test.next_due()` | the script clock, the next due time (nil: nothing waits) |
| `rhp.sleep(ms)`, `rhp.wait(n)` in a test | the runner moves the clock or pumps for the test |
| `os.time()`, `os.clock()` | follow the fake clock (a test file starts at `--epoch`, 1 700 000 000 by default) |
| `test.publish(name, ...)` | `rhp.publish`, then two frames: handlers ran and their failures are reported |
| `test.fire("shop.opened", 3)` | fires a C++ `Rhp::lua_event` by name, as the game would (an event registers itself where the program fires it; when the test executable doesn't contain that code, the `rhp.on` handlers get it as a script event at the next frame) |
| `test.call_point("shop.tax", 120)` | calls a patch point as C++ would, overrides included (points whose parameters and result convert to values) |
| `test.output()`, `test.emitted()`, `test.failures()` | what scripts printed, `rhp.emit`ted, and the handler failures so far in this test |
| `test.deferred()` | a result to resolve later: `d:resolve(v)`, `d:reject(e)`, `d:await()` (from a stub standing in for an asynchronous binding) |

An event a test publishes just before it ends still reaches its handlers within that test.

## Measuring

Every test's cost is measured exactly from the request that ran it: instructions (Lua VM instructions, counted exactly, not sampled), the time Lua ran, allocations and bytes allocated, peak memory above where the test started, memory retained after a full collection, objects made by kind, and frames. `-v` prints it for every test; the text report always lists the tests with the most instructions and memory.

```lua
local m = test.measure(function() return rules.total(basket) end, { name = "total of 200" })
-- m.instructions, m.allocations, m.bytes, m.peak, m.retained, m.time_ms, m.objects.table, m.results
local b = test.bench("total", function() rules.total(basket) end, { runs = 30, warmup = 3 })
-- b.instructions.median, b.time_ms.mean, b.time_ms.stddev, b.bytes.max, ...
test.budget({ instructions = 50000, memory = 64 * 1024 })      -- for the whole test, checked when it ends
test.expect_budget(function() rules.total(basket) end, { instructions = 5000, bytes = 1024 })
it("stays cheap", function() ... end, { budget = { instructions = 10000 } })
```

`test.measure` collects garbage around the call (`{gc = false}` skips that). Instruction counts don't change between runs or machines; times do. A measure's `retained` includes what the function returns. The first call of something can grow Lua's internal tables (the string table, say): warm up before measuring what has to be exact. Measures and benches appear in every report. `--no-measure` skips the collections around each test (faster, no retained memory).

## Snapshots

```lua
assert.snapshot(rules.receipt(basket))
expect(rules.receipt(basket)).to.match_snapshot("receipt")
```

The first run stores the value in `__snapshots__/<file>.snap.lua` next to the test file, serialized as readable Lua (keys sorted, one entry per line); later runs compare. Review that file like code. `-u / --update-snapshots` stores every value as it is now and drops snapshots no test checked (otherwise reported as obsolete). `--ci` refuses to store new snapshots: a missing one fails. An unreadable snapshot file fails its tests and is never rewritten.

## Property-based tests

```lua
test.property({ gen.int(0, 1000), gen.int(0, 1000) }, function(base, armor)
    assert.is_true(combat.damage(base, armor) >= 0)
end)

it.property("sorting keeps every element", { gen.list(gen.int()) }, function(list)
    return #sorted(list) == #list
end, { runs = 200 })
```

The function runs with generated arguments (`--property-runs`, 100 by default); a raise or a `false` return is a failure. The failing case is **shrunk** (smaller numbers, shorter lists and strings) and reported with the original, the seed and the error:

```text
Property failed after 8 run(s) (seed 6080735783159274859, shrunk in 20 step(s)).
Counterexample: (50)
Original: (74)
```

Generators: `gen.int(lo, hi)`, `gen.number(lo, hi)`, `gen.bool()`, `gen.constant(v)`, `gen.element(list)`, `gen.one_of(g...)`, `gen.frequency({weight, g}...)`, `gen.optional(g)`, `gen.string({min, max, chars})`, `gen.list(g, {min, max})`, `gen.tuple(g...)`, `gen.record({field = g})`, `gen.table(key_g, value_g, {max})`, `gen.any()`, and `g:map(fn)` / `gen.map(g, fn)`, `g:filter(pred)` / `gen.filter(g, pred)`.

## Fuzzing

```lua
it("never crashes on any input", function()
    test.fuzz(function(text) parser.parse(text) end, { gen = gen.string({ max = 200 }), runs = 2000 })
end)
```

`test.fuzz` calls the function with generated inputs; an error is a failure (a `false` return isn't). A crash is shrunk and saved in `__fuzz__/<file>/<test>/`, and saved inputs run first on every later run, whatever the seed: a crash found once stays a regression test. With `--coverage`, inputs that reach new lines are kept and mutated further (`save_coverage = true` keeps them on disk too). `--fuzz MS` makes every `test.fuzz` run for that much Lua time instead of a number of inputs.

## Fakes

Without the real program, a test can run against **fakes** with the same names and types.

- **From C++:** install `Rhp::test::fake<shop::lib>` instead of `shop::lib`. Every function records its calls and returns its type's default; `undo<>` tags record their reverts; variables get storage of their own; handles are always alive. The scripts can't tell.
- **From an API description:** `sandbox::api()` (Lua: `rhp.api()`) describes the installed libs. `--dump-api api.json` writes it from a test executable; `rhp-cli test --api api.json` fakes those libs; `rhp-cli test --api-from host:port --api-identity id.rhpid` fetches it from a running host (`--api-tls`, `--api-ca`, `--api-server-name`, `--api-insecure-lan` as for other commands).

Either way, from Lua:

```lua
assert.same({ { "sword" } }, fake.calls("shop.price"))   -- methods: "customer:pay"
fake.returns("shop.price", 120)
fake.reset("shop.price")
local c = fake.handle("customer", { gold = 50 })         -- description fakes: a handle with properties
```

Calls, and results configured from Lua, are forgotten after each test (results a test executable configured from C++ through `fake_registry` before the run stay); variables of description fakes go back to their values. `--strict-fakes` makes a call nothing configured raise `not mocked: shop.price("sword")`. Arguments are type-checked against the description. A fake of a function whose result has no default (and doesn't convert from a value) doesn't compile; one that converts from a value but has no default needs `fake.returns`.

## Coverage and profiles

```bash
game_lua_tests tests -s scripts --coverage summary --coverage lcov:out/lcov.info --coverage cobertura:out/coverage.xml
```

Coverage counts the lines of the module scripts that ran (`--coverage-tests` adds the test files). Executable lines come from the compiled code, so totals are exact: lines that never ran show 0, comments and blank lines aren't counted. Exclude lines with `-- rhp: coverage off` / `-- rhp: coverage on` (or luacov's `-- luacov: disable` / `enable`). LCOV feeds Codecov, Coveralls and editors; Cobertura feeds GitLab and Azure DevOps.

`--profile[=N]` samples every N instructions (1000 by default) in each test; `--profile-out file.folded` writes every test's samples as folded stacks for `flamegraph.pl` or speedscope.

## Reports

`-r / --reporter KIND[:FILE]`, repeatable: `text` (default), `tap` (TAP 14), `junit` (JUnit XML: GitHub, GitLab, Jenkins), `json` (one event per line: `run_start`, `file_start`, `test_start`, `test_end`, `file_end`, `run_end`) and `github` (`::error file=...,line=...` annotations). Standard output keeps the text report unless a reporter without a file takes it. Failures carry expected / actual values for diff views.

```bash
game_lua_tests tests -s scripts -r junit:out/lua-tests.xml -r github --coverage lcov:out/lcov.info
```

`--list` lists the selected tests without running them (`--list -r json` for tools). Selection: `-f / --filter TEXT` (repeatable, `/regex/` for a regex) on full names, `--filter-out TEXT`, `-t / --tags a,b`, `--exclude-tags a,b`, `--fail-fast`, `--repeat N`. `--root DIR` makes paths in reports relative to `DIR`. `--help` lists everything.

## From C++

`Rhp::test::main` parses the command line. To drive a run from your own code (a game's in-editor test button, a custom CI step), build `Rhp::test::run_options` and use `Rhp::test::runner`:

```cpp
#include <iostream>
#include <rhp/test/test.hpp>

int run_shop_tests() {
    Rhp::test::run_options options;
    options.tests = {"tests"};
    options.scripts = {"scripts"};
    options.coverage = {{Rhp::test::coverage_kind::kLcov, "out/lcov.info"}}; // collect line coverage
    Rhp::test::runner r{options, [](Rhp::script::sandbox& box) { return box.install<shop::lib>(); }};
    auto text = Rhp::test::make_text_reporter(std::cout, false, false);
    const Rhp::test::run_result result = r.run(*text);
    std::ofstream{"out/lcov.info"} << Rhp::test::lcov_text(result.coverage); // the runner doesn't write files
    return result.totals.ok() ? 0 : 1; // also result.files, result.seed, result.profile
}
```

This needs `<fstream>` too. `runner::list()` returns the selected tests without running them; `lcov_text` / `cobertura_text` / `folded_text` turn the results into files. `Rhp::test::run_cli(args, install)` is `main` without `argc` / `argv`. Reporters: `make_text_reporter`, `make_tap_reporter`, `make_junit_reporter`, `make_json_reporter`, `make_github_reporter`.

## rhp-cli test

`rhp-cli test` takes the same arguments:

- With no libs, scripts get the `rhp` API only: fine for pure logic.
- `--api api.json` or `--api-from host:port --api-identity id.rhpid` fakes the libs of a description.
- `--exe build/game_lua_tests` runs your program's own test executable with the other arguments, so one command line works for every project.

## In CMake and CI

`rhp_add_lua_tests(<name> TARGET <exe> FILES <specs...> [SCRIPTS <dirs...>] [ROOT <dir>] [ARGS <args...>] [LABELS <labels...>] [JUNIT] [TIMEOUT <s>] [STORE_SNAPSHOTS])` makes each file a ctest test named `<name>.<file stem>` (with its folder too when two files share a stem), labelled `lua`. It runs with `--ci`, so ctest never writes new snapshots into the source tree (`STORE_SNAPSHOTS` allows it); store them by running the test executable once. It comes with `find_package(rhp)` and with RHP as a subdirectory. `TARGET rhp-cli` runs files with `rhp-cli test`. `JUNIT` writes `<build>/<name>/<stem>.junit.xml` for CI test reports.

A GitHub Actions step:

```yaml
- run: build/game_lua_tests tests -s scripts --ci -r github -r junit:lua-tests.xml --coverage lcov:lcov.info
```

`--ci` keeps a forgotten snapshot from being stored silently in CI; `-r github` puts failures on the pull request's lines.

## In VS Code

`clients/vscode` is an extension for the Test Explorer: it lists the tests of every spec file (refreshed on save), runs a file, a block or one test, shows failures in place with a diff, the output of each test and its cost, and line coverage (the Coverage run profile). Set `rhpTests.command` to your test executable (`["build/game_lua_tests"]`) or keep `["rhp-cli", "test"]`, and `rhpTests.args` to `["-s", "scripts"]`. See its [README](../../clients/vscode/README.md).

## With RHP_ENABLE=OFF

There is no Lua: test files report that they can't run (exit status 1), while `--dump-api`, the options and `fake<L>` still work.

## Limits

- Tests run on one thread; the runner pumps the sandbox itself. Code that needs other threads (a network round trip) belongs in C++ tests.
- Patch points are process-wide: a test executable shares them between files. Each test's patches are undone, but C++ code running in the background of your test executable would see them.
- `test.call_point` only calls points whose parameters and result convert to values.
- Instruction counts are exact for Lua; time spent in C++ bindings shows in `time_ms` only.
- Fuzzing is generation plus coverage-guided mutation in Lua, not libFuzzer: it finds logic errors in scripts, not memory errors in C++ (for those, `Tests/fuzz`).

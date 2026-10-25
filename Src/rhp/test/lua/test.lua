-- Rhp::test, the Lua side, part 5: `test`, the helpers a test body uses.
--   test.advance(250)            -- the script clock moves 250 ms; due timers fire in order on the way
--   test.frames(3)               -- three pump() calls (frame callbacks, rhp.wait, tasks run)
--   test.run_pending() / test.run_all{limit = 1000}
--   local m = test.measure(function() combat.tick() end)   -- m.instructions, m.bytes, m.peak, ...
--   test.bench("tick", function() combat.tick() end)
--   test.budget{instructions = 50000, memory = 64 * 1024}
--   test.fire("game.round_over", "red")     test.call_point("combat.damage", 10, 2)
--   local d = test.deferred() ... d:resolve(value)            -- an asynchronous result to wait for
-- test(name, fn) is it(name, fn).

local T = __rhp_t
local bridge = T.bridge
local type, select, pairs, ipairs, error, tostring, tonumber, setmetatable, pcall =
    type, select, pairs, ipairs, error, tostring, tonumber, setmetatable, pcall
local concat, sort, unpack = table.concat, table.sort, table.unpack
local format = string.format
local floor, sqrt, huge = math.floor, math.sqrt, math.huge
local pack = T.pack

local function running(what)
    if not T.running then
        error(format("test.%s() only works inside a running test", what), 3)
    end
    return T.running
end

local function number_arg(v, what, min)
    if type(v) ~= "number" or v ~= v or (min ~= nil and v < min) then
        error(format("test.%s expects a number%s, got %s", what, min and (" >= " .. min) or "", tostring(v)), 3)
    end
    return v
end

test = setmetatable({}, { __call = function(_, name, fn, opts) return it(name, fn, opts) end })
test.only = it.only
test.skip = it.skip
test.each = it.each

-- ---- the clock ------------------------------------------------------------------------------------------

-- Moves the script clock `ms` forward: every timer and sleeper due on the way runs at its own time.
function test.advance(ms)
    running("advance")
    ms = number_arg(ms, "advance", 0)
    bridge.host("advance", ms)
    rhp.sleep(ms)
end

-- `n` pump() calls (at least 1), the clock moving `opts.dt` ms before each (default 0).
function test.frames(n, opts)
    running("frames")
    n = number_arg(n or 1, "frames", 1) // 1
    local dt = opts and opts.dt or 0
    number_arg(dt, "frames dt", 0)
    bridge.host("frames", n, dt)
    rhp.wait(n)
end

-- Runs what is due now: the timers and sleepers already scheduled (not the ones they schedule).
function test.run_pending()
    running("run_pending")
    local due = bridge.due()
    if #due == 0 then
        return 0
    end
    test.advance(due[#due])
    return #due
end

-- Advances to each next due time until nothing waits for time; fails after `limit` steps (1000) as
-- probably an endless loop of timers.
function test.run_all(opts)
    running("run_all")
    local limit = opts and opts.limit or 1000
    local steps = 0
    while true do
        local next_ms = bridge.next_due()
        if next_ms == nil then
            break
        end
        steps = steps + 1
        if steps > limit then
            T.fail(format("test.run_all: still running after %d steps; probably an endless loop of timers (raise opts.limit if not)", limit))
        end
        test.advance(next_ms)
    end
    test.frames(1) -- what the last ones woke up
    return steps
end

function test.now()
    return bridge.now()
end

function test.next_due()
    return bridge.next_due()
end

-- ---- driving the program -------------------------------------------------------------------------------

function test.fire(name, ...)
    bridge.fire(name, ...)
end

function test.call_point(id, ...)
    return bridge.call_point(id, ...)
end

-- rhp.publish, then two frames: the handlers run in the first, and what they did (failures, the
-- events they published) is settled when it ends.
function test.publish(name, ...)
    running("publish")
    rhp.publish(name, ...)
    test.frames(2)
end

-- What scripts printed / emitted (rhp.emit) / which handlers failed in this test so far.
function test.output()
    return bridge.host("output")
end

function test.emitted()
    return bridge.host("emitted")
end

function test.failures()
    return bridge.host("failures")
end

-- After this test, its revert must undo everything: irreversible effects fail it too.
function test.expect_undone()
    running("expect_undone").strict_undo = true
end

-- ---- an asynchronous result -----------------------------------------------------------------------------

local deferred_mt = {}
deferred_mt.__index = deferred_mt

function test.deferred()
    return setmetatable({ settled = false }, deferred_mt)
end

function deferred_mt:resolve(...)
    if self.settled then
        error("this deferred is already settled", 2)
    end
    self.settled, self.ok, self.values = true, true, pack(...)
end

function deferred_mt:reject(err)
    if self.settled then
        error("this deferred is already settled", 2)
    end
    self.settled, self.ok, self.err = true, false, err
end

-- Waits (one frame at a time) until settled; returns the values or raises the error. Called from a
-- script's own request (a stub standing in for an asynchronous binding), it suspends that script.
function deferred_mt:await()
    while not self.settled do
        rhp.wait(1)
    end
    if not self.ok then
        error(self.err, 2)
    end
    return unpack(self.values, 1, self.values.n)
end

-- ---- measuring -----------------------------------------------------------------------------------------

-- Reading tables are reused (one set per nesting level of test.measure) so that measuring allocates
-- nothing between its readings: the figures are the function's own.
local readings = {}
local function new_reading()
    return { objects = {} }
end
T.measure_depth = 0

-- fn's results into a reused table (no allocation for up to its existing slots).
local function capture(t, ...)
    local n = select("#", ...)
    t.n = n
    for i = 1, n do
        t[i] = (select(i, ...))
    end
end

-- What fn(...) cost: instructions, bytes and allocations it asked for, peak bytes above where it
-- started, bytes still held after a full collection (retained), objects made by kind, and its time.
-- opts.gc = false skips the collections around it; opts.name names it in the report.
function test.measure(fn, opts)
    if type(fn) ~= "function" then
        error("test.measure expects a function", 2)
    end
    opts = opts or {}
    local gc = opts.gc ~= false
    local depth = T.measure_depth + 1
    T.measure_depth = depth
    local set = readings[depth]
    if not set then
        set = { before = new_reading(), base = new_reading(), after = new_reading(), settled = new_reading(),
                results = table.create and table.create(8, 1) or {} }
        capture(set.results, nil, nil, nil, nil, nil, nil, nil, nil) -- the slots exist from now on
        bridge.meter(set.before) -- every field made once now, outside any measure
        bridge.meter(set.base)
        bridge.meter(set.after)
        bridge.meter(set.settled)
        readings[depth] = set
    end
    local before, base, after, settled = set.before, set.base, set.after, set.settled
    if gc then
        bridge.gc()
    end
    bridge.meter(before)
    bridge.reset_peak()
    bridge.meter(base)
    local kept = set.results
    capture(kept, fn())
    bridge.meter(after)
    if gc then
        bridge.gc()
    end
    bridge.meter(settled)
    T.measure_depth = depth - 1
    local results = { n = kept.n }
    for i = 1, kept.n do
        results[i], kept[i] = kept[i], nil
    end
    local objects = {}
    for kind, n in pairs(after.objects) do
        objects[kind] = n - before.objects[kind]
    end
    local m = {
        instructions = after.instructions - base.instructions,
        allocations = after.allocations - base.allocations,
        bytes = after.bytes - base.bytes,
        peak = after.peak - base.memory,
        retained = settled.memory - before.memory,
        time_ms = after.active_ms - base.active_ms,
        objects = objects,
        metering = after.metering,
        results = results,
        name = opts.name,
    }
    if T.running then
        local list = T.running.measures
        list[#list + 1] = {
            name = opts.name or ("measure " .. (#list + 1)),
            instructions = m.instructions,
            allocations = m.allocations,
            bytes = m.bytes,
            peak = m.peak,
            retained = m.retained,
            time_ms = m.time_ms,
        }
    end
    return m
end

local function stats(values)
    local n = #values
    local sorted = { unpack(values) }
    sort(sorted)
    local sum = 0
    for i = 1, n do
        sum = sum + sorted[i]
    end
    local mean = sum / n
    local var = 0
    for i = 1, n do
        var = var + (sorted[i] - mean) ^ 2
    end
    local median = n % 2 == 1 and sorted[(n + 1) // 2] or (sorted[n // 2] + sorted[n // 2 + 1]) / 2
    return { min = sorted[1], max = sorted[n], mean = mean, median = median, stddev = n > 1 and sqrt(var / (n - 1)) or 0 }
end

-- Runs fn opts.runs times (default 30, after opts.warmup = 3 unmeasured runs) and reports the median,
-- mean, spread and extremes of its instructions, time and bytes. Instructions don't vary between
-- runs; time does (it is wall time on this machine).
function test.bench(name, fn, opts)
    if type(name) == "function" then
        name, fn, opts = "bench", name, fn
    end
    if type(fn) ~= "function" then
        error("test.bench expects a function", 2)
    end
    opts = opts or {}
    local runs = opts.runs or 30
    for _ = 1, opts.warmup or 3 do
        fn()
    end
    local instructions, times, bytes, allocations = {}, {}, {}, {}
    for i = 1, runs do
        local m = test.measure(fn, { gc = false, name = false })
        instructions[i], times[i], bytes[i], allocations[i] = m.instructions, m.time_ms, m.bytes, m.allocations
        if T.running then
            T.running.measures[#T.running.measures] = nil -- the bench reports them together
        end
    end
    local result = {
        name = name,
        runs = runs,
        instructions = stats(instructions),
        time_ms = stats(times),
        bytes = stats(bytes),
        allocations = stats(allocations),
    }
    if T.running then
        local list = T.running.benches
        list[#list + 1] = result
    end
    return result
end

-- Limits for the whole test (instructions, memory = peak bytes, allocations, bytes, time_ms), checked
-- by the runner when it ends.
function test.budget(limits)
    local state = running("budget")
    if type(limits) ~= "table" then
        error("test.budget expects a table of limits", 2)
    end
    state.budget = state.budget or {}
    for k, v in pairs(limits) do
        state.budget[k] = v
    end
end

-- Measures fn and fails if it goes over any limit given.
function test.expect_budget(fn, limits)
    local m = test.measure(fn, { name = limits.name })
    local over = {}
    for _, key in ipairs({ "instructions", "allocations", "bytes", "peak", "retained", "time_ms" }) do
        local limit = limits[key] or (key == "peak" and limits.memory) or nil
        if limit ~= nil and m[key] > limit then
            over[#over + 1] = format("%s %s > %s", key, T.number_text(m[key]), T.number_text(limit))
        end
    end
    T.count_assertion()
    if #over > 0 then
        T.fail("Over budget: " .. concat(over, ", "))
    end
    return m
end

function test.gc()
    bridge.gc()
end

function test.memory()
    return bridge.meter().memory
end

-- ---- fakes from C++ (Rhp::test::fake<L>) -----------------------------------------------------------------

-- fake.calls("game.spawn") -> {{args...}, ...}; fake.returns("game.spawn", v...); fake.reset([path]).
-- Fakes the runner made from an API description (rhp-cli test --api) answer the same calls.
fake = fake or {}
function fake.calls(path)
    if T.described_fake and T.described_fake.calls[path] then
        return T.described_fake.calls[path]
    end
    return bridge.host("fake_calls", path)
end
function fake.returns(path, ...)
    if T.described_fake and T.described_fake.functions[path] then
        T.described_fake.returns[path] = pack(...)
        return
    end
    bridge.host("fake_returns", path, ...)
end
function fake.reset(path)
    if T.described_fake then
        T.described_fake.reset(path)
    end
    pcall(bridge.host, "fake_reset", path)
end

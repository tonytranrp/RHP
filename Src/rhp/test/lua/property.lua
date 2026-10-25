-- Rhp::test, the Lua side, part 7: snapshots, property-based tests and fuzzing.
--   assert.snapshot(value)  /  expect(value).to.match_snapshot()      -- __snapshots__/<file>.snap.lua
--   test.property({gen.int(1, 100), gen.list(gen.string())}, function(n, words) ... end, {runs = 200})
--   it.property("sorting keeps every element", {gen.list(gen.int())}, function(list) ... end)
--   test.fuzz(function(input) parser.parse(input) end, {gen = gen.string{max = 200}})
-- Random values come from a seeded generator (the runner's --seed), so a failure reproduces; a failing
-- case is shrunk to a small one before it is reported.

local T = __rhp_t
local bridge = T.bridge
local type, select, pairs, ipairs, next, error, pcall, xpcall, tostring, setmetatable, load =
    type, select, pairs, ipairs, next, error, pcall, xpcall, tostring, setmetatable, load
local concat, insert, remove, unpack, sort = table.concat, table.insert, table.remove, table.unpack, table.sort
local format, byte, char, sub = string.format, string.byte, string.char, string.sub
local floor, huge, mtype = math.floor, math.huge, math.type
local pack = T.pack

-- ---- snapshots ------------------------------------------------------------------------------------------

-- ok, message, negative message, extra: the value against the snapshot stored for this test (the
-- first run stores it; --ci refuses to store, --update-snapshots replaces).
function T.snapshot_check(v, name)
    local state = T.running
    if not state then
        error("snapshots only work inside a running test", 3)
    end
    state.snapshot_count = state.snapshot_count + 1
    local key = state.test.full_name .. " " .. (name ~= nil and tostring(name) or tostring(state.snapshot_count))
    local text = T.serialize(v)
    local answer = bridge.host("snapshot", key, text)
    if answer.status == "match" or answer.status == "new" or answer.status == "updated" then
        return true, "", format("expected not to match the snapshot '%s'", key)
    end
    if answer.status == "broken" then
        return false, answer.message, ""
    end
    if answer.status == "missing" then
        return false, format("no snapshot '%s' was stored, and --ci refuses to store new ones\nValue:\n%s", key, text), ""
    end
    return false, format("snapshot '%s' doesn't match (run with --update-snapshots if the change is right)\n%s", key, T.line_diff(answer.stored or "", text)),
        "", { expected = answer.stored, actual = text }
end

T.assertions.snapshot = {
    check = function(state, a)
        local ok, positive, negative, extra = T.snapshot_check(a[1], a[2])
        state.positive, state.negative, state.extra = positive, negative, extra
        return ok
    end,
    positive = "%s",
    negative = "%s",
    show = function(_, state) return { state.positive or state.negative or "" }, state.extra end,
}
T.assertions.matches_snapshot = T.assertions.snapshot

-- ---- random numbers ------------------------------------------------------------------------------------

-- splitmix64 over Lua's 64-bit integers (wrapping arithmetic).
local rng_mt = {}
rng_mt.__index = rng_mt

local function new_rng(seed)
    return setmetatable({ state = seed // 1 }, rng_mt)
end
T.new_rng = new_rng

function rng_mt:next()
    self.state = self.state + 0x9E3779B97F4A7C15
    local z = self.state
    z = (z ~ (z >> 30)) * 0xBF58476D1CE4E5B9
    z = (z ~ (z >> 27)) * 0x94D049BB133111EB
    return z ~ (z >> 31)
end

-- An integer in [lo, hi].
function rng_mt:int(lo, hi)
    if hi <= lo then
        return lo
    end
    local range = hi - lo + 1
    if range <= 0 then -- the whole integer range
        return self:next()
    end
    return lo + ((self:next() >> 1) % range)
end

function rng_mt:float()
    return (self:next() >> 11) * (1.0 / 9007199254740992.0)
end

function rng_mt:chance(p)
    return self:float() < p
end

-- A seed from text (a test's name) and the run's seed.
local function seed_of(text, base)
    local h = (base or 0) ~ 0xCBF29CE484222325
    for i = 1, #text do
        h = (h ~ byte(text, i)) * 0x100000001B3
    end
    return h
end
T.seed_of = seed_of

-- ---- generators ------------------------------------------------------------------------------------------

-- A generator: {generate = function(rng, size) -> value, shrink = function(value) -> {candidates...}}
-- (smaller candidates first). `size` grows from 1 to 100 over a run.
local gen_mt = {}
gen_mt.__index = gen_mt
local function generator(generate, shrink, label)
    return setmetatable({ generate = generate, shrink = shrink or function() return {} end, label = label }, gen_mt)
end

local function is_generator(v)
    return type(v) == "table" and getmetatable(v) == gen_mt
end

-- Integers shrink toward `target` by halving the distance.
local function shrink_integer(v, target)
    local out = {}
    if v == target then
        return out
    end
    out[#out + 1] = target
    local gap = v - target
    local step = gap // 2
    while step ~= 0 and step ~= gap do
        out[#out + 1] = v - step
        step = step // 2
    end
    if gap > 0 then
        out[#out + 1] = v - 1
    else
        out[#out + 1] = v + 1
    end
    return out
end

gen = {}

function gen.int(lo, hi)
    lo, hi = lo or -1000, hi or 1000
    if hi < lo then
        error("gen.int: lo > hi", 2)
    end
    local target = (lo <= 0 and hi >= 0) and 0 or (lo > 0 and lo or hi)
    return generator(function(rng, size)
        local roll = rng:float()
        if roll < 0.05 then
            return lo
        elseif roll < 0.1 then
            return hi
        elseif roll < 0.15 and target ~= lo and target ~= hi then
            return target
        end
        -- small values more often while size is small
        local span = (hi - lo) * size // 100
        if span < 1 then
            span = 1
        end
        local low = target - span // 2
        if low < lo then
            low = lo
        end
        local high = low + span
        if high > hi then
            high = hi
        end
        return rng:int(low, high)
    end, function(v)
        local out = {}
        for _, c in ipairs(shrink_integer(v, target)) do
            if c >= lo and c <= hi then
                out[#out + 1] = c
            end
        end
        return out
    end, format("int(%d, %d)", lo, hi))
end

function gen.number(lo, hi)
    lo, hi = lo or -1000.0, hi or 1000.0
    return generator(function(rng)
        local roll = rng:float()
        if roll < 0.05 then
            return lo + 0.0
        elseif roll < 0.1 then
            return hi + 0.0
        elseif roll < 0.15 and lo <= 0 and hi >= 0 then
            return 0.0
        end
        return lo + (hi - lo) * rng:float()
    end, function(v)
        local out = {}
        local target = (lo <= 0 and hi >= 0) and 0.0 or lo + 0.0
        if v ~= target then
            out[#out + 1] = target
        end
        local whole = floor(v) + 0.0
        if whole ~= v and whole >= lo and whole <= hi then
            out[#out + 1] = whole
        end
        local half = target + (v - target) / 2
        if half ~= v and half ~= target then
            out[#out + 1] = half
        end
        return out
    end, "number")
end

function gen.bool()
    return generator(function(rng) return rng:chance(0.5) end, function(v) return v and { false } or {} end, "bool")
end

function gen.constant(v)
    return generator(function() return v end, nil, "constant")
end

-- gen.element({"a", "b", "c"}): one of the values (shrinks toward the first).
function gen.element(list)
    if type(list) ~= "table" or #list == 0 then
        error("gen.element expects a non-empty list", 2)
    end
    return generator(function(rng) return list[rng:int(1, #list)] end, function(v)
        local out = {}
        for i = 1, #list do
            if list[i] == v then
                break
            end
            out[#out + 1] = list[i]
        end
        return out
    end, "element")
end

-- gen.one_of(g1, g2, ...): a value of one of the generators.
function gen.one_of(...)
    local gens = pack(...)
    for i = 1, gens.n do
        if not is_generator(gens[i]) then
            gens[i] = gen.constant(gens[i])
        end
    end
    return generator(function(rng, size) return gens[rng:int(1, gens.n)].generate(rng, size) end, function(v)
        local out = {}
        for i = 1, gens.n do
            for _, c in ipairs(gens[i].shrink(v)) do
                out[#out + 1] = c
            end
        end
        return out
    end, "one_of")
end

-- gen.frequency({3, gen.int()}, {1, gen.string()}): weighted choice.
function gen.frequency(...)
    local entries = pack(...)
    local total = 0
    for i = 1, entries.n do
        total = total + entries[i][1]
    end
    return generator(function(rng, size)
        local roll = rng:float() * total
        for i = 1, entries.n do
            roll = roll - entries[i][1]
            if roll < 0 then
                return entries[i][2].generate(rng, size)
            end
        end
        return entries[entries.n][2].generate(rng, size)
    end, function(v)
        local out = {}
        for i = 1, entries.n do
            for _, c in ipairs(entries[i][2].shrink(v)) do
                out[#out + 1] = c
            end
        end
        return out
    end, "frequency")
end

function gen.optional(g)
    return generator(function(rng, size)
        if rng:chance(0.2) then
            return nil
        end
        return g.generate(rng, size)
    end, function(v)
        if v == nil then
            return {}
        end
        local out = { nil }
        out.n = 1
        for _, c in ipairs(g.shrink(v)) do
            out[#out + 1] = c
        end
        return out
    end, "optional")
end

local default_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-.,:;!?/\\'\"()[]{}<>=+*&^%$#@~\n\t"

-- Shorter versions of a list (or string, as a list of bytes): without its tail, its halves, each item.
local function shorter(n, min)
    local cuts = {}
    if n <= min then
        return cuts
    end
    cuts[#cuts + 1] = { 1, min } -- keep only the first `min`
    local size = n // 2
    while size >= 1 do
        for start = 1, n - size + 1, size do
            if n - size >= min then
                cuts[#cuts + 1] = { remove_from = start, count = size }
            end
        end
        size = size // 2
    end
    return cuts
end

function gen.string(opts)
    opts = opts or {}
    local min, max = opts.min or 0, opts.max or 32
    local chars = opts.chars or default_chars
    return generator(function(rng, size)
        local limit = min + (max - min) * size // 100
        if limit < min then
            limit = min
        end
        local n = rng:int(min, limit)
        local out = {}
        for i = 1, n do
            local k = rng:int(1, #chars)
            out[i] = sub(chars, k, k)
        end
        return concat(out)
    end, function(s)
        local out = {}
        for _, cut in ipairs(shorter(#s, min)) do
            if cut.remove_from then
                out[#out + 1] = sub(s, 1, cut.remove_from - 1) .. sub(s, cut.remove_from + cut.count)
            else
                out[#out + 1] = sub(s, 1, cut[2])
            end
        end
        local first = sub(chars, 1, 1)
        for i = 1, #s do
            local c = sub(s, i, i)
            if c ~= first then
                out[#out + 1] = sub(s, 1, i - 1) .. first .. sub(s, i + 1)
            end
        end
        return out
    end, "string")
end

function gen.list(g, opts)
    opts = opts or {}
    local min, max = opts.min or 0, opts.max or 20
    if not is_generator(g) then
        error("gen.list expects a generator", 2)
    end
    return generator(function(rng, size)
        local limit = min + (max - min) * size // 100
        if limit < min then
            limit = min
        end
        local n = rng:int(min, limit)
        local out = {}
        for i = 1, n do
            out[i] = g.generate(rng, size)
        end
        return out
    end, function(list)
        local out = {}
        local n = #list
        for _, cut in ipairs(shorter(n, min)) do
            local c = {}
            if cut.remove_from then
                for i = 1, n do
                    if i < cut.remove_from or i >= cut.remove_from + cut.count then
                        c[#c + 1] = list[i]
                    end
                end
            else
                for i = 1, cut[2] do
                    c[i] = list[i]
                end
            end
            out[#out + 1] = c
        end
        for i = 1, n do
            for _, smaller in ipairs(g.shrink(list[i])) do
                local c = { unpack(list, 1, n) }
                c[i] = smaller
                out[#out + 1] = c
            end
        end
        return out
    end, "list")
end

-- gen.tuple(g1, g2, ...): {v1, v2, ...}
function gen.tuple(...)
    local gens = pack(...)
    return generator(function(rng, size)
        local out = {}
        for i = 1, gens.n do
            out[i] = gens[i].generate(rng, size)
        end
        return out
    end, function(t)
        local out = {}
        for i = 1, gens.n do
            for _, smaller in ipairs(gens[i].shrink(t[i])) do
                local c = { unpack(t, 1, gens.n) }
                c[i] = smaller
                out[#out + 1] = c
            end
        end
        return out
    end, "tuple")
end

-- gen.record{name = gen.string(), hp = gen.int(0, 100)}
function gen.record(fields)
    local keys = {}
    for k in pairs(fields) do
        keys[#keys + 1] = k
    end
    sort(keys, T.key_less)
    return generator(function(rng, size)
        local out = {}
        for _, k in ipairs(keys) do
            out[k] = fields[k].generate(rng, size)
        end
        return out
    end, function(r)
        local out = {}
        for _, k in ipairs(keys) do
            for _, smaller in ipairs(fields[k].shrink(r[k])) do
                local c = {}
                for k2, v in pairs(r) do
                    c[k2] = v
                end
                c[k] = smaller
                out[#out + 1] = c
            end
        end
        return out
    end, "record")
end

-- gen.table(key_gen, value_gen [, {max}]): a table with generated keys and values.
function gen.table(kg, vg, opts)
    local pairs_gen = gen.list(gen.tuple(kg, vg), { max = opts and opts.max or 10 })
    return generator(function(rng, size)
        local out = {}
        for _, kv in ipairs(pairs_gen.generate(rng, size)) do
            if kv[1] ~= nil and kv[1] == kv[1] then
                out[kv[1]] = kv[2]
            end
        end
        return out
    end, function(t)
        local out = {}
        for k in pairs(t) do
            local c = {}
            for k2, v in pairs(t) do
                if k2 ~= k then
                    c[k2] = v
                end
            end
            out[#out + 1] = c
        end
        return out
    end, "table")
end

-- gen.map(g, fn): fn of a generated value (shrinks through g when given `unmap`).
function gen.map(g, fn)
    return generator(function(rng, size) return fn(g.generate(rng, size)) end, nil, "map")
end

-- gen.filter(g, predicate): retries until predicate holds (100 tries).
function gen.filter(g, predicate)
    return generator(function(rng, size)
        for _ = 1, 100 do
            local v = g.generate(rng, size)
            if predicate(v) then
                return v
            end
        end
        error("gen.filter: the predicate rejected 100 values in a row", 0)
    end, function(v)
        local out = {}
        for _, c in ipairs(g.shrink(v)) do
            if predicate(c) then
                out[#out + 1] = c
            end
        end
        return out
    end, "filter")
end

-- Any plain value: nil, booleans, integers, floats, strings, lists and tables of them.
function gen.any(depth)
    depth = depth or 2
    local leaves = gen.frequency({ 1, gen.constant(nil) }, { 2, gen.bool() }, { 4, gen.int() }, { 2, gen.number() }, { 4, gen.string() })
    if depth <= 0 then
        return leaves
    end
    local inner = gen.any(depth - 1)
    return gen.frequency({ 6, leaves }, { 2, gen.list(inner, { max = 6 }) }, { 1, gen.table(gen.string{ max = 8 }, inner, { max = 6 }) })
end

-- g:filter(predicate), g:map(fn)
function gen_mt:filter(predicate)
    return gen.filter(self, predicate)
end
function gen_mt:map(fn)
    return gen.map(self, fn)
end

-- ---- running properties --------------------------------------------------------------------------------

local function args_text(args)
    local parts = {}
    for i = 1, args.n do
        parts[i] = T.inline(args[i])
    end
    return "(" .. concat(parts, ", ") .. ")"
end

-- Whether fn(args) fails (raises, or returns false), and the error.
local function fails(fn, args)
    local ok, result = xpcall(fn, T.catch, unpack(args, 1, args.n))
    if not ok then
        return true, result
    end
    if result == false then
        return true, { kind = "failure", message = "the property returned false" }
    end
    return false
end

-- Greedy shrinking (fast-check's way): the first smaller candidate that still fails replaces the case.
local function shrink_case(gens, args, fn, budget)
    local steps = 0
    local err
    local improved = true
    while improved and steps < budget do
        improved = false
        for i = 1, args.n do
            local candidates = gens[i].shrink(args[i])
            local count = candidates.n or #candidates
            for c = 1, count do
                steps = steps + 1
                if steps > budget then
                    break
                end
                local trial = { n = args.n, unpack(args, 1, args.n) }
                trial[i] = candidates[c]
                local failed, e = fails(fn, trial)
                if failed then
                    args, err, improved = trial, e, true
                    break
                end
            end
            if improved then
                break
            end
        end
    end
    return args, err, steps
end

local function as_generators(gens)
    if is_generator(gens) then
        return { gens, n = 1 }
    end
    if type(gens) ~= "table" then
        error("expected a generator or a list of generators", 3)
    end
    local out = { n = #gens }
    for i = 1, #gens do
        if not is_generator(gens[i]) then
            error(format("argument %d isn't a generator (gen.*)", i), 3)
        end
        out[i] = gens[i]
    end
    return out
end

local function run_seed(opts, label)
    if opts.seed then
        return opts.seed
    end
    local base = T.config.seed or 0
    return seed_of(label or "property", base)
end

-- test.property(generators, fn [, {runs = 100, seed = n, shrink = 1000}])
function test.property(gens, fn, opts)
    opts = opts or {}
    gens = as_generators(gens)
    if type(fn) ~= "function" then
        error("test.property expects a function", 2)
    end
    local runs = opts.runs or T.config.property_runs or 100
    local label = T.running and T.running.test.full_name or "property"
    local seed = run_seed(opts, label)
    local rng = new_rng(seed)
    T.count_assertion()
    for run = 1, runs do
        local size = 1 + (run - 1) * 99 // (runs > 1 and runs - 1 or 1)
        local args = { n = gens.n }
        for i = 1, gens.n do
            args[i] = gens[i].generate(rng, size)
        end
        local failed, err = fails(fn, args)
        if failed then
            local small, small_err, steps = shrink_case(gens, args, fn, opts.shrink or 1000)
            local e = small_err or err
            T.fail(format("Property failed after %d run(s) (seed %d, shrunk in %d step(s)).\nCounterexample: %s\nOriginal: %s\n%s", run, seed, steps,
                args_text(small), args_text(args), e.message or tostring(e)), { expected = "", actual = args_text(small) })
        end
    end
    return runs
end

-- it.property(name, generators, fn [, opts]): a test that is one property.
it.property = function(name, gens, fn, opts)
    return it(name, function() test.property(gens, fn, opts) end)
end

-- ---- fuzzing ---------------------------------------------------------------------------------------------

local function decode(text)
    local chunk = load("return " .. text, "=corpus", "t", { math = { huge = huge } })
    if not chunk then
        return nil
    end
    local ok, v = pcall(chunk)
    if ok then
        return v
    end
    return nil
end

-- test.fuzz(fn [, {gen = gen.any(), gens = {...}, runs = 500, time_ms = n, corpus = name, seed = n}])
-- Calls fn with generated inputs; an error is a failure (a false return isn't). Inputs saved in the
-- corpus (__fuzz__/<file>/<name>/) run first, every time: a crash found once stays a regression test.
-- With coverage on (--coverage), inputs that reach new lines join the corpus and are mutated further
-- (kept on disk too with save_coverage = true).
function test.fuzz(fn, opts)
    opts = opts or {}
    local gens = as_generators(opts.gens or opts.gen or gen.any())
    local label = opts.corpus or (T.running and T.running.test.full_name) or "fuzz"
    local seed = run_seed(opts, label)
    local rng = new_rng(seed)
    local budget_ms = opts.time_ms or T.config.fuzz_ms
    local runs = opts.runs or (budget_ms and 1e15 or (T.config.fuzz_runs or 500))
    local started = bridge.meter().active_ms
    local corpus = {}
    local stored = bridge.host("corpus_load", label)
    for i = 1, #stored do
        local v = decode(stored[i])
        if type(v) == "table" then
            corpus[#corpus + 1] = { n = v.n or #v, unpack(v, 1, v.n or #v) }
        end
    end
    local function check(args, saved)
        local ok, err = xpcall(fn, T.catch, unpack(args, 1, args.n))
        if ok then
            return
        end
        local small, small_err = shrink_case(gens, args, function(...)
            local inner_ok, inner_err = xpcall(fn, T.catch, ...)
            if not inner_ok then
                error(inner_err, 0)
            end
        end, opts.shrink or 1000)
        local record = { n = small.n, unpack(small, 1, small.n) }
        if not saved then
            pcall(bridge.host, "corpus_save", label, T.serialize(record), "crash")
        end
        local e = small_err or err
        T.fail(format("Fuzzing found a failure (seed %d).\nInput: %s\nOriginal: %s\n%s", seed, args_text(small), args_text(args), (type(e) == "table" and (e.message or tostring(e.message))) or tostring(e)),
            { actual = args_text(small) })
    end
    T.count_assertion()
    for i = 1, #corpus do
        check(corpus[i], true)
    end
    local seen = bridge.coverage()
    local run = 0
    while run < runs do
        run = run + 1
        if budget_ms and bridge.meter().active_ms - started > budget_ms then
            break
        end
        local args
        if #corpus > 0 and rng:chance(0.5) then
            -- mutate a corpus entry: shrink a part, or regenerate one argument
            local base = corpus[rng:int(1, #corpus)]
            args = { n = base.n, unpack(base, 1, base.n) }
            local i = rng:int(1, gens.n)
            local smaller = gens[i].shrink(args[i])
            if #smaller > 0 and rng:chance(0.5) then
                args[i] = smaller[rng:int(1, #smaller)]
            else
                args[i] = gens[i].generate(rng, rng:int(1, 100))
            end
        else
            args = { n = gens.n }
            for i = 1, gens.n do
                args[i] = gens[i].generate(rng, rng:int(1, 100))
            end
        end
        check(args, false)
        local now = bridge.coverage()
        if now > seen then -- reached new lines: mutate it further (saved too with opts.save_coverage)
            seen = now
            corpus[#corpus + 1] = args
            if opts.save_coverage then
                pcall(bridge.host, "corpus_save", label, T.serialize({ n = args.n, unpack(args, 1, args.n) }), "cov")
            end
        end
    end
    return run
end

it.fuzz = function(name, fn, opts)
    return it(name, function() test.fuzz(fn, opts) end)
end

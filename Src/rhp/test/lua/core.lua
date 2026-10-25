-- Rhp::test, the Lua side, part 1: the test tree, the busted-style DSL (describe / it / hooks) and the
-- protocol the C++ runner drives (__rhp_t.list / prepare / run / finish). Runs in a test sandbox's
-- scratch environment: test files see these globals, the modules under test don't.

local bridge = __rhp_test
local T = {}
__rhp_t = T

local type, select, pairs, ipairs, next, error, pcall, xpcall, tostring, tonumber, setmetatable, getmetatable, rawget, rawset, rawequal =
    type, select, pairs, ipairs, next, error, pcall, xpcall, tostring, tonumber, setmetatable, getmetatable, rawget, rawset, rawequal
local concat, insert, sort, unpack = table.concat, table.insert, table.sort, table.unpack
local format, find, sub, gsub, gmatch, match, lower = string.format, string.find, string.sub, string.gsub, string.gmatch, string.match, string.lower

T.bridge = bridge
T.env = _ENV -- the scratch environment: test files' globals
T.framework = "rhp.test/" -- chunk names of the framework's own files start with this

-- ---- the tree ---------------------------------------------------------------------------------------

local function new_block(kind, name, parent)
    return {
        kind = kind,
        name = name,
        parent = parent,
        children = {},
        before_each = {},
        after_each = {},
        setup = {},
        teardown = {},
        lazy_setup = {},
        lazy_teardown = {},
        depth = parent and parent.depth + 1 or 0,
    }
end

T.root = new_block("file", "", nil)
T.current = T.root
T.tests = {}  -- id -> test
T.order = {}  -- ids in definition order
T.errors = {} -- errors outside tests: a failing describe body, setup or teardown
T.running = nil
T.next_id = 0
T.config = {} -- what the runner says (host "config"): seed, ci, ...

-- ---- locations --------------------------------------------------------------------------------------

-- The innermost frame outside the framework (and outside C functions), from `level` on.
function T.user_frame(frames)
    for i = 1, #frames do
        local f = frames[i]
        if f.what ~= "C" and sub(f.source, 1, #T.framework) ~= T.framework and f.line and f.line > 0 then
            return f
        end
    end
    return nil
end

-- (The first frame outside the framework: counting levels would break on tail calls.)
function T.caller()
    local frames = bridge.frames(2)
    local f = T.user_frame(frames)
    if f then
        return f.source, f.line
    end
    return "?", 0
end

-- A traceback of the frames outside the framework, innermost first.
function T.traceback(frames)
    local lines = {}
    for i = 1, #frames do
        local f = frames[i]
        if f.what ~= "C" and sub(f.source, 1, #T.framework) ~= T.framework then
            lines[#lines + 1] = format("%s:%d: in %s", f.source, f.line or 0, f.name ~= "?" and ("function '" .. f.name .. "'") or (f.what == "main" and "main chunk" or "function"))
        end
    end
    return concat(lines, "\n")
end

-- ---- names and tags ---------------------------------------------------------------------------------

local function full_name(block, name)
    local parts = {}
    local b = block
    while b and b.kind ~= "file" do
        insert(parts, 1, b.name)
        b = b.parent
    end
    parts[#parts + 1] = name
    return concat(parts, " ")
end

local function tags_of(name)
    local tags = {}
    for tag in gmatch(name, "#([%w_%-%.:]+)") do
        tags[#tags + 1] = tag
    end
    return tags
end

-- "adds %d and %d", "loads $name", "case %#" with a case's values.
function T.name_of(template, case, index)
    local args = type(case) == "table" and case or { case }
    local position = 0
    local out = gsub(template, "%%([%%sdifjo#])", function(spec)
        if spec == "%" then
            return "%"
        elseif spec == "#" then
            return tostring(index)
        end
        position = position + 1
        local v = args[position]
        if spec == "d" or spec == "i" then
            local n = tonumber(v)
            return n and format("%d", n // 1) or tostring(v)
        elseif spec == "f" then
            local n = tonumber(v)
            return n and tostring(n + 0.0) or tostring(v)
        elseif spec == "j" or spec == "o" then
            return T.inline(v)
        end
        return tostring(v)
    end)
    out = gsub(out, "%$([%a_][%w_]*)", function(key)
        if type(case) == "table" and case[key] ~= nil then
            return tostring(case[key])
        end
        return "$" .. key
    end)
    return out
end

-- ---- registration -----------------------------------------------------------------------------------

local function registering(what)
    if T.running then
        error(format("%s() can't be called while a test runs: declare it in the file or a describe", what), 3)
    end
end

local function check_name(name, what)
    if type(name) ~= "string" then
        error(format("%s expects a name (a string), got %s", what, type(name)), 3)
    end
end

local function add_test(name, fn, opts, flags)
    check_name(name, "it")
    registering("it")
    if fn ~= nil and type(fn) ~= "function" then
        error(format("it('%s') expects a function, got %s", name, type(fn)), 3)
    end
    if opts ~= nil and type(opts) ~= "table" then
        error(format("it('%s') options must be a table, got %s", name, type(opts)), 3)
    end
    local source, line = T.caller(3)
    T.next_id = T.next_id + 1
    local block = T.current
    local test = {
        id = T.next_id,
        name = name,
        full_name = full_name(block, name),
        block = block,
        fn = fn,
        opts = opts or {},
        source = source,
        line = line,
        only = flags.only or false,
        skip = flags.skip or false,
        pending = fn == nil or flags.pending or false,
    }
    test.tags = tags_of(test.full_name)
    T.tests[test.id] = test
    T.order[#T.order + 1] = test.id
    block.children[#block.children + 1] = test
    return test
end

local function add_block(name, fn, flags)
    check_name(name, "describe")
    registering("describe")
    if type(fn) ~= "function" then
        error(format("describe('%s') expects a function, got %s", name, type(fn)), 3)
    end
    local block = new_block("describe", name, T.current)
    block.only = flags.only or (T.current.only or false)
    block.skip = flags.skip or (T.current.skip or false)
    block.source, block.line = T.caller(3)
    T.current.children[#T.current.children + 1] = block
    local previous = T.current
    T.current = block
    local ok, err = xpcall(fn, function(e)
        return { message = type(e) == "table" and (e.message or tostring(e)) or tostring(e), frames = bridge.frames(2) }
    end)
    T.current = previous
    if not ok then
        local f = T.user_frame(err.frames)
        T.errors[#T.errors + 1] = {
            message = format("describe '%s' failed: %s", full_name(block.parent, name), err.message),
            source = f and f.source or block.source,
            line = f and f.line or block.line,
            traceback = T.traceback(err.frames),
        }
    end
    return block
end

-- describe(name, fn) / context(...) / insulate(...) / expose(...), with .only, .skip, .each
local function make_describe(flags)
    return function(name, fn)
        return add_block(name, fn, flags)
    end
end

local function each_of(add)
    return function(cases)
        if type(cases) ~= "table" then
            error("each() expects a list of cases", 2)
        end
        return function(template, fn, opts)
            for i = 1, #cases do
                local case = cases[i]
                -- A list case is spread into arguments; a record case ({name = ...}) is passed whole.
                local spread = type(case) == "table" and (case.n ~= nil or #case > 0)
                local args = spread and case or { case }
                local n = spread and (case.n or #case) or 1
                add(T.name_of(template, case, i), function()
                    return fn(unpack(args, 1, n))
                end, opts)
            end
        end
    end
end

local function callable(fn, fields)
    return setmetatable(fields, { __call = function(_, ...) return fn(...) end })
end

describe = callable(make_describe({}), {})
describe.only = make_describe({ only = true })
describe.skip = make_describe({ skip = true })
describe.each = each_of(function(name, fn) return add_block(name, fn, {}) end)
context = describe
insulate = describe
expose = describe

it = callable(function(name, fn, opts) return add_test(name, fn, opts, {}) end, {})
it.only = function(name, fn, opts) return add_test(name, fn, opts, { only = true }) end
it.skip = function(name, fn, opts) return add_test(name, fn, opts, { skip = true }) end
it.each = each_of(function(name, fn, opts) return add_test(name, fn, opts, {}) end)
spec = it

-- pending("name"[, fn]) declares a pending test; pending("why") inside a running test stops it as pending.
local pending_mt = { __tostring = function(p) return "pending: " .. tostring(p.message) end }
T.pending_mt = pending_mt

function pending(name, fn)
    if T.running then
        error(setmetatable({ message = name ~= nil and tostring(name) or "pending" }, pending_mt), 2)
    end
    check_name(name, "pending")
    return add_test(name, nil, nil, { pending = true })
end

local function hook(kind)
    return function(fn)
        registering(kind)
        if type(fn) ~= "function" then
            error(format("%s expects a function, got %s", kind, type(fn)), 2)
        end
        local list = T.current[kind]
        list[#list + 1] = fn
    end
end

before_each = hook("before_each")
after_each = hook("after_each")
setup = hook("setup")
teardown = hook("teardown")
lazy_setup = hook("lazy_setup")
lazy_teardown = hook("lazy_teardown")
strict_setup = setup
strict_teardown = teardown
before_all = setup -- Jest's names
after_all = teardown

-- finally(fn): runs when the current test ends, pass or fail (last registered first).
function finally(fn)
    if not T.running then
        error("finally() only works inside a running test", 2)
    end
    if type(fn) ~= "function" then
        error("finally expects a function", 2)
    end
    local list = T.running.finally
    list[#list + 1] = fn
end

-- ---- running ----------------------------------------------------------------------------------------

-- An error as a record: an assertion failure (a table from T.fail), pending, or anything else.
local function catch(e)
    local frames = bridge.frames(2)
    if type(e) == "table" and getmetatable(e) == pending_mt then
        return { kind = "pending", message = e.message, frames = frames }
    end
    if type(e) == "table" and rawget(e, "rhp_failure") then
        e.frames = e.frames or frames
        return e
    end
    local message
    if type(e) == "table" and rawget(e, "message") ~= nil then
        message = tostring(rawget(e, "message"))
    elseif type(e) == "string" or type(e) == "number" then
        message = tostring(e)
    else
        message = "error object: " .. T.inline(e) -- error({code = 9}) shows the table
    end
    return { kind = "error", message = message, frames = frames }
end
T.catch = catch

local function call(fn, ...)
    return xpcall(fn, catch, ...)
end
T.call = call

local function chain_of(block)
    local chain = {}
    local b = block
    while b do
        insert(chain, 1, b)
        b = b.parent
    end
    return chain
end

-- A raised error (or a failed assertion) as a result table.
local function describe_error(err, test)
    local out = { message = err.message or "error" }
    local f = err.frames and T.user_frame(err.frames)
    if err.source then
        out.source, out.line = err.source, err.line
    elseif f then
        out.source, out.line = f.source, f.line
    else
        out.source, out.line = test and test.source or "?", test and test.line or 0
    end
    out.traceback = err.frames and T.traceback(err.frames) or ""
    out.expected = err.expected
    out.actual = err.actual
    out.diff = err.diff
    return out
end
T.describe_error = describe_error

function T.list()
    local tests = {}
    for i = 1, #T.order do
        local t = T.tests[T.order[i]]
        local skip = t.skip
        local b = t.block
        while b do
            skip = skip or b.skip or false
            b = b.parent
        end
        local only = t.only
        b = t.block
        while b do
            only = only or b.only or false
            b = b.parent
        end
        tests[#tests + 1] = {
            id = t.id,
            name = t.full_name,
            short = t.name,
            source = t.source,
            line = t.line,
            tags = t.tags,
            only = only,
            skip = skip,
            pending = t.pending,
        }
    end
    local errors = {}
    for i = 1, #T.errors do
        local e = T.errors[i]
        errors[i] = { message = e.message, source = e.source, line = e.line, traceback = e.traceback }
    end
    return { tests = tests, errors = errors }
end

-- Runs the setup and lazy_setup of every block above test `id` that hasn't run them yet (outer
-- first). Called by the runner before the test's checkpoint: what setup does lasts for the file.
function T.prepare(id)
    local test = T.tests[id]
    if not test then
        return { ok = false, message = "no test " .. tostring(id) }
    end
    local chain = chain_of(test.block)
    for i = 1, #chain do
        local b = chain[i]
        if b.setup_state == nil then
            b.setup_state = { ok = true }
            for _, list in ipairs({ b.setup, b.lazy_setup }) do
                for j = 1, #list do
                    local ok, err = call(list[j])
                    if not ok then
                        local d = describe_error(err, test)
                        b.setup_state = { ok = false, message = d.message, source = d.source, line = d.line, traceback = d.traceback }
                        break
                    end
                end
                if not b.setup_state.ok then
                    break
                end
            end
        end
        if not b.setup_state.ok then
            local s = b.setup_state
            return {
                ok = false,
                message = format("setup of '%s' failed: %s", b.kind == "file" and "the file" or full_name(b.parent, b.name), s.message),
                source = s.source,
                line = s.line,
                traceback = s.traceback,
            }
        end
    end
    return { ok = true }
end

-- Runs test `id`: before_each (outer first), the body, finally (last first), after_each (inner first).
function T.run(id)
    local test = T.tests[id]
    local state = {
        test = test,
        finally = {},
        assertions = 0,
        measures = {},
        benches = {},
        budget = test.opts.budget,
        snapshot_count = 0,
        strict_undo = test.opts.undone or false,
        fakes = {},
    }
    T.running = state
    T.measure_depth = 0 -- a measure an error left open
    local globals_before = {}
    for k in next, T.env do
        globals_before[k] = true
    end
    if T.before_test then
        T.before_test(state)
    end
    local chain = chain_of(test.block)
    local ok, err = true, nil
    local reached = 0
    for i = 1, #chain do
        reached = i
        local list = chain[i].before_each
        for j = 1, #list do
            ok, err = call(list[j])
            if not ok then
                break
            end
        end
        if not ok then
            break
        end
    end
    if ok then
        if test.pending or test.fn == nil then
            ok, err = false, { kind = "pending", message = "pending" }
        else
            ok, err = call(test.fn)
        end
    end
    for i = #state.finally, 1, -1 do
        local fok, ferr = call(state.finally[i])
        if ok and not fok then
            ok, err = fok, ferr
        end
    end
    for i = reached, 1, -1 do
        local list = chain[i].after_each
        for j = 1, #list do
            local aok, aerr = call(list[j])
            if ok and not aok then
                ok, err = aok, aerr
            end
        end
    end
    if T.after_test then
        local aok, aerr = call(T.after_test, state)
        if ok and not aok then
            ok, err = aok, aerr
        end
    end
    T.running = nil
    -- Globals the test created are removed (the next test starts without them) and reported.
    local new_globals = {}
    for k in next, T.env do
        if not globals_before[k] then
            new_globals[#new_globals + 1] = tostring(k)
        end
    end
    for i = 1, #new_globals do
        rawset(T.env, new_globals[i], nil)
    end
    sort(new_globals)
    local result
    if ok then
        result = { status = "passed" }
    elseif err.kind == "pending" then
        result = { status = "pending", message = err.message }
    else
        result = describe_error(err, test)
        result.status = err.kind == "failure" and "failed" or "error"
    end
    result.assertions = state.assertions
    result.measures = state.measures
    result.benches = state.benches
    result.budget = state.budget
    result.strict_undo = state.strict_undo
    result.globals = new_globals
    return result
end

-- Runs teardown and lazy_teardown of every block whose setup ran (inner blocks first).
function T.finish()
    local blocks = {}
    local function walk(b)
        for i = 1, #b.children do
            local c = b.children[i]
            if c.children then
                walk(c)
            end
        end
        if b.setup_state ~= nil then
            blocks[#blocks + 1] = b
        end
    end
    walk(T.root)
    local errors = {}
    for i = 1, #blocks do
        local b = blocks[i]
        for _, list in ipairs({ b.lazy_teardown, b.teardown }) do
            for j = 1, #list do
                local ok, err = call(list[j])
                if not ok then
                    local d = describe_error(err, nil)
                    errors[#errors + 1] = {
                        message = format("teardown of '%s' failed: %s", b.kind == "file" and "the file" or full_name(b.parent, b.name), d.message),
                        source = d.source,
                        line = d.line,
                        traceback = d.traceback,
                    }
                end
            end
        end
    end
    return { errors = errors }
end

-- The runner's settings for this file (seed, ci, update_snapshots, fuzz budget, ...).
function T.configure(config)
    T.config = config or {}
end

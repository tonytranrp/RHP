-- Rhp::test, the Lua side, part 4: spies, stubs and mocks (luassert's API).
--   local s = spy.on(game, "spawn")          -- wraps game.spawn (a lib function, a module export, a method, a field)
--   stub(game, "spawn").returns(42)          -- replaces it
--   stub(game, "load").on_call_with("boss").returns(nil, "missing")
--   mock(game)                               -- every function of game spied (mock(game, true): stubbed)
--   stub.var(game, "speed", 2.5)             -- a lib variable read from the stub (writes kept there)
--   assert.spy(s).was.called_with("boss", match.is_number())
-- Swaps of lib members, module exports and handle members are journaled by the sandbox: they are put
-- back when the test ends, whatever happened. s:revert() puts one back earlier.

local T = __rhp_t
local bridge = T.bridge
local type, pairs, ipairs, next, error, tostring, setmetatable, getmetatable, rawget, rawequal =
    type, pairs, ipairs, next, error, tostring, setmetatable, getmetatable, rawget, rawequal
local concat, unpack = table.concat, table.unpack
local format = string.format
local pack = T.pack

-- A copy of a call's arguments as they were (tables copied deeply, cycles kept), for called_with.
local function deep_copy(v, seen)
    if type(v) ~= "table" then
        return v
    end
    seen = seen or {}
    if seen[v] then
        return seen[v]
    end
    local out = {}
    seen[v] = out
    for k, x in next, v do
        out[deep_copy(k, seen)] = deep_copy(x, seen)
    end
    -- A protected metatable (__metatable) can't be set on the copy: comparisons ignore it anyway.
    local mt = getmetatable(v)
    if type(mt) == "table" then
        pcall(setmetatable, out, mt)
    end
    return out
end

local function copy_args(args)
    -- Without tables there is nothing to copy: the packed arguments are both (the common case).
    local has_table = false
    for i = 1, args.n do
        if type(args[i]) == "table" then
            has_table = true
            break
        end
    end
    if not has_table then
        return { vals = args, refs = args }
    end
    local vals = { n = args.n }
    local refs = { n = args.n }
    for i = 1, args.n do
        vals[i] = deep_copy(args[i])
        refs[i] = args[i]
    end
    return { vals = vals, refs = refs }
end

local spy_mt = {}
local spies = setmetatable({}, { __mode = "k" }) -- wrapper function -> spy

function T.is_spy(v)
    return getmetatable(v) == spy_mt or spies[v] ~= nil
end

local function spy_of(v)
    if getmetatable(v) == spy_mt then
        return v
    end
    return spies[v]
end
T.spy_of = spy_of

local function record_call(self, ...)
    local args = pack(...)
    self.calls[#self.calls + 1] = copy_args(args)
    local results = pack(self.callback(...))
    self.returnvals[#self.returnvals + 1] = copy_args(results)
    return unpack(results, 1, results.n)
end

spy_mt.__index = spy_mt
spy_mt.__call = function(self, ...)
    return record_call(self, ...)
end
spy_mt.__tostring = function(self)
    return format("spy: %s (%d calls)", self.label or "?", #self.calls)
end

function spy_mt:clear()
    self.calls = {}
    self.returnvals = {}
    return self
end

-- Puts the original back (the sandbox would at the end of the test anyway).
function spy_mt:revert()
    if self.target ~= nil then
        -- Only while this spy is the member: a spy installed over it stays (the test's end puts
        -- everything back anyway), and this one just calls through from now on.
        if rawequal(self.target[self.key], self.fn) then
            -- Below may be a spy reverted earlier (it only calls through): skip to what it replaced.
            local original = self.original
            while spies[original] ~= nil and spies[original].reverted do
                original = spies[original].original
            end
            bridge.swap(self.target, self.key, original)
        else
            local original = self.original
            self.callback = function(...) return original(...) end
        end
        self.reverted = true
        self.target = nil
    end
    return self.original
end

local function args_match(recorded, expected)
    if recorded.vals.n ~= expected.n then
        return false
    end
    for i = 1, expected.n do
        local want = expected[i]
        if T.is_matcher(want) then
            if not want(recorded.refs[i]) then
                return false
            end
        elseif not T.deep_equal(want, recorded.vals[i], true) then
            return false
        end
    end
    return true
end

function spy_mt:called(times)
    if times == nil then
        return #self.calls > 0
    end
    return #self.calls == times
end

function spy_mt:called_with(...)
    local expected = pack(...)
    for i = #self.calls, 1, -1 do
        if args_match(self.calls[i], expected) then
            return true, self.calls[i]
        end
    end
    return false, self.calls[#self.calls]
end

function spy_mt:returned_with(...)
    local expected = pack(...)
    for i = #self.returnvals, 1, -1 do
        if args_match(self.returnvals[i], expected) then
            return true, self.returnvals[i]
        end
    end
    return false, self.returnvals[#self.returnvals]
end

local function new_spy(callback, label)
    return setmetatable({ callback = callback or function() end, calls = {}, returnvals = {}, label = label }, spy_mt)
end

-- A function that calls the spy (what goes into a lib, a module or a handle: callers there need a
-- real function), registered so assert.spy(target.key) finds the spy.
local function wrapper_of(s)
    local w = function(...)
        return record_call(s, ...)
    end
    spies[w] = s
    s.fn = w
    return w
end

local function label_of(target, key)
    local kind = bridge.kind(target)
    local name = tostring(target)
    return format("%s.%s", kind == "table" and "table" or name, tostring(key))
end

local function install(target, key, s)
    if type(key) ~= "string" and type(key) ~= "number" then
        error("expected the name of a member to replace", 3)
    end
    local kind = bridge.kind(target)
    if kind ~= "lib" and kind ~= "module" and kind ~= "handle" and kind ~= "table" then
        error(format("can't replace a member of a %s", kind), 3)
    end
    local meta = type(target) == "table" and getmetatable(target)
    if kind == "table" and type(meta) == "table" and rawget(meta, "__rhp_fake_handle") ~= nil and rawget(target, key) == nil then
        target = rawget(meta, "__rhp_fake_handle") -- a fake handle's methods are shared by its type, like a real handle's
    end
    s.target, s.key = target, key
    s.original = bridge.swap(target, key, wrapper_of(s))
    return s
end

-- spy.new(fn) / spy(fn): a callable table recording calls to fn. spy.on(target, key): replaces
-- target[key] with a function recording calls and calling through.
spy = setmetatable({}, { __call = function(_, fn) return new_spy(fn, "spy") end })
spy.new = function(fn) return new_spy(fn, "spy") end
spy.is_spy = T.is_spy
function spy.on(target, key)
    local current = target[key]
    if current ~= nil and type(current) ~= "function" and not T.is_spy(current) then
        local mt = getmetatable(current)
        if not (type(mt) == "table" and rawget(mt, "__call")) then
            error(format("spy.on: %s is a %s, not a function", tostring(key), type(current)), 2)
        end
    end
    local s = new_spy(function(...)
        if current == nil then
            return nil
        end
        return current(...)
    end, label_of(target, key))
    return install(target, key, s)
end

-- Stubs: spies whose callback returns configured values.
local function make_stub(label, values)
    local s = new_spy(nil, label)
    local behaviour = { returns = values, invokes = nil }
    local rules = {} -- {args, returns / invokes} from on_call_with
    s.callback = function(...)
        local args = pack(...)
        for i = #rules, 1, -1 do
            local r = rules[i]
            if args_match({ vals = args, refs = args }, r.args) then
                if r.invokes then
                    return r.invokes(...)
                end
                return unpack(r.returns, 1, r.returns.n)
            end
        end
        if behaviour.invokes then
            return behaviour.invokes(...)
        end
        if behaviour.returns then
            return unpack(behaviour.returns, 1, behaviour.returns.n)
        end
        if s.strict then
            error(format("not mocked: %s called with (%s)", s.label or "?", (function()
                local parts = {}
                for i = 1, args.n do
                    parts[i] = T.inline(args[i])
                end
                return concat(parts, ", ")
            end)()), 2)
        end
    end
    s.returns = function(...)
        behaviour.returns, behaviour.invokes = pack(...), nil
        return s
    end
    s.invokes = function(fn)
        behaviour.invokes, behaviour.returns = fn, nil
        return s
    end
    s.by_default = { returns = s.returns, invokes = s.invokes }
    s.on_call_with = function(...)
        local rule = { args = pack(...), returns = { n = 0 } }
        rules[#rules + 1] = rule
        return {
            returns = function(...)
                rule.returns = pack(...)
                return s
            end,
            invokes = function(fn)
                rule.invokes = fn
                return s
            end,
        }
    end
    return s
end

-- stub(target, key, ...): target[key] returns ... (or calls the one function given).
stub = setmetatable({}, {
    __call = function(_, target, key, ...)
        if target == nil then
            return make_stub("stub", { n = 0 })
        end
        local values = pack(...)
        local s = make_stub(label_of(target, key), values)
        if values.n == 1 and type(values[1]) == "function" then
            s.invokes(values[1])
        end
        return install(target, key, s)
    end,
})
stub.new = function(target, key, ...) return stub(target, key, ...) end

-- stub.var(lib, name, value): the variable reads `value`; writes (as any script would make them) are
-- kept by the stub and read back. Returns a table {value = ..., writes = {...}}.
function stub.var(target, name, value)
    if bridge.kind(target) ~= "lib" then
        if type(target) == "table" then -- a fake lib or a plain table: just a field
            local s = { value = value, writes = {} }
            bridge.swap(target, name, value)
            return s
        end
        error("stub.var expects a lib", 2)
    end
    local state = { value = value, writes = {} }
    bridge.swap_var(target, name, function() return state.value end, function(v)
        state.writes[#state.writes + 1] = v
        state.value = v
    end)
    return state
end

-- mock(target [, stubbed]): every function member spied (or stubbed), recursively into tables and
-- sub-libs. mock.revert(target) / mock.clear(target).
local mocked = setmetatable({}, { __mode = "k" }) -- target -> {spies}
mock = setmetatable({}, {
    __call = function(_, target, stubbed, seen)
        seen = seen or {}
        if seen[target] then
            return target
        end
        seen[target] = true
        local list = {}
        mocked[target] = list
        local members = bridge.members(target)
        for key, what in pairs(members) do
            if what == "function" or what == "method" then
                list[#list + 1] = stubbed and stub(target, key) or spy.on(target, key)
            elseif what == "lib" or what == "table" then
                local inner = target[key]
                if type(inner) == "table" or bridge.kind(inner) == "lib" then
                    mock(inner, stubbed, seen)
                end
            end
        end
        return target
    end,
})
function mock.revert(target)
    for _, s in ipairs(mocked[target] or {}) do
        s:revert()
    end
    mocked[target] = nil
end
function mock.clear(target)
    for _, s in ipairs(mocked[target] or {}) do
        s:clear()
    end
end

-- ---- spy assertions -------------------------------------------------------------------------------

local function call_list(s)
    local last = s.calls[#s.calls]
    if not last then
        return "(no calls)"
    end
    local parts = {}
    for i = 1, last.vals.n do
        parts[i] = T.inline(last.vals[i])
    end
    return "(" .. concat(parts, ", ") .. ")"
end

local function expected_list(args, first)
    local parts = {}
    for i = first, args.n do
        parts[#parts + 1] = T.is_matcher(args[i]) and tostring(args[i]) or T.inline(args[i])
    end
    return "(" .. concat(parts, ", ") .. ")"
end

local A = T.spy_assertions
local function counted(rule, phrase)
    return {
        check = function(_, a)
            local s = spy_of(a[1])
            local n, want = #s.calls, a[2]
            if want == nil then
                return n > 0
            end
            return rule(n, want)
        end,
        positive = "Expected to be called " .. phrase .. "%s time(s), but was called %s time(s)",
        negative = "Expected not to be called " .. phrase .. "%s time(s), but it was (%s)",
        show = function(a)
            return { a[2] == nil and ">0" or tostring(a[2]), tostring(#spy_of(a[1]).calls) }
        end,
    }
end
A.called = counted(function(n, want) return n == want end, "")
A.called_at_least = counted(function(n, want) return n >= want end, "at least ")
A.called_at_most = counted(function(n, want) return n <= want end, "at most ")
A.called_more_than = counted(function(n, want) return n > want end, "more than ")
A.called_less_than = counted(function(n, want) return n < want end, "less than ")
A.called_with = {
    check = function(_, a)
        local s = spy_of(a[1])
        return (s:called_with(unpack(a, 2, a.n)))
    end,
    positive = "Function was never called with matching arguments.\nCalled with (last call if any):\n%s\nExpected:\n%s",
    negative = "Function was called with matching arguments at least once.\nCalled with (last matching call):\n%s\nDid not expect:\n%s",
    show = function(a)
        local s = spy_of(a[1])
        return { call_list(s), expected_list(a, 2) }, { expected = expected_list(a, 2), actual = call_list(s) }
    end,
}
A.returned_with = {
    check = function(_, a)
        local s = spy_of(a[1])
        return (s:returned_with(unpack(a, 2, a.n)))
    end,
    positive = "Function never returned matching arguments.\nReturned (last call if any):\n%s\nExpected:\n%s",
    negative = "Function returned matching arguments at least once.\nReturned (last matching call):\n%s\nDid not expect:\n%s",
    show = function(a)
        local s = spy_of(a[1])
        local last = s.returnvals[#s.returnvals]
        local parts = {}
        if last then
            for i = 1, last.vals.n do
                parts[i] = T.inline(last.vals[i])
            end
        end
        return { last and ("(" .. concat(parts, ", ") .. ")") or "(no calls)", expected_list(a, 2) }
    end,
}

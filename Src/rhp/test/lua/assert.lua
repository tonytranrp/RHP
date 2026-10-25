-- Rhp::test, the Lua side, part 3: luassert-compatible assertions and matchers.
--   assert.equals(expected, actual)   assert.is_true(v)   assert.are.same(t1, t2)   assert.is_not.near(a, b, tol)
--   assert.has_error(fn, "msg")       assert.matches("^a", s)   assert.spy(s).was.called_with(1, match._)
-- Words are case-insensitive and split on "_"; is/are/was/has/does/a/an/the change nothing, not/no
-- flip the assertion. A failure raises a table error the runner reports with the test file's line.

local T = __rhp_t
local type, select, pairs, ipairs, next, error, pcall, tostring, tonumber, setmetatable, getmetatable, rawget, rawset, rawequal =
    type, select, pairs, ipairs, next, error, pcall, tostring, tonumber, setmetatable, getmetatable, rawget, rawset, rawequal
local concat, insert, unpack = table.concat, table.insert, table.unpack
local format, find, gsub, gmatch, lower, sub = string.format, string.find, string.gsub, string.gmatch, string.lower, string.sub
local lua_assert = assert

-- ---- failures -----------------------------------------------------------------------------------------

-- Raises an assertion failure. `expected` / `actual` are shown values (strings) for editors' diff views.
function T.fail(message, extra)
    local e = { rhp_failure = true, kind = "failure", message = message }
    if extra then
        for k, v in pairs(extra) do
            e[k] = v
        end
    end
    error(e, 0)
end

local function count_assertion()
    if T.running then
        T.running.assertions = T.running.assertions + 1
    end
end
T.count_assertion = count_assertion

local function pack(...)
    return { n = select("#", ...), ... }
end
T.pack = pack

-- ---- matchers ---------------------------------------------------------------------------------------

local matcher_mt = {}
matcher_mt.__index = matcher_mt
function matcher_mt:__call(v)
    return self.callback(v) == not self.negated
end
matcher_mt.__tostring = function(m)
    local args = {}
    for i = 1, m.arguments.n do
        args[i] = T.inline(m.arguments[i])
    end
    return format("(matcher) %s%s(%s)", m.negated and "is_not." or "is.", m.name, concat(args, ", "))
end

local function is_matcher(v)
    return getmetatable(v) == matcher_mt
end
T.is_matcher = is_matcher

local matchers = {} -- name -> function(state, arguments) -> callback(value) -> bool

local function type_matcher(t)
    return function() return function(v) return type(v) == t end end
end
for _, t in ipairs({ "nil", "boolean", "number", "string", "table", "function", "userdata", "thread" }) do
    matchers[t] = type_matcher(t)
end
matchers["true"] = function() return function(v) return v == true end end
matchers["false"] = function() return function(v) return v == false end end
matchers.truthy = function() return function(v) return v ~= nil and v ~= false end end
matchers.falsy = function() return function(v) return v == nil or v == false end end
matchers.ref = function(_, args) local r = args[1] return function(v) return rawequal(v, r) end end
matchers.same = function(_, args) local r = args[1] return function(v) return (T.deep_equal(v, r, true)) end end
matchers.equal = function(_, args) local r = args[1] return function(v) return v == r end end
matchers.equals = matchers.equal
matchers.near = function(_, args)
    local expected, tol = tonumber(args[1]), tonumber(args[2]) or 0
    return function(v)
        v = tonumber(v)
        return v ~= nil and v >= expected - tol and v <= expected + tol
    end
end
matchers.match = function(_, args)
    local pattern, init, plain = args[1], args[2], args[3]
    return function(v)
        if type(v) == "number" then
            v = tostring(v)
        end
        return type(v) == "string" and find(v, pattern, init, plain) ~= nil
    end
end
matchers.matches = matchers.match
matchers.unique = function() return function(v)
    if type(v) ~= "table" then
        return false
    end
    for i = 1, #v do
        for j = i + 1, #v do
            if T.deep_equal(v[i], v[j], true) then
                return false
            end
        end
    end
    return true
end end
local function composite(rule)
    return function(_, args)
        for i = 1, args.n do
            if not is_matcher(args[i]) then
                error("match." .. rule .. " expects matchers", 4)
            end
        end
        return function(v)
            local hits = 0
            for i = 1, args.n do
                if args[i](v) then
                    hits = hits + 1
                end
            end
            if rule == "all_of" then
                return hits == args.n
            elseif rule == "any_of" then
                return hits > 0
            end
            return hits == 0
        end
    end
end
matchers.all_of = composite("all_of")
matchers.any_of = composite("any_of")
matchers.none_of = composite("none_of")
matchers.contains = function(_, args)
    local item = args[1]
    return function(v)
        if type(v) == "string" then
            return find(v, tostring(item), 1, true) ~= nil
        end
        if type(v) ~= "table" then
            return false
        end
        for _, x in pairs(v) do
            if T.deep_equal(x, item, true) then
                return true
            end
        end
        return false
    end
end
matchers.table_containing = function(_, args)
    local fields = args[1]
    return function(v)
        if type(v) ~= "table" then
            return false
        end
        for k, want in pairs(fields) do
            local got = v[k]
            if is_matcher(want) then
                if not want(got) then
                    return false
                end
            elseif not T.deep_equal(got, want, true) then
                return false
            end
        end
        return true
    end
end

-- Modifier words: nothing, or a flip.
local fillers = { is = true, are = true, was = true, has = true, does = true, a = true, an = true, the = true, to = true, be = true, been = true }
local negations = { ["not"] = true, no = true }

-- Splits accumulated words into (negated, name).
local function resolve(words)
    local negated = false
    local parts = {}
    for i = 1, #words do
        local w = words[i]
        if negations[w] then
            negated = not negated
        elseif not fillers[w] then
            parts[#parts + 1] = w
        end
    end
    return negated, concat(parts, "_")
end

local function chain(words, on_call)
    return setmetatable({ words = words }, {
        __index = function(self, key)
            local next_words = { unpack(rawget(self, "words")) }
            for w in gmatch(lower(key), "[^_]+") do
                next_words[#next_words + 1] = w
            end
            return chain(next_words, on_call)
        end,
        __call = function(self, ...)
            return on_call(rawget(self, "words"), ...)
        end,
    })
end

match = chain({}, function(words, ...)
    local negated, name = resolve(words)
    local make = matchers[name]
    if not make then
        error(format("no matcher 'match.%s'", concat(words, "_")), 2)
    end
    local args = pack(...)
    return setmetatable({ name = name, negated = negated, arguments = args, callback = make({}, args) }, matcher_mt)
end)
rawset(match, "_", setmetatable({ name = "_", negated = false, arguments = { n = 0 }, callback = function() return true end }, matcher_mt))
T.matchers = matchers

-- ---- assertions -------------------------------------------------------------------------------------

-- name -> {check = function(state, args) -> ok, ...extra}, positive = template, negative = template,
-- show = function(args, extra) -> values shown in the template}
local assertions = {}
T.assertions = assertions

local function shown(args)
    return function(...)
        local out = {}
        for i = 1, select("#", ...) do
            out[i] = T.show(args[select(i, ...)])
        end
        return unpack(out, 1, select("#", ...))
    end
end

-- `arity`: how many arguments the assertion takes; the first string after them is the message
-- (assert.equals(1, x, "why")), as in luassert.
local function register(name, check, positive, negative, show, arity)
    assertions[name] = { check = check, positive = positive, negative = negative, show = show, arity = arity or 1 }
end

-- equals(expected, actual): ==
register("equals", function(_, a)
    return a[1] == a[2]
end, "Expected objects to be equal.\nPassed in:\n%s\nExpected:\n%s", "Expected objects to not be equal.\nPassed in:\n%s\nDid not expect:\n%s",
    function(a) return { T.show(a[2]), T.show(a[1]) }, { expected = T.inline(a[1]), actual = T.inline(a[2]) } end)
assertions.equal = assertions.equals
assertions.equals.arity = 2

-- same(expected, actual): deep
register("same", function(state, a)
    local ok, path = T.deep_equal(a[1], a[2], true)
    state.path = path
    return ok
end, "Expected objects to be the same.\nPassed in:\n%s\nExpected:\n%s", "Expected objects to not be the same.\nPassed in:\n%s\nDid not expect:\n%s",
    function(a, state)
        local path = state.path
        local where = path and #path > 0 and ("\nFirst difference at " .. T.path_text(path) .. ": " .. T.inline(T.at_path(a[2], path)) .. " instead of " .. T.inline(T.at_path(a[1], path))) or ""
        return { T.show(a[2], path), T.show(a[1], path) .. where }, { expected = T.serialize(a[1]), actual = T.serialize(a[2]) }
    end, 2)

register("near", function(_, a)
    local e, v, tol = tonumber(a[1]), tonumber(a[2]), tonumber(a[3])
    if e == nil or v == nil or tol == nil then
        error("near expects numbers (expected, actual, tolerance)", 0)
    end
    return v >= e - tol and v <= e + tol
end, "Expected values to be near.\nPassed in:\n%s\nExpected:\n%s +/- %s", "Expected values to not be near.\nPassed in:\n%s\nDid not expect:\n%s +/- %s",
    function(a) return { T.show(a[2]), T.show(a[1]), T.show(a[3]) } end, 3)

register("matches", function(_, a)
    local pattern, v, init, plain = a[1], a[2], a[3], a[4]
    if type(v) == "number" then
        v = tostring(v)
    elseif type(v) ~= "string" then
        local mt = getmetatable(v)
        if type(mt) == "table" and rawget(mt, "__tostring") then
            v = tostring(v)
        else
            return false
        end
    end
    if type(init) ~= "number" then
        init, plain = nil, nil
    end
    return find(v, pattern, init, plain == true) ~= nil
end, "Expected strings to match.\nPassed in:\n%s\nExpected:\n%s", "Expected strings not to match.\nPassed in:\n%s\nDid not expect:\n%s",
    function(a) return { T.show(a[2]), T.show(a[1]) } end)
assertions.matches.arity = 2
assertions.match = assertions.matches

register("truthy", function(_, a) return a[1] ~= nil and a[1] ~= false end, "Expected to be truthy, but value was:\n%s",
    "Expected to not be truthy, but value was:\n%s", function(a) return { T.show(a[1]) } end)
register("falsy", function(_, a) return a[1] == nil or a[1] == false end, "Expected to be falsy, but value was:\n%s",
    "Expected to not be falsy, but value was:\n%s", function(a) return { T.show(a[1]) } end)
register("true", function(_, a) return a[1] == true end, "Expected to be true, but value was:\n%s", "Expected to not be true, but value was:\n%s",
    function(a) return { T.show(a[1]) } end)
register("false", function(_, a) return a[1] == false end, "Expected to be false, but value was:\n%s", "Expected to not be false, but value was:\n%s",
    function(a) return { T.show(a[1]) } end)
for _, t in ipairs({ "nil", "boolean", "number", "string", "table", "function", "userdata", "thread" }) do
    register(t, function(_, a) return type(a[1]) == t end, "Expected type " .. t .. ", but value was:\n%s", "Expected not type " .. t .. ", but value was:\n%s",
        function(a) return { T.show(a[1]) } end)
end
register("unique", function(_, a) return matchers.unique()(a[1]) end, "Expected object to be unique:\n%s", "Expected object to not be unique:\n%s",
    function(a) return { T.show(a[1]) } end)

-- has_error(fn [, expected]): expected is the message (its "file:line: " prefix ignored), or any value compared deeply.
local function caught(fn, ...)
    if type(fn) ~= "function" then
        error("expected a function to call, got " .. type(fn), 0)
    end
    local ok, err = pcall(fn, ...)
    if ok then
        return false
    end
    if type(err) == "string" then
        err = gsub(err, "^.-:%d+: ", "", 1)
    elseif type(err) == "table" and rawget(err, "rhp_failure") then
        err = err.message
    end
    return true, err
end

register("error", function(state, a)
    local raised, err = caught(a[1])
    state.caught = err
    state.raised = raised
    if not raised then
        return false
    end
    if a.n < 2 or a[2] == nil then
        return true
    end
    local expected = a[2]
    if type(expected) == "string" then
        return err == expected or (type(err) == "string" and err == gsub(expected, "^.-:%d+: ", "", 1))
    elseif type(expected) == "number" then
        return tostring(tonumber(err)) == tostring(expected)
    end
    return (T.deep_equal(expected, err, true))
end, "Expected a different error.\nCaught:\n%s\nExpected:\n%s", "Expected no error, but caught:\n%s",
    function(a, state)
        if not state.raised then
            return { "(no error)", a.n >= 2 and a[2] ~= nil and T.show(a[2]) or "(error)" }
        end
        return { T.show(state.caught), a.n >= 2 and a[2] ~= nil and T.show(a[2]) or "(error)" }
    end)
assertions.error.arity = 2
assertions.errors = assertions.error

register("error_matches", function(state, a)
    local raised, err = caught(a[1])
    state.caught, state.raised = err, raised
    if not raised then
        return false
    end
    local pattern, init, plain = a[2], a[3], a[4]
    if type(init) ~= "number" then
        init, plain = nil, nil
    end
    return find(tostring(err), pattern, init, plain == true) ~= nil
end, "Expected a different error.\nCaught:\n%s\nExpected:\n%s", "Expected no error matching, but caught:\n%s",
    function(a, state) return { state.raised and T.show(state.caught) or "(no error)", T.show(a[2]) } end)
assertions.error_matches.arity = 2
assertions.error_match = assertions.error_matches
assertions.match_error = assertions.error_matches
assertions.matches_error = assertions.error_matches

register("returned_arguments", function(_, a)
    return tostring(a[1]) == tostring(a.n - 1)
end, "Expected %s result(s) to be returned, but got %s", "Expected not %s result(s) to be returned, but got %s",
    function(a) return { tostring(a[1]), tostring(a.n - 1) } end)

-- Spy assertions (assert.spy(s).was.called(n) ...): see spy.lua for the spies.
T.spy_assertions = {}

-- Runs an assertion: raises the failure, or returns the arguments.
local function check(words, target, message, ...)
    local negated, name = resolve(words)
    local args = pack(...)
    local spec
    if target ~= nil then
        spec = T.spy_assertions[name]
        if not spec then
            error(format("no spy assertion '%s'", name), 3)
        end
        args = pack(target, ...)
    else
        spec = assertions[name]
        if not spec then
            error(format("no assertion 'assert.%s'", concat(words, "_")), 3)
        end
    end
    count_assertion()
    if message == nil and target == nil then
        for i = (spec.arity or 1) + 1, args.n do
            if type(args[i]) == "string" then
                message = args[i]
                break
            end
        end
    end
    local state = {}
    local ok = spec.check(state, args)
    if (ok and true or false) ~= negated then
        return ...
    end
    local values, extra = spec.show(args, state)
    local template = negated and spec.negative or spec.positive
    local text = format(template, unpack(values, 1, #values))
    if message ~= nil then
        text = tostring(message) .. "\n" .. text
    end
    T.fail(text, extra)
end
T.check = check

-- assert(v, msg, ...) is Lua's assert (counted); everything else is a chain of words.
local function assert_chain(words, target, message)
    return setmetatable({}, {
        __index = function(_, key)
            local lk = lower(key)
            if lk == "spy" or lk == "stub" then
                return function(s)
                    if not T.is_spy(s) then
                        error(format("assert.%s(x): x is not a spy (did you pass the original function?)", lk), 2)
                    end
                    return assert_chain(words, s, message)
                end
            elseif lk == "message" then
                return function(m) return assert_chain(words, target, m) end
            end
            local next_words = { unpack(words) }
            for w in gmatch(lk, "[^_]+") do
                next_words[#next_words + 1] = w
            end
            return assert_chain(next_words, target, message)
        end,
        __call = function(_, ...)
            if #words == 0 and target == nil then
                count_assertion()
                return lua_assert(...)
            end
            return check(words, target, message, ...)
        end,
    })
end

assert = assert_chain({}, nil, nil)

-- assert:register("assertion", name, fn(state, arguments) -> bool, positive_template, negative_template)
-- assert:register("matcher", name, fn(state, arguments) -> function(value) -> bool)
rawset(getmetatable(assert), "__index", (function(previous)
    return function(self, key)
        if key == "register" then
            return function(_, kind, name, fn, positive, negative)
                if kind == "assertion" then
                    register(lower(name), function(state, a) return fn(state, a) end, positive or ("Expected " .. name .. " to hold for:\n%s"),
                        negative or ("Expected " .. name .. " not to hold for:\n%s"), function(a)
                            local out = {}
                            for i = 1, math.max(a.n, 1) do
                                out[i] = T.show(a[i])
                            end
                            return out
                        end)
                elseif kind == "matcher" then
                    matchers[lower(name)] = fn
                else
                    error("assert:register: kind is 'assertion' or 'matcher'", 2)
                end
            end
        end
        return previous(self, key)
    end
end)(getmetatable(assert).__index))

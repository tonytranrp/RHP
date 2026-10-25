-- Rhp::test, the Lua side, part 6: expect(), Jest-style assertions over the same checks as assert.
--   expect(x).to.equal(y)          -- deep equality (like Jest's toEqual)
--   expect(x).to.be(y)             -- the same value (==)
--   expect(x).to_not.be_nil()      expect(t).to.have_length(3)   expect(s).to.match("^id")
--   expect(fn).to.fail("message")  expect(n).to.be_near(1.0, 0.01)   expect(n).to.be_greater_than(2)
--   expect(game.spawn).to.have_been_called_with("boss")   expect(v).to.match_snapshot()
-- Filler words: to, be, been, have, has, a, an, is, that, and. Negation: to_not, not_to, never.

local T = __rhp_t
local type, select, pairs, ipairs, error, tostring, setmetatable, rawget, rawequal, getmetatable, pcall =
    type, select, pairs, ipairs, error, tostring, setmetatable, rawget, rawequal, getmetatable, pcall
local concat, unpack = table.concat, table.unpack
local format, find = string.format, string.find
local pack = T.pack

local fillers = { to = true, be = true, been = true, have = true, has = true, a = true, an = true, is = true, that = true, ["and"] = true, does = true }
local negators = { to_not = true, not_to = true, never = true, ["not"] = true }

local matchers = {}
T.expect_matchers = matchers

-- Each matcher: function(actual, ...) -> ok, describe; describe() -> positive message, negative
-- message, extra. Messages are built for a failure only: a passing expect formats nothing.
matchers.be = function(actual, expected)
    return actual == expected, function()
        return format("expected %s to be %s", T.inline(actual), T.inline(expected)), format("expected %s not to be %s", T.inline(actual), T.inline(expected)),
            { expected = T.inline(expected), actual = T.inline(actual) }
    end
end
matchers.equal = function(actual, expected)
    local ok, path = T.deep_equal(expected, actual, true)
    return ok, function()
        local where = (not ok and path and #path > 0) and format(" (first difference at %s: %s instead of %s)", T.path_text(path), T.inline(T.at_path(actual, path)), T.inline(T.at_path(expected, path))) or ""
        return format("expected %s to equal %s%s", T.inline(actual), T.inline(expected), where), format("expected %s not to equal %s", T.inline(actual), T.inline(expected)),
            { expected = T.serialize(expected), actual = T.serialize(actual) }
    end
end
matchers.equals = matchers.equal
matchers.eq = matchers.equal
matchers.same = matchers.equal

-- A matcher from a test and a phrase ("be near"): "expected 3 to be near 1, 0.5".
local function simple(test, phrase)
    return function(actual, ...)
        local args = pack(...)
        return test(actual, ...), function()
            local shown = {}
            for i = 1, args.n do
                shown[i] = T.inline(args[i])
            end
            local suffix = #shown > 0 and (" " .. concat(shown, ", ")) or ""
            return format("expected %s to %s%s", T.inline(actual), phrase, suffix), format("expected %s not to %s%s", T.inline(actual), phrase, suffix)
        end
    end
end
matchers.truthy = simple(function(v) return v ~= nil and v ~= false end, "be truthy")
matchers.be_truthy = matchers.truthy
matchers.falsy = simple(function(v) return v == nil or v == false end, "be falsy")
matchers.be_falsy = matchers.falsy
matchers.be_nil = simple(function(v) return v == nil end, "be nil")
matchers.exist = simple(function(v) return v ~= nil end, "exist")
matchers.be_true = simple(function(v) return v == true end, "be true")
matchers.be_false = simple(function(v) return v == false end, "be false")
matchers.be_a = simple(function(v, t)
    if type(t) == "table" then
        return getmetatable(v) == t
    end
    return type(v) == t or (type(v) == "number" and (t == "integer" or t == "float") and math.type(v) == t)
end, "be a")
matchers.be_an = matchers.be_a
matchers.be_near = simple(function(v, e, tol) return type(v) == "number" and v >= e - (tol or 0) and v <= e + (tol or 0) end, "be near")
matchers.be_greater_than = simple(function(v, x) return type(v) == "number" and v > x end, "be greater than")
matchers.be_less_than = simple(function(v, x) return type(v) == "number" and v < x end, "be less than")
matchers.be_at_least = simple(function(v, x) return type(v) == "number" and v >= x end, "be at least")
matchers.be_at_most = simple(function(v, x) return type(v) == "number" and v <= x end, "be at most")
matchers.match = simple(function(v, p, init, plain)
    if type(v) == "number" then
        v = tostring(v)
    end
    return type(v) == "string" and find(v, p, init, plain) ~= nil
end, "match")
matchers.contain = simple(function(v, item) return T.matchers.contains({}, pack(item))(v) end, "contain")
matchers.contains = matchers.contain
matchers.have_length = simple(function(v, n)
    if type(v) == "string" or type(v) == "table" then
        return #v == n
    end
    return false
end, "have length")
matchers.have_key = simple(function(v, k) return type(v) == "table" and v[k] ~= nil end, "have key")
matchers.satisfy = simple(function(v, m)
    if T.is_matcher(m) then
        return m(v)
    end
    return m(v) and true or false
end, "satisfy")

-- expect(fn).to.fail([message or pattern]): fn raises (an error whose message matches, if given).
matchers.fail = function(fn, expected)
    if type(fn) ~= "function" then
        return false, function() return "expected a function that raises, got " .. type(fn), "expected a function" end
    end
    local ok, err = pcall(fn)
    local text = type(err) == "table" and rawget(err, "rhp_failure") and err.message or tostring(err)
    local matched = not ok and (expected == nil or text == expected or find(text, expected, 1, true) ~= nil or find(text, expected) ~= nil)
    return matched, function()
        return ok and "expected the function to raise, but it returned" or format("expected an error matching %s, got %s", T.inline(expected), T.inline(text)),
            format("expected the function not to raise, but it raised %s", T.inline(text))
    end
end
matchers.throw = matchers.fail
matchers.raise = matchers.fail
matchers.error = matchers.fail

local function spy_or_fail(v)
    local s = T.spy_of(v)
    if not s then
        T.fail("expected a spy or stub (spy.on / stub), got " .. T.inline(v))
    end
    return s
end
matchers.have_been_called = function(v, times)
    local s = spy_or_fail(v)
    local n = #s.calls
    return (times == nil and n > 0) or n == times, function()
        return format("expected to be called %s time(s), was called %d", times == nil and ">0" or tostring(times), n),
            format("expected not to be called %s time(s), was called %d", times == nil and "any" or tostring(times), n)
    end
end
matchers.be_called = matchers.have_been_called
matchers.have_been_called_with = function(v, ...)
    local s = spy_or_fail(v)
    local args = pack(...)
    return s:called_with(...), function()
        local parts = {}
        for i = 1, args.n do
            parts[i] = T.is_matcher(args[i]) and tostring(args[i]) or T.inline(args[i])
        end
        local last = s.calls[#s.calls]
        local got = {}
        if last then
            for i = 1, last.vals.n do
                got[i] = T.inline(last.vals[i])
            end
        end
        local wanted = "(" .. concat(parts, ", ") .. ")"
        local seen = last and ("(" .. concat(got, ", ") .. ")") or "(no calls)"
        return format("expected a call with %s, last call was %s", wanted, seen), format("expected no call with %s", wanted), { expected = wanted, actual = seen }
    end
end
matchers.be_called_with = matchers.have_been_called_with

-- Short names after filler words: expect(t).to.have.length(3), expect(s).to.have.been.called_with(1).
matchers.length = matchers.have_length
matchers.key = matchers.have_key
matchers.called = matchers.have_been_called
matchers.called_with = matchers.have_been_called_with
matchers.above = matchers.be_greater_than
matchers.below = matchers.be_less_than
matchers.near = matchers.be_near

matchers.match_snapshot = function(v, name)
    local ok, positive, negative, extra = T.snapshot_check(v, name)
    return ok, function() return positive, negative, extra end
end

-- Runs matcher m on actual: raises the failure, or returns.
local function check(m, negated, actual, ...)
    T.count_assertion()
    local ok, describe = m(actual, ...)
    if (ok and true or false) == negated then
        local positive, negative, extra = describe()
        T.fail(negated and negative or positive, extra)
    end
end

-- An expectation is {actual, negated, word} with one shared metatable: a step of a chain makes one
-- small table, a matcher one closure.
local expectation_mt = {}

local function expectation(actual, negated, word)
    return setmetatable({ actual, negated, word }, expectation_mt)
end

expectation_mt.__index = function(self, key)
    local actual, negated = rawget(self, 1), rawget(self, 2) -- raw: a nil actual must not come back here
    if fillers[key] then
        return expectation(actual, negated, key)
    elseif negators[key] then
        return expectation(actual, not negated, nil)
    end
    local m = matchers[key]
    if not m then
        error(format("expect(): no matcher '%s'", tostring(key)), 2)
    end
    return function(...)
        check(m, negated, actual, ...)
        return self
    end
end

-- expect(x).to.be(y), expect(x).to.be.a("number"): the last word decides.
expectation_mt.__call = function(self, ...)
    local word = rawget(self, 3)
    local m = word == "be" and matchers.be or (word == "a" or word == "an") and matchers.be_a or nil
    if not m then
        error(format("expect(): '%s' isn't a matcher", tostring(word)), 2)
    end
    check(m, rawget(self, 2), rawget(self, 1), ...)
    return self
end

function expect(actual)
    return expectation(actual, false, nil)
end

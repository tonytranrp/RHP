-- The DSL: nesting, hooks in order, setup / teardown, finally, each, pending, skip and tags.
local log = {}
local setups = 0

describe("outer", function()
    setup(function() setups = setups + 1 log[#log + 1] = "setup outer" end)
    before_each(function() log[#log + 1] = "before outer" end)
    after_each(function() log[#log + 1] = "after outer" end)

    describe("inner", function()
        before_all(function() log[#log + 1] = "setup inner" end)
        before_each(function() log[#log + 1] = "before inner" end)
        after_each(function() log[#log + 1] = "after inner" end)

        it("hooks run outer first and setup once (ok)", function()
            assert.same({ "setup outer", "setup inner", "before outer", "before inner" }, log)
            assert.equals(1, setups)
        end)

        it("after_each runs inner first (ok)", function()
            assert.same({ "setup outer", "setup inner", "before outer", "before inner", "after inner", "after outer", "before outer", "before inner" }, log)
            assert.equals(1, setups)
        end)
    end)

    it("finally runs after the body, last first (ok)", function()
        local order = {}
        finally(function() order[#order + 1] = 1 end)
        finally(function()
            order[#order + 1] = 2
            assert.same({ 2 }, order)
        end)
    end)

    it("a failing finally fails the test (fails)", function()
        finally(function() assert.equals(1, 2) end)
    end)

    it("pending inside a body (pending)", function()
        pending("not written yet")
        error("never reached")
    end)

    pending("declared pending (pending)")

    it("no body (pending)")
end)

describe.skip("a skipped block", function()
    it("is skipped (skipped)", function() error("never runs") end)
end)

describe("each", function()
    it.each({ { 1, 2, 3 }, { 2, 3, 5 }, { -1, 1, 0 } })("%d plus %d is %d (ok)", function(a, b, sum)
        assert.equals(sum, a + b)
    end)

    it.each({ { name = "orc", hp = 5 }, { name = "elf", hp = 7 } })("$name has hp (ok)", function(case)
        assert.is_number(case.hp)
    end)

    it.each({ "a", "b" })("case %# is %s (ok)", function(v)
        assert.is_string(v)
    end)

    describe.each({ { 10 }, { 20 } })("block %d", function(n)
        it("gets its value (ok)", function()
            assert.is_true(n == 10 or n == 20)
        end)
    end)
end)

describe("tags", function()
    it("a #slow test (ok)", function() end)
    it("a #slow #net test (ok)", function() end)
end)

describe("a failing before_each", function()
    before_each(function() error("before broke") end)
    after_each(function() log[#log + 1] = "after still runs" end)
    it("errors the test (errors)", function() end)
end)

describe("a failing setup", function()
    setup(function() error("setup broke") end)
    it("errors every test of the block (errors)", function() end)
    it("this one too (errors)", function() end)
end)

it("hooks can't be declared inside a test (errors)", function()
    before_each(function() end)
end)

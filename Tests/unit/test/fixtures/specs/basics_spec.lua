-- Known outcomes: 5 passed, 2 failed, 1 error, 1 pending, 1 skipped.
local combat = require("game.combat")

describe("damage", function()
    it("subtracts armor", function()
        assert.equals(7, combat.damage(10, 3))
    end)

    it("never goes below zero", function()
        expect(combat.damage(2, 5)).to.equal(0)
    end)

    it("fails on purpose", function()
        assert.equals(8, combat.damage(10, 3)) -- line 14
    end)

    it("fails a deep comparison", function()
        assert.same({ a = 1, b = { c = 2 } }, { a = 1, b = { c = 3 } }) -- line 18
    end)

    it("errors on purpose", function()
        local t = nil
        return t.field -- line 23
    end)

    it("is pending")

    it.skip("is skipped", function()
        error("never runs")
    end)
end)

describe("hooks", function()
    local log = {}
    before_each(function() log[#log + 1] = "before" end)
    after_each(function() log[#log + 1] = "after" end)

    it("runs before_each first", function()
        assert.same({ "before" }, log)
    end)

    it("ran after_each after the first test", function()
        assert.same({ "before", "after", "before" }, log)
    end)
end)

it("handles tables and strings #fast", function()
    assert.is_true(true)
    assert.is_not.equal(1, 2)
    assert.matches("^uni", "unit1")
    assert.has_error(function() error("boom") end, "boom")
    assert.has_no.errors(function() end)
    expect({ 1, 2, 3 }).to.have_length(3)
    expect("hello").to.contain("ell")
end)

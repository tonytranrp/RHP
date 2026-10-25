-- Measuring: test.measure, test.bench, budgets, leaks and the per-test cost.
local combat = require("game.combat")

describe("measure", function()
    it("measure counts instructions and memory (ok)", function()
        local small = test.measure(function() return combat.sum(10) end, { name = "sum 10" })
        local big = test.measure(function() return combat.sum(1000) end, { name = "sum 1000" })
        assert.is_true(big.instructions > small.instructions * 20)
        assert.equals(55, small.results[1])
        combat.big_list(100) -- warm up: the string table grows once
        local list = test.measure(function() combat.big_list(100) end)
        assert.is_true(list.bytes > 100 * 40)
        assert.is_true(list.allocations >= 100)
        assert.is_true(list.objects.table >= 101)
        assert.equals(0, list.retained)
        assert.equals(0, small.bytes)
        assert.equals(0, small.retained)
        local kept
        local held = test.measure(function() kept = combat.big_list(100) end)
        assert.is_true(held.retained > 100 * 40)
        assert.is_table(kept)
    end)

    it("bench reports statistics (ok)", function()
        local b = test.bench("sum", function() combat.sum(100) end, { runs = 10 })
        assert.equals(10, b.runs)
        assert.equals(b.instructions.min, b.instructions.max)
        assert.is_true(b.time_ms.median >= 0)
    end)

    it("within budget (ok)", function()
        test.budget({ instructions = 100000, memory = 1024 * 1024 })
        combat.sum(100)
    end)

    it("over the instruction budget (fails)", function()
        test.budget({ instructions = 1000 })
        combat.sum(10000)
    end)

    it("expect_budget (fails)", function()
        test.expect_budget(function() combat.big_list(1000) end, { bytes = 1024 })
    end)

    it("measuring something small keeps the test's own peak (fails)", function()
        test.budget({ memory = 64 * 1024 })
        local big = combat.big_list(2000) -- far over 64 KiB
        big = nil
        test.gc()
        test.measure(function() return combat.sum(10) end)
    end)

    it("a global left behind is removed (ok)", function()
        leaked_global = 1
    end)

    it("an irreversible effect with expect_undone (errors)", function()
        test.expect_undone()
        arena.wipe()
    end)

    it("a limit stops a runaway test (errors)", function()
        while true do end
    end)
end)

-- A test stopped by a limit still gets its cleanup: finally, after_each, its globals removed.
local log = {}

describe("aborted", function()
    after_each(function() log[#log + 1] = "after_each" end)

    it("runs away (errors)", function()
        finally(function() log[#log + 1] = "finally" end)
        runaway_global = true
        while true do end
    end)

    it("was cleaned up after (ok)", function()
        assert.is_nil(runaway_global)
        assert.same({ "finally", "after_each" }, log)
    end)
end)

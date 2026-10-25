-- Snapshots. VALUE is replaced by the C++ test between runs.
local combat = require("game.combat")

describe("snapshot", function()
    it("a table (ok)", function()
        assert.snapshot({ list = combat.big_list(2), total = combat.sum(4), note = "line one\nline two" })
    end)

    it("awkward strings and keys read back (ok)", function()
        assert.snapshot({ ["end"] = 1, ["a\nb"] = "x]", tail = "line\n]", deep = "]]", ["[x]"] = "\r\n" }, "awkward")
    end)

    it("named snapshots and expect (ok)", function()
        expect(VALUE).to.match_snapshot("value")
        assert.snapshot(combat.damage(10, 3), "damage")
    end)
end)

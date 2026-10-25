local combat = require("game.combat")
local util = require("game.util")

it("calls some functions", function()
    combat.big_list(3)
    combat.damage(5, 1)
    util.used()
end)

it("spends time in sum", function()
    combat.sum(200000)
end)

-- Module state between tests: shared per file (isolation file), fresh per test (isolation test).
local combat = require("game.combat")

it("first sets module state", function()
    combat.set_rounds(5)
    arena.spawn("orc", 1)
end)

it("second reads the module state", function()
    assert.equals(0, arena.count()) -- lib effects are always undone
    assert.equals(5, combat.rounds)
end)

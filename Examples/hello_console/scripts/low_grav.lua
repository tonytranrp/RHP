-- low_grav: lowers gravity, spawns two entities and doubles combat damage.
-- Everything it does is journaled, so reverting the module undoes all of it.
local M = {}

game.gravity = -1.6

local first = game.spawn(0, 10)
local second = game.spawn(5, 10)
print("spawned " .. tostring(first) .. " and " .. tostring(second) .. ", " .. game.count() .. " alive")

rhp.patch("combat.damage", function(original, base, mult)
    return original(base, mult) * 2
end)

function M.on_load()
    print("low gravity on: " .. game.gravity)
end

-- Exported: callable from C++ with box.call(mod, "boost", n).
function M.boost(n)
    return n * game.count()
end

return M

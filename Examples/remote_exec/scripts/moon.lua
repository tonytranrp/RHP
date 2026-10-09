-- tuning.moon: moon gravity for as long as this module is loaded (or its session lives).
local M = {}

function M.on_load()
    print("moon gravity on: " .. game.gravity)
end

function M.on_unload()
    print("moon gravity off")
end

game.gravity = -1.6

return M

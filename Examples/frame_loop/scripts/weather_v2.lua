-- weather, revised: stronger gusts every 5 frames. on_restore picks up the old gust count, so a
-- reload doesn't reset the module's state.
local M = { gusts = 0 }

local function gust_loop()
    while true do
        rhp.wait(5)
        M.gusts = M.gusts + 1
        game.wind = math.sin(M.gusts) * 9
        rhp.emit({ gust = M.gusts, wind = game.wind })
    end
end

rhp.timer(0, gust_loop)

rhp.on("game.goal", function(frame)
    game.score = game.score + 1
    print("goal at frame " .. frame .. ", score " .. game.score .. " (v2)")
end)

function M.gust_count() return M.gusts end

function M.on_save() return M.gusts end

function M.on_restore(saved)
    M.gusts = saved or 0
    print("weather v2 resumed at " .. M.gusts .. " gusts")
end

return M

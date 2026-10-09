-- weather: changes the wind every 10 frames, forever, without ever blocking a frame.
-- The loop runs as its own request (started by a timer) and sleeps between gusts.
local M = { gusts = 0 }

local function gust_loop()
    while true do
        rhp.wait(10)
        M.gusts = M.gusts + 1
        game.wind = math.sin(M.gusts) * 5
        rhp.emit({ gust = M.gusts, wind = game.wind })
    end
end

rhp.timer(0, gust_loop)

rhp.on("game.goal", function(frame)
    game.score = game.score + 1
    print("goal at frame " .. frame .. ", score " .. game.score)
end)

function M.gust_count() return M.gusts end

-- Called on the old revision when this module is reloaded; the new one gets the result.
function M.on_save() return M.gusts end

return M

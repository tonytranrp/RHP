-- A module under test: uses the `arena` lib (installed by the test runner) and the rhp API.
local M = {}

M.rounds = 0

function M.damage(base, armor)
    if armor >= base then
        return 0
    end
    return base - armor
end

function M.start()
    M.rounds = 0
    M.timer = rhp.every(1000, function()
        M.rounds = M.rounds + 1
        if M.rounds == 3 then
            arena.spawn("boss", 3)
        end
    end)
end

function M.stop()
    if M.timer then
        rhp.off(M.timer)
        M.timer = nil
    end
end

function M.set_rounds(n)
    M.rounds = n
end

function M.big_list(n)
    local t = {}
    for i = 1, n do
        t[i] = { id = i, name = "unit" .. i }
    end
    return t
end

function M.sum(n)
    local s = 0
    for i = 1, n do
        s = s + i
    end
    return s
end

return M

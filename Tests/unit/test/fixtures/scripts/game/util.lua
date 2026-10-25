-- Coverage exclusions.
local M = {}

function M.used()
    return 1
end

-- rhp: coverage off
function M.debug_only()
    return 2
end
-- rhp: coverage on

-- luacov: disable
function M.also_excluded()
    return 3
end
-- luacov: enable

function M.never()
    return 4
end

return M

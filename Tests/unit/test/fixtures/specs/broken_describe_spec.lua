-- A describe body that raises: a file error; the tests declared before it still run.
it("declared before (ok)", function() end)
describe("broken", function()
    local x = nil
    x.y = 1
end)

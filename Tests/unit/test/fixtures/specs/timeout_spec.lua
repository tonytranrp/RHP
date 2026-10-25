-- Stopped by the real-time limit (no instruction limit here).
it("spins forever", function()
    while true do end
end)
it("still runs after the spinner", function() end)
it("waits on frames forever", function()
    while true do rhp.wait(1) end
end)

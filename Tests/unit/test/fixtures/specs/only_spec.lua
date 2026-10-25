-- .only: the file's other tests are skipped.
it("left out (skipped)", function() error("never runs") end)
it.only("selected (ok)", function() end)
describe.only("a selected block", function()
    it("runs (ok)", function() end)
end)
describe("another block", function()
    it("left out too (skipped)", function() error("never runs") end)
end)

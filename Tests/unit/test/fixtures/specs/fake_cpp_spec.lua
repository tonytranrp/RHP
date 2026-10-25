-- Rhp::test::fake<L>: the real lib's shape, recorders behind it. Every test name ends with its outcome.
describe("fake<L>", function()
    it("calls are recorded with their arguments (ok)", function()
        assert.equals(0, arena.spawn("orc", 2))
        assert.same({ { "orc", 2 } }, fake.calls("arena.spawn"))
    end)

    it("fake.returns sets results (ok)", function()
        fake.returns("arena.spawn", 5)
        assert.equals(5, arena.spawn("orc", 2))
    end)

    it("variables have storage (ok)", function()
        arena.gravity = 2.5
        assert.equals(2.5, arena.gravity)
    end)

    it("handles work (ok)", function()
        local u = arena.make(1)
        assert.equals(0, u:move(3))
        assert.equals(0, u.x)
        assert.equals(1, #fake.calls("unit:move"))
    end)

    it("the lib can still be stubbed (ok)", function()
        stub(arena, "count").returns(3)
        assert.equals(3, arena.count())
    end)
end)

describe("fake<L> configured from C++", function()
    it("keeps results set before the run (ok)", function()
        assert.equals(42, arena.count())
    end)
end)

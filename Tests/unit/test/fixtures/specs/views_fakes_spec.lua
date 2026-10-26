-- Libs with typed views and struct views, faked from an API description (no real lib installed).

describe("described views", function()
    it("fake view bindings return empty spans nil and default objects (ok)", function()
        local samples = fviews.samples()
        assert.equals(0, #samples)
        assert.is_nil(fviews.find(1))
        local p = fviews.main()
        assert.equals(0, p.x)
        p.y = 5
        assert.equals(5, p.y)
        assert.equals(0, fviews.main().y) -- every call returns a fresh default object
    end)

    it("fake view parameters are not type checked beyond their description (ok)", function()
        assert.equals(0, fviews.total({ 1, 2 }))
    end)
end)

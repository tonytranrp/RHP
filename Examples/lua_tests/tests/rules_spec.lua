-- shop.rules against the real `shop` bindings (installed by the test executable).
local rules = require("shop.rules")

describe("total", function()
    it("adds the prices of a basket", function()
        assert.equals(135, rules.total({ "sword", "potion" }))
    end)

    it("applies the discount", function()
        shop.discount = 0.5 -- undone when the test ends
        expect(rules.total({ "sword" })).to.equal(60)
    end)

    it("refuses a discount out of its range", function()
        expect(function() shop.discount = 0.9 end).to.fail("out_of_range")
    end)

    it.each({ { "sword", 120 }, { "shield", 80 }, { "unknown", 0 } })("prices %s at %d", function(item, cost)
        assert.equals(cost, shop.price(item))
    end)
end)

describe("checkout", function()
    it("charges the customer", function()
        local c = shop.visit(200)
        assert.is_true(rules.checkout(c, { "sword" }))
        assert.equals(80, c.gold)
    end)

    it("refuses a customer without the gold", function()
        local c = shop.visit(10)
        local ok, why = rules.checkout(c, { "sword" })
        assert.is_false(ok)
        assert.equals("not enough gold", why)
        assert.equals(10, c.gold)
    end)

    it("publishes each sale", function()
        local sold = {}
        rhp.on("shop.sold", function(cost) sold[#sold + 1] = cost end)
        rules.checkout(shop.visit(500), { "shield", "potion" })
        test.frames(2)
        assert.same({ 95 }, sold)
    end)

    it("can be checked with a stubbed price list", function()
        stub(shop, "price").returns(1)
        assert.equals(3, rules.total({ "a", "b", "c" }))
        assert.stub(shop.price).was.called(3)
    end)
end)

describe("properties", function()
    it.property("a total is never negative or above the sum of prices",
        { gen.list(gen.element({ "sword", "shield", "potion" }), { max = 8 }), gen.number(0, 0.5) },
        function(basket, discount)
            shop.discount = discount
            local full = 0
            for _, item in ipairs(basket) do
                full = full + shop.price(item)
            end
            local t = rules.total(basket)
            return t >= 0 and t <= full
        end)
end)

describe("cost", function()
    it("checks out a big basket within its budget", function()
        local basket = {}
        for i = 1, 200 do
            basket[i] = "potion"
        end
        local m = test.expect_budget(function() rules.total(basket) end, { instructions = 5000, bytes = 1024 })
        assert.is_true(m.instructions > 0)
    end)
end)

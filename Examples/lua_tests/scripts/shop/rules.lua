-- shop.rules: pricing and sales, written against the `shop` lib the game installs.
local M = {}

M.sales = 0

-- The price of a basket ({"sword", "potion", ...}) after the current discount, rounded down.
function M.total(basket)
    local sum = 0
    for _, item in ipairs(basket) do
        sum = sum + shop.price(item)
    end
    return math.floor(sum * (1 - shop.discount))
end

-- Charges a customer for a basket. Returns true, or false and why.
function M.checkout(customer, basket)
    local cost = M.total(basket)
    if customer.gold < cost then
        return false, "not enough gold"
    end
    customer:pay(cost)
    M.sales = M.sales + 1
    rhp.publish("shop.sold", cost)
    return true
end

-- Happy hour: a discount every `period_ms`, for `length_ms`.
function M.happy_hours(period_ms, length_ms, discount)
    return rhp.every(period_ms, function()
        shop.discount = discount
        rhp.after(length_ms, function()
            shop.discount = 0
        end)
    end)
end

-- The game says the shop opened: greet in the log.
rhp.on("shop.opened", function(day)
    print("the shop opens, day " .. day)
end)

return M

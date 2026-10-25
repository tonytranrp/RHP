-- Property-based tests: generators, shrinking, reproducible seeds.
local combat = require("game.combat")

describe("property", function()
    it("damage is never negative (ok)", function()
        test.property({ gen.int(0, 1000), gen.int(0, 1000) }, function(base, armor)
            assert.is_true(combat.damage(base, armor) >= 0)
        end)
    end)

    it.property("sum matches the formula (ok)", { gen.int(0, 200) }, function(n)
        return combat.sum(n) == n * (n + 1) // 2
    end)

    it("generators make what they say (ok)", function()
        test.property({
            gen.string({ max = 10 }),
            gen.list(gen.bool(), { min = 1, max = 5 }),
            gen.record({ id = gen.int(1, 9), tag = gen.element({ "a", "b" }) }),
            gen.one_of(gen.constant("x"), gen.int(1, 3)),
            gen.optional(gen.number(0, 1)),
            gen.tuple(gen.int(), gen.string()),
            gen.map(gen.int(1, 5), function(n) return n * 10 end),
            gen.table(gen.string({ min = 1, max = 3 }), gen.int(), { max = 4 }),
            gen.frequency({ 1, gen.constant(1) }, { 3, gen.constant(2) }),
            gen.int(1, 100):filter(function(n) return n % 2 == 0 end),
        }, function(s, list, rec, one, opt, tuple, tens, map, freq, even)
            assert.is_string(s)
            assert.is_true(#s <= 10)
            assert.is_true(#list >= 1 and #list <= 5)
            assert.is_true(rec.id >= 1 and rec.id <= 9 and (rec.tag == "a" or rec.tag == "b"))
            assert.is_true(one == "x" or (one >= 1 and one <= 3))
            assert.is_true(opt == nil or (opt >= 0 and opt <= 1))
            assert.is_number(tuple[1])
            assert.is_string(tuple[2])
            assert.is_true(tens % 10 == 0)
            assert.is_table(map)
            assert.is_true(freq == 1 or freq == 2)
            assert.equals(0, even % 2)
        end, { runs = 200 })
    end)

    it("a failing property shrinks to the smallest case (fails)", function()
        test.property({ gen.int(0, 1000) }, function(n)
            assert.is_true(n < 50)
        end)
    end)

    it("a failing negative property shrinks and ends (fails)", function()
        test.property({ gen.int(-1000, -1) }, function(n)
            assert.is_true(n > -5)
        end)
    end)

    it("one_of shrinks values of either kind (fails)", function()
        test.property({ gen.one_of(gen.constant("x"), gen.int(1, 3)) }, function(v)
            return v ~= "x"
        end)
    end)

    it("optional shrinks to nil (fails)", function()
        test.property({ gen.optional(gen.int(1, 100)) }, function(v)
            return v ~= nil and v < 0
        end)
    end)

    it("a failing list property shrinks the list (fails)", function()
        test.property({ gen.list(gen.int(0, 100)) }, function(list)
            local total = 0
            for _, v in ipairs(list) do
                total = total + v
            end
            return total < 100
        end)
    end)
end)

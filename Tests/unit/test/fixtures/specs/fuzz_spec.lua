-- Fuzzing: a crash is found, shrunk and saved; saved inputs run first next time.
local function parse(s)
    if #s >= 3 and s:find("x", 1, true) then
        local t = nil
        return t.boom
    end
    return #s
end

describe("fuzz", function()
    it("a robust function survives (ok)", function()
        test.fuzz(function(s) return #s end, { gen = gen.string({ max = 50 }), runs = 300 })
    end)

    it("finds a crash with the default generator (fails)", function()
        test.fuzz(function(v)
            if type(v) == "string" and #v > 3 then
                error("too long")
            end
        end, { runs = 2000 })
    end)

    it("finds the crash (fails)", function()
        test.fuzz(parse, { gen = gen.string({ max = 20, chars = "abx" }), runs = 2000 })
    end)
end)

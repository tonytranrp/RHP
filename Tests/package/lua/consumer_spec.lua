-- A Lua test through an installed RHP: rhp_add_lua_tests, Rhp::test::main and the consumer's lib.
it("the consumer's lib is installed", function()
    assert.equals(42, consumer.answer())
end)

-- Two tests with the same full name store snapshots under the same key: the second one is refused.
it("same name", function()
    assert.snapshot("first")
end)

it("same name", function()
    assert.snapshot("second")
end)

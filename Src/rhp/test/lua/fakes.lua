-- Rhp::test, the Lua side, part 8: fake libs built from an API description (sandbox::api, rhp.api(),
-- rhp-cli test --api file.json), for tests that run without the real program. Every function records
-- its calls and returns a default of its declared type (or what fake.returns gave, or what a stub
-- replaces it with); variables keep their values and check writes like the real ones (writable,
-- range); handles are tables with the methods and properties of their type. Strict fakes raise
-- "not mocked: game.spawn(...)" for a call nothing configured.

local T = __rhp_t
local bridge = T.bridge
local type, select, pairs, ipairs, error, tostring, setmetatable, rawget, rawset, tonumber =
    type, select, pairs, ipairs, error, tostring, setmetatable, rawget, rawset, tonumber
local concat, unpack = table.concat, table.unpack
local format, find, sub = string.format, string.find, string.sub
local mtype = math.type
local pack = T.pack

local registry = { calls = {}, returns = {}, functions = {} }
T.described_fake = registry

function registry.reset(path)
    if path == nil then
        for k in pairs(registry.calls) do
            registry.calls[k] = {}
        end
        registry.returns = {}
        return
    end
    registry.calls[path] = {}
    registry.returns[path] = nil
end

-- Every test starts with no recorded calls and no configured results, and the variables of fake
-- libs go back to what they were before it when it ends (a real lib's writes are journaled).
local var_stores = {} -- the `values` table of every fake lib
local saved_vars = {}

T.before_test = function()
    registry.reset()
    for i = 1, #var_stores do
        local copy = {}
        for k, v in pairs(var_stores[i]) do
            copy[k] = v
        end
        saved_vars[i] = copy
    end
end

T.after_test = function()
    for i = 1, #var_stores do
        local store, saved = var_stores[i], saved_vars[i]
        if saved then
            for k in pairs(store) do
                store[k] = nil
            end
            for k, v in pairs(saved) do
                store[k] = v
            end
        end
    end
end

local handle_types = {} -- name -> {methods = table, properties = {name = type}, next_id = n}

local function default_of(type_name)
    if type_name == nil then
        return nil
    end
    local optional = sub(type_name, -1) == "?"
    if optional then
        return nil
    end
    if type_name == "integer" then
        return 0
    elseif type_name == "number" then
        return 0.0
    elseif type_name == "string" then
        return ""
    elseif type_name == "boolean" then
        return false
    end
    local h = handle_types[type_name]
    if h then
        return h.new()
    end
    return nil
end

local function check_type(type_name, v)
    if type_name == nil or type_name == "any" then
        return true
    end
    if sub(type_name, -1) == "?" then
        if v == nil then
            return true
        end
        type_name = sub(type_name, 1, -2)
    end
    if type_name == "integer" then
        return mtype(v) == "integer" or (mtype(v) == "float" and v == v // 1)
    elseif type_name == "number" then
        return type(v) == "number"
    elseif type_name == "string" then
        return type(v) == "string"
    elseif type_name == "boolean" then
        return type(v) == "boolean"
    end
    if handle_types[type_name] then
        return type(v) == "table" and rawget(v, "__rhp_fake_type") == type_name
    end
    return true
end

local function fake_function(path, desc, strict, self_type)
    registry.calls[path] = {}
    registry.functions[path] = desc
    local params = desc.params or {}
    local returns = desc.returns or {}
    return function(...)
        local args = pack(...)
        local first = 1
        if self_type then
            first = 2 -- a method: the handle itself
        end
        for i = 1, #params do
            local v = args[i + first - 1]
            if not check_type(params[i], v) then
                error(format("%s: argument %d: expected %s, got %s", path, i, params[i], type(v)), 2)
            end
        end
        local calls = registry.calls[path]
        local count = args.n - first + 1
        local recorded = {} -- the arguments as a plain list, as fake<L> records them
        for i = first, args.n do
            recorded[i - first + 1] = args[i]
        end
        calls[#calls + 1] = recorded
        local configured = registry.returns[path]
        if configured then
            return unpack(configured, 1, configured.n)
        end
        if strict then
            local shown = {}
            for i = 1, count do
                shown[i] = T.inline(recorded[i])
            end
            error(format("not mocked: %s(%s)", path, concat(shown, ", ")), 2)
        end
        local out = {}
        for i = 1, #returns do
            out[i] = default_of(returns[i])
        end
        return unpack(out, 1, #returns)
    end
end

local function define_handle(desc, strict, prefix)
    local name = desc.name
    local methods = {}
    local properties = {}
    for _, m in ipairs(desc.methods or {}) do
        methods[m.name] = fake_function(name .. ":" .. m.name, m, strict, name)
    end
    for _, p in ipairs(desc.properties or {}) do
        properties[p.name] = p.type
    end
    local mt = {
        __name = name,
        __rhp_fake_handle = methods,
        __index = function(self, key)
            local m = methods[key]
            if m ~= nil then
                return m
            end
            if properties[key] ~= nil then
                local values = rawget(self, "__rhp_properties")
                local v = values[key]
                if v == nil then
                    return default_of(properties[key])
                end
                return v
            end
            return nil
        end,
        __newindex = function(self, key)
            error(format("%s.%s is read-only (a handle's members are set in C++)", name, tostring(key)), 2)
        end,
        __tostring = function(self) return format("%s: %d", name, rawget(self, "__rhp_fake_id")) end,
        __eq = function(a, b) return rawget(a, "__rhp_fake_type") == rawget(b, "__rhp_fake_type") and rawget(a, "__rhp_fake_id") == rawget(b, "__rhp_fake_id") end,
    }
    local h = { methods = methods, properties = properties, next_id = 0, metatable = mt }
    function h.new(values)
        h.next_id = h.next_id + 1
        return setmetatable({ __rhp_fake_type = name, __rhp_fake_id = h.next_id, __rhp_properties = values or {} }, mt)
    end
    handle_types[name] = h
    return h
end

-- fake.handle("entity", {hp = 10}): a fake handle of a described type, with property values.
function fake.handle(type_name, values)
    local h = handle_types[type_name]
    if not h then
        error(format("no fake handle type '%s'", tostring(type_name)), 2)
    end
    return h.new(values)
end

local function build_lib(desc, strict)
    local path = desc.path or desc.name
    local members = {}
    local variables = {}
    local values = {}
    for _, f in ipairs(desc.functions or {}) do
        members[f.name] = fake_function(path .. "." .. f.name, f, strict)
    end
    var_stores[#var_stores + 1] = values
    for _, v in ipairs(desc.variables or {}) do
        variables[v.name] = v
        local initial = v.min ~= nil and (v.type == "integer" and v.min // 1 or v.min) or default_of(v.type)
        values[v.name] = initial
    end
    for _, sub_lib in ipairs(desc.libs or {}) do
        members[sub_lib.name] = build_lib(sub_lib, strict)
    end
    return setmetatable(members, {
        __name = "fake lib " .. path,
        __index = function(_, key)
            if variables[key] then
                return values[key]
            end
            return nil
        end,
        __newindex = function(self, key, v)
            local var = variables[key]
            if not var then
                error(format("%s.%s is not writable", path, tostring(key)), 2)
            end
            if not var.writable then
                error(format("%s.%s is read-only", path, tostring(key)), 2)
            end
            if not check_type(var.type, v) then
                error(format("%s.%s: expected %s, got %s", path, key, var.type, type(v)), 2)
            end
            if var.min ~= nil and (v ~= v or v < var.min or v > var.max) then
                error(format("[out_of_range] %s.%s: %s is outside [%s, %s]", path, key, tostring(v), tostring(var.min), tostring(var.max)), 2)
            end
            values[key] = v
        end,
        __tostring = function() return "lib: " .. path end,
    })
end

-- Installs a fake lib for every lib of an API description, as globals every module sees.
function T.install_fakes(api, opts)
    opts = opts or {}
    local strict = opts.strict or false
    local libs = api.libs or {}
    -- Handle types first: functions may return them.
    local function handles_of(desc)
        for _, h in ipairs(desc.handles or {}) do
            define_handle(h, strict)
        end
        for _, s in ipairs(desc.libs or {}) do
            handles_of(s)
        end
    end
    for _, lib in ipairs(libs) do
        handles_of(lib)
    end
    local installed = {}
    for _, lib in ipairs(libs) do
        bridge.set_global(lib.name, build_lib(lib, strict))
        installed[#installed + 1] = lib.name
    end
    return installed
end

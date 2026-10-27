-- Rhp::test, the Lua side, part 2: showing values (luassert's style), deep comparison with the path to
-- the first difference, and the stable serializer snapshots use.

local T = __rhp_t
local type, ipairs, next, tostring, getmetatable, rawget, rawequal =
    type, ipairs, next, tostring, getmetatable, rawget, rawequal
local concat, sort, insert = table.concat, table.sort, table.insert
local format, rep, gsub, find, sub = string.format, string.rep, string.gsub, string.find, string.sub
local mtype = math.type

T.table_depth = 3 -- levels of a table shown in failure messages

-- A key's sort rank: array part first, then numbers, booleans, strings, then everything else.
local type_rank = { number = 1, boolean = 2, string = 3, table = 4, ["function"] = 5, userdata = 6, thread = 7 }

local function key_less(a, b)
    local ta, tb = type(a), type(b)
    if ta ~= tb then
        return (type_rank[ta] or 9) < (type_rank[tb] or 9)
    end
    if ta == "number" or ta == "string" then
        return a < b
    end
    if ta == "boolean" then
        return a and not b
    end
    return tostring(a) < tostring(b)
end
T.key_less = key_less

local function sorted_keys(t)
    local keys = {}
    for k in next, t do
        keys[#keys + 1] = k
    end
    sort(keys, key_less)
    return keys
end

local function quote(s)
    return "'" .. gsub(s, "[%c\\']", function(c)
        if c == "\n" then
            return "\\n"
        elseif c == "\t" then
            return "\\t"
        elseif c == "\r" then
            return "\\r"
        elseif c == "\\" then
            return "\\\\"
        elseif c == "'" then
            return "\\'"
        end
        return format("\\%03d", c:byte())
    end) .. "'"
end

local function number_text(n)
    if mtype(n) == "integer" then
        return format("%d", n)
    end
    if n ~= n then
        return "nan"
    elseif n == math.huge then
        return "inf"
    elseif n == -math.huge then
        return "-inf"
    end
    local s = format("%.17g", n)
    if tonumber(format("%.15g", n)) == n then
        s = format("%.15g", n) -- the shortest of the usual forms that reads back the same
    end
    if not find(s, "[%.eEn]") then
        s = s .. ".0"
    end
    return s
end
T.number_text = number_text

local function plain_tostring(v)
    local mt = getmetatable(v)
    if type(v) == "table" and type(mt) == "table" and rawget(mt, "__tostring") then
        return "table"
    end
    return tostring(v)
end

-- One value on one line: 5, 0.5, 'text', {1, 2, a = 3}, function: 0x..., lib: game.
local function inline(v, depth, seen)
    local t = type(v)
    if t == "string" then
        return quote(v)
    elseif t == "number" then
        return number_text(v)
    elseif t ~= "table" then
        return tostring(v)
    end
    seen = seen or {}
    if seen[v] then
        return "{...recursive}"
    end
    depth = depth or 0
    if depth >= T.table_depth then
        return "{...}"
    end
    seen[v] = true
    local parts = {}
    local n = #v
    for i = 1, n do
        parts[#parts + 1] = inline(v[i], depth + 1, seen)
    end
    for _, k in ipairs(sorted_keys(v)) do
        if not (mtype(k) == "integer" and k >= 1 and k <= n) then
            local key = type(k) == "string" and find(k, "^[%a_][%w_]*$") and k or ("[" .. inline(k, depth + 1, seen) .. "]")
            parts[#parts + 1] = key .. " = " .. inline(v[k], depth + 1, seen)
        end
    end
    seen[v] = nil
    return "{" .. concat(parts, ", ") .. "}"
end
T.inline = function(v) return inline(v) end

-- luassert's formatter: "(number) 5", "(string) 'x'", tables over several lines with `*` marking
-- the key on the path to a difference (`crumbs`, outermost key first).
local function show(v, crumbs, depth, seen, indent)
    local t = type(v)
    if t == "nil" then
        return "(nil)"
    elseif t == "boolean" then
        return "(boolean) " .. tostring(v)
    elseif t == "number" then
        return "(number) " .. number_text(v)
    elseif t == "string" then
        return "(string) " .. quote(v)
    elseif t ~= "table" then
        return "(" .. t .. ") " .. tostring(v)
    end
    depth = depth or 0
    indent = indent or ""
    seen = seen or {}
    local head = "(" .. plain_tostring(v) .. ") "
    if seen[v] then
        return head .. "{ ... recursive }"
    end
    local keys = sorted_keys(v)
    if #keys == 0 then
        return head .. "{ }"
    end
    if depth >= T.table_depth then
        return head .. "{ ... more }"
    end
    seen[v] = true
    local lines = {}
    local marked = crumbs and crumbs[depth + 1]
    for _, k in ipairs(keys) do
        local here = marked ~= nil and rawequal(k, marked)
        local key = type(k) == "string" and k or inline(k)
        local value = show(v[k], here and crumbs or nil, depth + 1, seen, indent .. "  ")
        lines[#lines + 1] = (here and (indent .. " *") or (indent .. "  ")) .. "[" .. key .. "] = " .. value
    end
    seen[v] = nil
    return head .. "{\n" .. concat(lines, "\n") .. " }"
end
T.show = function(v, crumbs) return show(v, crumbs) end

-- Deep equality, luassert's rules: values compare with ==, tables key by key (metatables ignored at
-- the top level, __eq used below when both tables share one), cycles allowed. Returns true, or false
-- and the path to the first difference (outermost key first).
local function deep_equal(a, b, ignore_mt, visited)
    if rawequal(a, b) then
        return true
    end
    if T.is_matcher and T.is_matcher(a) then -- a matcher on the expected side (match._, match.is_number() ...)
        return a(b) and true or false, {}
    end
    if type(a) ~= "table" or type(b) ~= "table" then
        return a == b, {}
    end
    local mt_a, mt_b = getmetatable(a), getmetatable(b)
    if not ignore_mt and mt_a ~= nil and mt_a == mt_b and type(mt_a) == "table" and rawget(mt_a, "__eq") then
        return a == b, {}
    end
    visited = visited or {}
    visited[a] = visited[a] or {}
    if visited[a][b] then
        return true -- already being compared further up
    end
    visited[a][b] = true
    for k, va in next, a do
        local vb = b[k]
        if vb == nil and va ~= nil and not (T.is_matcher and T.is_matcher(va)) then
            return false, { k }
        end
        local same, path = deep_equal(va, vb, false, visited)
        if not same then
            insert(path, 1, k)
            return false, path
        end
    end
    for k, vb in next, b do
        if a[k] == nil and vb ~= nil then
            return false, { k }
        end
    end
    return true
end
T.deep_equal = deep_equal

-- "a.b[2]" from a path.
function T.path_text(path)
    local out = {}
    for i = 1, #path do
        local k = path[i]
        if type(k) == "string" and find(k, "^[%a_][%w_]*$") then
            out[#out + 1] = (i == 1 and "" or ".") .. k
        else
            out[#out + 1] = "[" .. inline(k) .. "]"
        end
    end
    return concat(out)
end

-- The value at a path (nil when a step is missing).
function T.at_path(v, path)
    for i = 1, #path do
        if type(v) ~= "table" then
            return nil
        end
        v = v[path[i]]
    end
    return v
end

-- ---- the snapshot serializer ------------------------------------------------------------------------

-- Lua source that reads back as the same plain value: tables with sorted keys, one entry per line,
-- strings in long brackets when they hold newlines. Functions, userdata and threads become their
-- type name in angle brackets (a string), cycles "<cycle>".
local function long_string(s)
    local level = 0
    -- Neither "]=*]" inside nor a "]=*" at the end (it would close the bracket early).
    while find(s, "]" .. rep("=", level) .. "]", 1, true) or sub(s, -(level + 1)) == "]" .. rep("=", level) do
        level = level + 1
    end
    local eq = rep("=", level)
    local lead = sub(s, 1, 1) == "\n" and "\n" or ""
    return "[" .. eq .. "[" .. lead .. s .. "]" .. eq .. "]"
end

-- Names that can't be bare keys.
local keywords = {}
for w in ("and break do else elseif end false for function global goto if in local nil not or repeat return then true until while"):gmatch("%a+") do
    keywords[w] = true
end

local function serialize(v, indent, seen)
    local t = type(v)
    if t == "nil" then
        return "nil"
    elseif t == "boolean" then
        return tostring(v)
    elseif t == "number" then
        if v ~= v then
            return "0/0"
        elseif v == math.huge then
            return "math.huge"
        elseif v == -math.huge then
            return "-math.huge"
        end
        return number_text(v)
    elseif t == "string" then
        if find(v, "\n", 1, true) and not find(v, "\r", 1, true) then
            return long_string(v)
        end
        return format("%q", v)
    elseif t ~= "table" then
        return format("%q", "<" .. t .. ">")
    end
    seen = seen or {}
    if seen[v] then
        return format("%q", "<cycle>")
    end
    local keys = sorted_keys(v)
    if #keys == 0 then
        return "{}"
    end
    seen[v] = true
    local inner = indent .. "  "
    local lines = {}
    local n = #v
    for i = 1, n do
        lines[#lines + 1] = inner .. serialize(v[i], inner, seen) .. ","
    end
    for _, k in ipairs(keys) do
        if not (mtype(k) == "integer" and k >= 1 and k <= n) then
            local key
            if type(k) == "string" and find(k, "^[%a_][%w_]*$") and not keywords[k] then
                key = k
            else
                key = "[ " .. serialize(k, inner, seen) .. " ]" -- spaces: "[[[" would start a long string
            end
            lines[#lines + 1] = inner .. key .. " = " .. serialize(v[k], inner, seen) .. ","
        end
    end
    seen[v] = nil
    return "{\n" .. concat(lines, "\n") .. "\n" .. indent .. "}"
end
T.serialize = function(v) return serialize(v, "") end

-- A line diff of two texts ("- expected" / "+ actual"), at most `limit` lines of it.
function T.line_diff(expected, actual, limit)
    limit = limit or 40
    local a, b = {}, {}
    for line in (expected .. "\n"):gmatch("(.-)\n") do
        a[#a + 1] = line
    end
    for line in (actual .. "\n"):gmatch("(.-)\n") do
        b[#b + 1] = line
    end
    -- Longest common subsequence over the lines (texts here are small).
    local n, m = #a, #b
    if n * m > 250000 then
        return "- " .. concat(a, "\n- ") .. "\n+ " .. concat(b, "\n+ ")
    end
    local lcs = {}
    for i = n + 1, 1, -1 do
        lcs[i] = {}
        for j = m + 1, 1, -1 do
            if i > n or j > m then
                lcs[i][j] = 0
            elseif a[i] == b[j] then
                lcs[i][j] = lcs[i + 1][j + 1] + 1
            else
                local x, y = lcs[i + 1][j], lcs[i][j + 1]
                lcs[i][j] = x > y and x or y
            end
        end
    end
    local out = {}
    local i, j = 1, 1
    while (i <= n or j <= m) and #out < limit do
        if i <= n and j <= m and a[i] == b[j] then
            out[#out + 1] = "  " .. a[i]
            i, j = i + 1, j + 1
        elseif j <= m and (i > n or lcs[i][j + 1] >= lcs[i + 1][j]) then
            out[#out + 1] = "+ " .. b[j]
            j = j + 1
        else
            out[#out + 1] = "- " .. a[i]
            i = i + 1
        end
    end
    if i <= n or j <= m then
        out[#out + 1] = "  ..."
    end
    return concat(out, "\n")
end

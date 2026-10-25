// The only translation unit that reads PUC Lua's private structures (lstate.h, lobject.h): the hook
// countdown of a thread and the line tables of function prototypes. Everything else goes through
// the public API. The line decoding mirrors ldebug.c (getbaseline / luaG_getfuncline /
// collectvalidlines), which onelua.c compiles as static functions.

#include <algorithm>
#include <cstdint>
#include <string_view>
#include <vector>

#include "ldebug.h"
#include "lfunc.h"
#include "lobject.h"
#include "lstate.h"
#include <lua.h>

#include <rhp/script/puc_lua/lua_internals.hpp>

namespace Rhp::script::detail::internals {

namespace {

const Proto* as_proto(const void* p) noexcept {
    return static_cast<const Proto*>(p);
}

// The line of instruction `pc` counted from the nearest absolute line entry at or before it.
int base_line(const Proto* f, int pc, int* basepc) noexcept {
    if (f->sizeabslineinfo == 0 || pc < f->abslineinfo[0].pc) {
        *basepc = -1;
        return f->linedefined;
    }
    int i = pc / MAXIWTHABS - 1;
    while (i + 1 < f->sizeabslineinfo && pc >= f->abslineinfo[i + 1].pc) {
        ++i;
    }
    *basepc = f->abslineinfo[i].pc;
    return f->abslineinfo[i].line;
}

int line_of(const Proto* f, int pc) noexcept {
    int basepc = 0;
    int line = base_line(f, pc, &basepc);
    while (basepc++ < pc) {
        line += f->lineinfo[basepc];
    }
    return line;
}

int next_line(const Proto* p, int current, int pc) noexcept {
    return p->lineinfo[pc] != ABSLINEINFO ? current + p->lineinfo[pc] : line_of(p, pc);
}

void collect(const Proto* p, std::vector<std::uint32_t>& lines, std::vector<const void*>& protos) {
    protos.push_back(p);
    if (p->lineinfo != nullptr) {
        int current = p->linedefined;
        int i = 0;
        if (isvararg(p)) { // the first instruction (OP_VARARGPREP) has no line of its own
            current = next_line(p, current, 0);
            i = 1;
        }
        for (; i < p->sizelineinfo; ++i) {
            current = next_line(p, current, i);
            if (current > 0) {
                lines.push_back(static_cast<std::uint32_t>(current));
            }
        }
    }
    for (int i = 0; i < p->sizep; ++i) {
        collect(p->p[i], lines, protos);
    }
}

} // namespace

std::uint32_t take_hook_progress(lua_State* L) noexcept {
    if ((L->hookmask & LUA_MASKCOUNT) == 0 || L->basehookcount <= 0) {
        return 0;
    }
    const int done = L->basehookcount - L->hookcount;
    L->hookcount = L->basehookcount;
    return done > 0 ? static_cast<std::uint32_t>(done) : 0;
}

const void* proto_of(const lua_Debug* ar) noexcept {
    const CallInfo* ci = ar->i_ci;
    if (ci == nullptr || !isLua(ci)) {
        return nullptr;
    }
    return ci_func(ci)->p;
}

const void* proto_on_top(lua_State* L) noexcept {
    if (lua_type(L, -1) != LUA_TFUNCTION || lua_iscfunction(L, -1) != 0) {
        return nullptr;
    }
    const auto* closure = static_cast<const LClosure*>(lua_topointer(L, -1));
    return closure != nullptr ? closure->p : nullptr;
}

std::string_view proto_source(const void* proto) noexcept {
    const Proto* p = as_proto(proto);
    if (p == nullptr || p->source == nullptr) {
        return {};
    }
    return std::string_view{getstr(p->source), tsslen(p->source)};
}

std::pair<int, int> proto_lines(const void* proto) noexcept {
    const Proto* p = as_proto(proto);
    return p != nullptr ? std::pair<int, int>{p->linedefined, p->lastlinedefined} : std::pair<int, int>{0, 0};
}

const void* proto_at(lua_State* L, int level) noexcept {
    lua_Debug ar{};
    if (lua_getstack(L, level, &ar) == 0) {
        return nullptr;
    }
    return proto_of(&ar);
}

void set_line_events(lua_State* L, bool on) noexcept {
    const int mask = L->hookmask;
    const int wanted = on ? (mask | LUA_MASKLINE) : (mask & ~LUA_MASKLINE);
    if (wanted == mask || L->hook == nullptr) {
        return;
    }
    const int left = L->hookcount;
    lua_sethook(L, L->hook, wanted, L->basehookcount);
    L->hookcount = left;
}

std::vector<std::uint32_t> executable_lines(const void* proto, std::vector<const void*>& protos) {
    std::vector<std::uint32_t> lines;
    if (proto != nullptr) {
        collect(as_proto(proto), lines, protos);
    }
    std::ranges::sort(lines);
    const auto dup = std::ranges::unique(lines);
    lines.erase(dup.begin(), dup.end());
    return lines;
}

} // namespace Rhp::script::detail::internals

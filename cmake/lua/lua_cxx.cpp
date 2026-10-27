// PUC Lua compiled as C++ in one translation unit (upstream's own onelua.c with MAKE_LIB).
// As C++, lua_error unwinds with exceptions, so RAII in RHP's binding trampolines stays correct.
// Lua headers are therefore included WITHOUT extern "C" everywhere in RHP.
//
// RHP_LUA_JUMP_YIELDS (cmake/RhpLua.cmake): errors still throw, but a coroutine yield jumps back to
// its lua_resume with _longjmp, as Lua does when compiled as C. A yield thrown as an exception costs
// microseconds in the unwinder; the jump costs nanoseconds. The jump skips the frames between
// lua_yield and lua_resume without running their destructors, so a C function that yields
// (lua_yield / lua_yieldk, itself or through a helper it calls) must hold no C++ object with a
// destructor at that point. In RHP those are rhp.wait, rhp.next_frame, rhp.sleep, rhp.wait_event,
// task:join (Src/rhp/script/puc_lua) and every asynchronous binding (detail::call_fn ->
// detail::yield_async, Src/rhp/script/detail/lib_builder.hpp). Yields from the hook are safe either
// way, the time-slice yield in the count hook and the debugger's pause in the line hook
// (Src/rhp/script/puc_lua/debug.cpp): Lua jumps after the hook has returned.
//
// x64 Windows: the CRT's longjmp unwinds (runs the skipped frames' destructors, like an exception)
// when the buffer names the frame setjmp ran in, and only restores the registers when that frame is
// 0. The buffer's frame is cleared right after setjmp, so the yield is a plain jump there too -
// unless the process runs with a CET shadow stack (an executable linked /CETCOMPAT on a CPU that has
// one): a plain jump leaves the shadow stack behind and the process dies, so yields throw there.
#if defined(RHP_LUA_JUMP_YIELDS)
#include <setjmp.h> // NOLINT(modernize-deprecated-headers): _setjmp / _longjmp are POSIX, not in <csetjmp>

#if defined(_M_X64)
#include <immintrin.h>

namespace {

// RDSSP reads the shadow stack pointer: 0 without a shadow stack (it is a NOP then, also on CPUs
// without CET).
#if defined(__clang__)
__attribute__((target("shstk"))) unsigned long long rhp_lua_ssp() noexcept {
    return __builtin_ia32_rdsspq(0);
}
#else
unsigned long long rhp_lua_ssp() noexcept {
    return _rdsspq();
}
#endif

bool rhp_lua_plain_jumps() noexcept {
    static const bool plain = rhp_lua_ssp() == 0; // fixed for the process's lifetime
    return plain;
}

} // namespace

#define RHP_LUA_SETJMP(b) setjmp(b)
#define RHP_LUA_LONGJMP(b) longjmp((b), 1)
#define RHP_LUA_NO_UNWIND(b) (reinterpret_cast<_JUMP_BUFFER*>(b)->Frame = 0)
#define RHP_LUA_CAN_JUMP() rhp_lua_plain_jumps()
#else
#define RHP_LUA_SETJMP(b) _setjmp(b)
#define RHP_LUA_LONGJMP(b) _longjmp((b), 1)
#define RHP_LUA_NO_UNWIND(b) ((void)0)
#define RHP_LUA_CAN_JUMP() true
#endif

#define LUAI_THROW(L, c)                                      \
    do {                                                      \
        if ((c)->status == LUA_YIELD && RHP_LUA_CAN_JUMP()) { \
            RHP_LUA_LONGJMP((c)->b);                          \
        }                                                     \
        throw(c);                                             \
    } while (0)

#define LUAI_TRY(L, c, f, ud)                    \
    do {                                         \
        if (RHP_LUA_SETJMP((c)->b) == 0) {       \
            RHP_LUA_NO_UNWIND((c)->b);           \
            try {                                \
                (f)(L, ud);                      \
            } catch (lua_longjmp * rhp_lua_c1) { \
                if (rhp_lua_c1 != (c)) {         \
                    throw;                       \
                }                                \
            } catch (...) {                      \
                (c)->status = -1;                \
            }                                    \
        }                                        \
    } while (0)
#endif

// upstream onelua.c with MAKE_LIB, spelled out so that one function can be put between ldebug.c and
// lvm.c (keep this list, in this order, in step with onelua.c when Lua is updated).
// clang-format off
#include "lprefix.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LUA_CORE
#define LUA_LIB

#include "luaconf.h"

#undef LUAI_FUNC
#undef LUAI_DDEC
#undef LUAI_DDEF
#define LUAI_FUNC static
#define LUAI_DDEC(def) /* empty */
#define LUAI_DDEF static

#include "lzio.c"
#include "lctype.c"
#include "lopcodes.c"
#include "lmem.c"
#include "lundump.c"
#include "ldump.c"
#include "lstate.c"
#include "lgc.c"
#include "llex.c"
#include "lcode.c"
#include "lparser.c"
#include "ldebug.c"
// clang-format on

#if LUA_VERSION_RELEASE_NUM != 50501
#error "Lua was updated: check onelua.c's include list, luaG_traceexec against rhp_lua_traceexec and the patches in cmake/RhpLua.cmake"
#endif

// While any hook mask is set (the exact count hook of the meter and the profiler, line events), the VM
// calls luaG_traceexec before every instruction; for a count hook that isn't due it only counts down
// (and stores the pc, which nothing reads until a hook runs or an instruction that may raise saves it
// itself, as it does without hooks). Counting down inline here makes the not-due case a decrement
// instead of a call. Everything else (a due count, line events, a hook that yielded) goes through
// upstream's function. RHP's cancel / limit / slice hook sets no mask: it counts at safe points (below).
#if defined(_MSC_VER) && !defined(__clang__)
#define RHP_LUA_FORCE_INLINE __forceinline
#else
#define RHP_LUA_FORCE_INLINE inline __attribute__((always_inline))
#endif
// Safe points. A count hook that only checks for cancels and limits doesn't need to run after an
// exact number of instructions, only before a script can run long: straight-line code is bounded by
// its function's size, so only loops and calls can. rhp_lua_sethook_safepoints installs such a hook
// with no mask at all (the VM then runs as fast as without a hook) and the patched lvm.c
// (cmake/RhpLua.cmake) charges L->hookcount at the safe points: a backward jump charges its distance
// (the loop body's length, so a limit still counts a loop's instructions), entering a Lua function
// charges 1. When the countdown runs out the count hook is armed for one instruction: it fires
// through luaG_traceexec like any count event (errors, yields and CIST_HOOKYIELD work unchanged),
// and rhp_lua_traceexec puts the safe-point mode back afterwards. With no hook the countdown only
// restarts from far away, so an unchecked run pays one subtraction per loop iteration.
// RHP_LUA_MASKSAFEPOINT marks the armed instruction (above the byte lua_sethook keeps, so only these
// functions set it; luaG_traceexec casts the mask to a byte and doesn't see it).
#define RHP_LUA_MASKSAFEPOINT 0x100

static int rhp_lua_safepoint_due(lua_State* L, CallInfo* ci) {
    if (L->hookmask == 0 && L->hook != NULL) { // counting at safe points: fire before the next instruction
        L->hookmask = LUA_MASKCOUNT | RHP_LUA_MASKSAFEPOINT;
        L->hookcount = 1;
        ci->u.l.trap = 1;
        return 1;
    }
    if (L->hookmask == 0) {
        L->hookcount = INT_MAX / 2; // no hook: nothing to count
        return 0;
    }
    return 1; // a hook set since this frame last looked (another mask): let luaG_traceexec see it
}

// lvm.c's charge at a safe point: `trap` is set while any other hook (or the armed count) needs
// luaG_traceexec, which then does the counting.
#define rhp_lua_charge(n)                                              \
    {                                                                  \
        if (l_unlikely(!trap && (L->hookcount -= cast_int(n)) <= 0)) { \
            trap = rhp_lua_safepoint_due(L, ci);                       \
        }                                                              \
    }

static RHP_LUA_FORCE_INLINE int rhp_lua_traceexec(lua_State* L, const Instruction* pc) {
    if ((L->hookmask & (LUA_MASKLINE | LUA_MASKCOUNT)) == LUA_MASKCOUNT && L->hookcount > 1) {
        --L->hookcount;
        return 1;
    }
    const int trap = luaG_traceexec(L, pc);
    if (l_unlikely(L->hookmask & RHP_LUA_MASKSAFEPOINT)) { // the armed count fired: back to safe points
        L->hookmask = 0;
        L->hookcount = L->basehookcount;
        L->ci->u.l.trap = 0;
        return 0;
    }
    return trap;
}

void rhp_lua_sethook_safepoints(lua_State* L, lua_Hook hook, int count) {
    if (hook == NULL || count <= 0) {
        lua_sethook(L, NULL, 0, 0);
        return;
    }
    L->hook = hook;
    L->basehookcount = count;
    L->hookcount = count;
    L->hookmask = 0; // frames still trapping for an earlier mask stop at their next instruction
}

int rhp_lua_hook_at_safepoints(lua_State* L) {
    return (L->hookmask == 0 && L->hook != NULL) || (L->hookmask & RHP_LUA_MASKSAFEPOINT) != 0;
}

// clang-format off
#include "lfunc.c"
#include "lobject.c"
#include "ltm.c"
#include "lstring.c"
#include "ltable.c"
#include "ldo.c"
#define luaG_traceexec rhp_lua_traceexec // lvm.c's vmfetch calls it
#include "rhp_lvm.c" // lvm.c with the safe-point charges (cmake/RhpLua.cmake)
#undef luaG_traceexec
#include "lapi.c"
// clang-format on

// Steps. Pattern matching and plain find run in C, where no hook fires: a pattern that backtracks
// (string.find(s, ("a*"):rep(10) .. "b")) or a plain find with many near misses could run for
// minutes. The patched lstrlib.c (cmake/RhpLua.cmake) counts that work in steps (a match call, a
// character an expansion or %b scans, RHP_LUA_BYTES_PER_STEP bytes a back-reference or a find
// candidate compares) and every RHP_LUA_STEPS hands them to the state's step function
// (rhp_lua_set_step_function), on a thread that has a hook (one RHP checks) outside hooks and
// finalizers. It is called directly, not through lua_call (no call hook, no C stack level), with the
// step count on top of the stack, and may raise. Otherwise (a state without one, a thread without a
// hook) the countdown just restarts: a step costs a decrement and a branch.
#define RHP_LUA_STEPS 4096
#define RHP_LUA_BYTES_PER_STEP 32

static const char rhp_lua_step_key = 's'; // its address: the registry key of the step function

void rhp_lua_set_step_function(lua_State* L, lua_CFunction f) {
    lua_pushcfunction(L, f);
    lua_rawsetp(L, LUA_REGISTRYINDEX, &rhp_lua_step_key);
}

static ptrdiff_t rhp_lua_steps_due(lua_State* L, ptrdiff_t left) {
    if (L->hook != NULL && L->allowhook) {
        const int top = lua_gettop(L);
        if (lua_rawgetp(L, LUA_REGISTRYINDEX, &rhp_lua_step_key) == LUA_TFUNCTION) {
            const lua_CFunction f = lua_tocfunction(L, -1);
            lua_pushinteger(L, (lua_Integer)(RHP_LUA_STEPS - left));
            f(L);
        }
        lua_settop(L, top);
    }
    return RHP_LUA_STEPS;
}

#define rhp_lua_step(L, left, n)                           \
    {                                                      \
        if (l_unlikely(((left) -= (ptrdiff_t)(n)) <= 0)) { \
            (left) = rhp_lua_steps_due((L), (left));       \
        }                                                  \
    }

// Addresses. tostring and string.format's %p (the patched lauxlib.c and lstrlib.c) show
// rhp_lua_topointer's value where they showed an object's address: SipHash-2-4 of the address under
// the state's 128-bit key (rhp_lua_set_address_key), so code learns nothing of the address space
// layout from them (a C function's address is the program's). Lua never moves an object, so the
// value stays the object's for its life, and at 64 bits two live objects practically never share one.
// A state without a key (not a sandbox) shows the address, as upstream does.
#include <stdint.h> // NOLINT(modernize-deprecated-headers): uint64_t, uintptr_t, like the C sources around

static const char rhp_lua_address_key = 'a'; // its address: the registry key of the key

void rhp_lua_set_address_key(lua_State* L, const char* key) {
    lua_pushlstring(L, key, 16);
    lua_rawsetp(L, LUA_REGISTRYINDEX, &rhp_lua_address_key);
}

static uint64_t rhp_lua_rotl(uint64_t x, int b) {
    return (x << b) | (x >> (64 - b));
}

static void rhp_lua_sipround(uint64_t v[4]) {
    v[0] += v[1];
    v[1] = rhp_lua_rotl(v[1], 13) ^ v[0];
    v[0] = rhp_lua_rotl(v[0], 32);
    v[2] += v[3];
    v[3] = rhp_lua_rotl(v[3], 16) ^ v[2];
    v[0] += v[3];
    v[3] = rhp_lua_rotl(v[3], 21) ^ v[0];
    v[2] += v[1];
    v[1] = rhp_lua_rotl(v[1], 17) ^ v[2];
    v[2] = rhp_lua_rotl(v[2], 32);
}

// SipHash-2-4 of one 8-byte message (m's little-endian bytes) under the key (k0, k1).
static uint64_t rhp_lua_siphash(uint64_t k0, uint64_t k1, uint64_t m) {
    uint64_t v[4] = {k0 ^ 0x736f6d6570736575u, k1 ^ 0x646f72616e646f6du, k0 ^ 0x6c7967656e657261u, k1 ^ 0x7465646279746573u};
    const uint64_t length = (uint64_t)8 << 56; // the last block: no bytes left, the message length
    v[3] ^= m;
    rhp_lua_sipround(v);
    rhp_lua_sipround(v);
    v[0] ^= m;
    v[3] ^= length;
    rhp_lua_sipround(v);
    rhp_lua_sipround(v);
    v[0] ^= length;
    v[2] ^= 0xff;
    for (int i = 0; i < 4; ++i) {
        rhp_lua_sipround(v);
    }
    return v[0] ^ v[1] ^ v[2] ^ v[3];
}

const void* rhp_lua_topointer(lua_State* L, int idx) {
    const void* p = lua_topointer(L, idx);
    if (p == NULL) {
        return NULL;
    }
    if (lua_rawgetp(L, LUA_REGISTRYINDEX, &rhp_lua_address_key) != LUA_TSTRING) {
        lua_pop(L, 1);
        return p;
    }
    uint64_t key[2];
    memcpy(key, lua_tostring(L, -1), sizeof key); // rhp_lua_set_address_key stored 16 bytes
    lua_pop(L, 1);
    const uint64_t h = rhp_lua_siphash(key[0], key[1], (uint64_t)(uintptr_t)p);
    return (const void*)(uintptr_t)(h != 0 ? h : 1); // never NULL: %p shows that as "(null)"
}

// clang-format off
#include "rhp_lauxlib.c" // lauxlib.c, tostring showing rhp_lua_topointer (cmake/RhpLua.cmake)

#include "lbaselib.c"
#include "lcorolib.c"
#include "ldblib.c"
#include "liolib.c"
#include "lmathlib.c"
#include "loadlib.c"
#include "loslib.c"
#include "rhp_lstrlib.c" // lstrlib.c with the step counting and %p showing rhp_lua_topointer (cmake/RhpLua.cmake)
#include "ltablib.c"
#include "lutf8lib.c"
#include "linit.c"
// clang-format on

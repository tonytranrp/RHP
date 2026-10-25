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
// detail::yield_async, Src/rhp/script/detail/lib_builder.hpp); the time-slice yield in the count hook
// is safe either way (Lua jumps after the hook has returned).
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
#error "Lua was updated: check onelua.c's include list and luaG_traceexec against rhp_lua_traceexec"
#endif

// While any hook is set (RHP's cancel / limit / slice hook counts instructions), the VM calls
// luaG_traceexec before every instruction; for a count hook that isn't due it only counts down (and
// stores the pc, which nothing reads until a hook runs or an instruction that may raise saves it
// itself, as it does without hooks). Counting down inline here makes the not-due case a decrement
// instead of a call: loops with RHP's default cancel checks run at about 1.25x raw Lua instead of 2x.
// Everything else (a due count, line events, a hook that yielded) goes through upstream's function.
#if defined(_MSC_VER) && !defined(__clang__)
#define RHP_LUA_FORCE_INLINE __forceinline
#else
#define RHP_LUA_FORCE_INLINE inline __attribute__((always_inline))
#endif
static RHP_LUA_FORCE_INLINE int rhp_lua_traceexec(lua_State* L, const Instruction* pc) {
    if ((L->hookmask & (LUA_MASKLINE | LUA_MASKCOUNT)) == LUA_MASKCOUNT && L->hookcount > 1) {
        --L->hookcount;
        return 1;
    }
    return luaG_traceexec(L, pc);
}

// clang-format off
#include "lfunc.c"
#include "lobject.c"
#include "ltm.c"
#include "lstring.c"
#include "ltable.c"
#include "ldo.c"
#define luaG_traceexec rhp_lua_traceexec // lvm.c's vmfetch calls it
#include "lvm.c"
#undef luaG_traceexec
#include "lapi.c"

#include "lauxlib.c"

#include "lbaselib.c"
#include "lcorolib.c"
#include "ldblib.c"
#include "liolib.c"
#include "lmathlib.c"
#include "loadlib.c"
#include "loslib.c"
#include "lstrlib.c"
#include "ltablib.c"
#include "lutf8lib.c"
#include "linit.c"
// clang-format on

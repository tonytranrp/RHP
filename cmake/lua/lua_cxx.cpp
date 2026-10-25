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

#define MAKE_LIB
#include "onelua.c"

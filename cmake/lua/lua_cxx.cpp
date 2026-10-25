// PUC Lua compiled as C++ in one translation unit (upstream's own onelua.c with MAKE_LIB).
// As C++, lua_error unwinds with exceptions, so RAII in RHP's binding trampolines stays correct.
// Lua headers are therefore included WITHOUT extern "C" everywhere in RHP.
//
// RHP_LUA_JUMP_YIELDS (cmake/RhpLua.cmake; every toolchain but the MSVC ABI, whose longjmp unwinds):
// errors still throw, but a coroutine yield jumps back to its lua_resume with _longjmp, as Lua does
// when compiled as C. A yield thrown as an exception costs microseconds in the unwinder; the jump
// costs nanoseconds. The jump skips the frames between lua_yield and lua_resume without running
// their destructors, so a C function that yields (lua_yield / lua_yieldk, itself or through a
// helper it calls) must hold no C++ object with a destructor at that point. In RHP those are
// rhp.wait, rhp.next_frame, rhp.sleep, rhp.wait_event, task:join (Src/rhp/script/puc_lua) and every
// asynchronous binding (detail::call_fn -> detail::yield_async, Src/rhp/script/detail/lib_builder.hpp); the
// time-slice yield in the count hook is safe either way (Lua jumps after the hook has returned).
#if defined(RHP_LUA_JUMP_YIELDS)
#include <setjmp.h> // NOLINT(modernize-deprecated-headers): _setjmp / _longjmp are POSIX, not in <csetjmp>

#define LUAI_THROW(L, c)                \
    do {                                \
        if ((c)->status == LUA_YIELD) { \
            _longjmp((c)->b, 1);        \
        }                               \
        throw(c);                       \
    } while (0)

#define LUAI_TRY(L, c, f, ud)                    \
    do {                                         \
        if (_setjmp((c)->b) == 0) {              \
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

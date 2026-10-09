// PUC Lua compiled as C++ in one translation unit (upstream's own onelua.c with MAKE_LIB).
// As C++, lua_error unwinds with exceptions, so RAII in RHP's binding trampolines stays correct.
// Lua headers are therefore included WITHOUT extern "C" everywhere in RHP.
#define MAKE_LIB
#include "onelua.c"

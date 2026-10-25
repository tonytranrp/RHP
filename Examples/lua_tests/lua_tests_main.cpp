// The game's Lua test executable: the real `shop` lib, Rhp::test's command line. Run it with test
// files or folders (it --help lists the options), or through ctest (rhp_add_lua_tests).
#include <rhp/test/test.hpp>

#include "shop.hpp"

int main(int argc, char** argv) {
    return Rhp::test::main(argc, argv, [](Rhp::script::sandbox& box) { return box.install<shop::lib>(); });
}

// Rhp::test from an installed RHP: a Lua test executable with a lib of its own.
#include <rhp/test/test.hpp>

namespace {

int answer() {
    return 42;
}

using consumer_lib = Rhp::lib<"consumer">::fn<"answer", &answer>;

} // namespace

int main(int argc, char** argv) {
    return Rhp::test::main(argc, argv, [](Rhp::script::sandbox& box) { return box.install<consumer_lib>(); });
}

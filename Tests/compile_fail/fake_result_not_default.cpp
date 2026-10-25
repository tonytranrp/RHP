// A fake must make a result when nothing configured one: a function whose result type converts
// from a value but can't be default-constructed can still be faked (fake.returns gives it; a call
// without one is a type mismatch at run time), while one that neither converts from a value nor
// default-constructs must not compile.
#include <rhp/core/convert.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/test/fake.hpp>

namespace fake_result_not_default_fixture {

// Converts both ways, no default constructor: fakeable.
struct ticket {
    explicit ticket(int n) : number(n) {}
    int number;
};

// Converts to a value only (a result Lua reads), no default constructor: not fakeable.
struct receipt {
    explicit receipt(int n) : number(n) {}
    int number;
};

} // namespace fake_result_not_default_fixture

template <>
struct Rhp::convert<fake_result_not_default_fixture::ticket> {
    static Rhp::value to_value(const fake_result_not_default_fixture::ticket& t) { return Rhp::value{static_cast<std::int64_t>(t.number)}; }
    static Rhp::result<fake_result_not_default_fixture::ticket> from_value(const Rhp::value& v) {
        const auto* n = v.get_if<std::int64_t>();
        if (n == nullptr) {
            return Rhp::fail(Rhp::errc::kTypeMismatch, "expected an integer");
        }
        return fake_result_not_default_fixture::ticket{static_cast<int>(*n)};
    }
};

template <>
struct Rhp::convert<fake_result_not_default_fixture::receipt> {
    static Rhp::value to_value(const fake_result_not_default_fixture::receipt& r) { return Rhp::value{static_cast<std::int64_t>(r.number)}; }
};

namespace fake_result_not_default_fixture {

inline ticket issue() {
    return ticket{1};
}

inline receipt pay() {
    return receipt{1};
}

using ok_lib = Rhp::lib<"ok">::fn<"issue", &issue>;
using bad_lib = Rhp::lib<"bad">::fn<"pay", &pay>;

inline void use(Rhp::script::sandbox& box) {
    (void)box.install<Rhp::test::fake<ok_lib>>();
#if defined(RHP_COMPILE_FAIL)
    (void)box.install<Rhp::test::fake<bad_lib>>();
#endif
}

} // namespace fake_result_not_default_fixture

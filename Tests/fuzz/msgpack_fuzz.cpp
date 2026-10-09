// MessagePack: decoding arbitrary bytes either fails or yields a value whose encoding decodes to
// the same encoding (canonical round trip). Depth and element limits hold before allocation.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <rhp/core/value.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/wire/codec.hpp>
#include <rhp/wire/codec/msgpack.hpp>

#include "fuzz_support.hpp"

namespace {

std::string encoded(const Rhp::value& v) {
    Rhp::utils::byte_buffer out;
    (void)Rhp::wire::msgpack::encode(v, out);
    return {reinterpret_cast<const char*>(out.view().data()), out.size()};
}

} // namespace

std::vector<std::string> rhp_fuzz_seeds() {
    Rhp::value::map m;
    m.emplace_back("req", Rhp::value{std::int64_t{42}});
    m.emplace_back("body", Rhp::value{std::string{"return game.gravity"}});
    m.emplace_back("blob", Rhp::value{Rhp::value::bytes(40, std::byte{9})});
    Rhp::value::array a{Rhp::value{1.5}, Rhp::value{true}, Rhp::value{}, Rhp::value{std::int64_t{-1}}, Rhp::value{m}};
    return {encoded(Rhp::value{}),
            encoded(Rhp::value{std::int64_t{-9'000'000'000}}),
            encoded(Rhp::value{3.25}),
            encoded(Rhp::value{std::string(300, 'x')}),
            encoded(Rhp::value{m}),
            encoded(Rhp::value{a}),
            std::string("\x91\x91\x91\x91\x91\x91\x91\x91\x91\xc0", 10), // nesting
            std::string("\xdd\xff\xff\xff\xff", 5),                     // a huge array count
            std::string("\xc6\x7f\xff\xff\xff", 5)};                    // a huge bin length
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const Rhp::utils::bytes_view in{reinterpret_cast<const std::byte*>(data), size};
    const Rhp::wire::decode_limits limits{32, 4096};
    auto v = Rhp::wire::msgpack::decode(in, limits);
    if (!v) {
        return 0;
    }
    Rhp::utils::byte_buffer first;
    RHP_FUZZ_CHECK(Rhp::wire::msgpack::encode(*v, first).has_value());
    auto again = Rhp::wire::msgpack::decode(first.view(), limits);
    RHP_FUZZ_CHECK(again.has_value());
    Rhp::utils::byte_buffer second;
    RHP_FUZZ_CHECK(Rhp::wire::msgpack::encode(*again, second).has_value());
    RHP_FUZZ_CHECK(first == second);
    return 0;
}

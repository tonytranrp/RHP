// Message schemas: a value decoded from arbitrary bytes is offered to every wire message type. A
// type that accepts it must give back a value that it accepts again, unchanged.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "fuzz_support.hpp"

#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/value.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/wire/codec/msgpack.hpp>
#include <rhp/wire/messages.hpp>

namespace {

std::string encoded(const Rhp::value& v) {
    Rhp::utils::byte_buffer out;
    (void)Rhp::wire::msgpack::encode(v, out);
    return {reinterpret_cast<const char*>(out.view().data()), out.size()};
}

template <class T>
void round_trip(const Rhp::value& v) {
    auto t = Rhp::from_value<T>(v);
    if (!t) {
        return;
    }
    const Rhp::value back = Rhp::to_value(*t);
    auto again = Rhp::from_value<T>(back);
    RHP_FUZZ_CHECK(again.has_value());
    RHP_FUZZ_CHECK(encoded(Rhp::to_value(*again)) == encoded(back));
}

template <class... Ts>
void all(const Rhp::value& v) {
    (round_trip<Ts>(v), ...);
}

} // namespace

std::vector<std::string> rhp_fuzz_seeds() {
    namespace w = Rhp::wire;
    std::vector<std::string> out;
    out.push_back(encoded(Rhp::to_value(w::envelope{7, 99, Rhp::value{std::string{"x"}}})));
    out.push_back(encoded(Rhp::to_value(w::resume{Rhp::session_id{12}, Rhp::value::bytes(32, std::byte{3})})));
    out.push_back(encoded(Rhp::to_value(w::welcome{Rhp::session_id{3}, "dev", Rhp::role::kAdmin, 2000, "linux"})));
    out.push_back(encoded(Rhp::to_value(w::hello{w::kProtocolRevision, "ios", Rhp::value{}})));
    out.push_back(encoded(Rhp::to_value(Rhp::make_error(Rhp::errc::kAuth, "no", "here"))));
    Rhp::value::map exec;
    exec.emplace_back("source", Rhp::value{std::string{"return 1"}});
    exec.emplace_back("signature", Rhp::value{});
    exec.emplace_back("module", Rhp::value{std::string{"low_grav"}});
    exec.emplace_back("fn", Rhp::value{std::string{"run"}});
    exec.emplace_back("args", Rhp::value{Rhp::value::array{Rhp::value{std::int64_t{1}}}});
    exec.emplace_back("target", Rhp::value{std::int64_t{5}});
    exec.emplace_back("bytes", Rhp::value{Rhp::value::bytes(8, std::byte{1})});
    out.push_back(encoded(Rhp::value{exec}));
    out.push_back(encoded(Rhp::to_value(w::subscribe_request{"game.round_over"})));
    out.push_back(encoded(Rhp::to_value(w::event_message{"game.score", Rhp::module_id{2}, Rhp::value::array{Rhp::value{std::int64_t{3}}}, 1})));
    return out;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto v = Rhp::wire::msgpack::decode(Rhp::utils::bytes_view{reinterpret_cast<const std::byte*>(data), size}, Rhp::wire::decode_limits{32, 4096});
    if (!v) {
        return 0;
    }
    namespace w = Rhp::wire;
    all<w::hello, w::challenge, w::response, w::welcome, w::resume, w::envelope, w::module_ref, w::exec_request, w::load_request, w::call_request, w::reload_request,
        w::rollback_request, w::unload_request, w::module_request, w::tag_request, w::cancel_request, w::blob_chunk, w::revert_summary, w::module_status,
        w::emit_message, w::subscribe_request, w::event_message, Rhp::error>(*v);
    return 0;
}

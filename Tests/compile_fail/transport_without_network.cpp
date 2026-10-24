// A transport must say whether it crosses a network (the TLS address rules depend on it): one
// without `network` is refused where the config names it, instead of being treated as local.
#include <memory>
#include <string_view>

#include <rhp/config/config.hpp>

namespace transport_without_network_fixtures {

struct declared {
    static constexpr std::string_view name = "declared";
    static constexpr bool network = true;
    static Rhp::result<std::unique_ptr<Rhp::net::listener>> listen(Rhp::net::io_context&, const Rhp::endpoint&, Rhp::net::accept_fn);
    static void dial(Rhp::net::io_context&, const Rhp::endpoint&, Rhp::net::connect_fn);
};

struct undeclared {
    static constexpr std::string_view name = "undeclared";
    static Rhp::result<std::unique_ptr<Rhp::net::listener>> listen(Rhp::net::io_context&, const Rhp::endpoint&, Rhp::net::accept_fn);
    static void dial(Rhp::net::io_context&, const Rhp::endpoint&, Rhp::net::connect_fn);
};

} // namespace transport_without_network_fixtures

#if defined(RHP_COMPILE_FAIL)
using broken = Rhp::config<>::transport<transport_without_network_fixtures::undeclared>;
broken::transport_t* unused = nullptr;
#else
using fine = Rhp::config<>::transport<transport_without_network_fixtures::declared>;
fine::transport_t* unused = nullptr;
#endif

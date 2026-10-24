// `network` must be a bool constant expression: a runtime flag (or an int) could be flipped or
// misread, and the TLS rules are decided at compile time from it.
#include <memory>
#include <string_view>

#include <rhp/config/config.hpp>

namespace transport_network_not_constant_fixtures {

struct constant {
    static constexpr std::string_view name = "constant";
    static constexpr bool network = false;
    static Rhp::result<std::unique_ptr<Rhp::net::listener>> listen(Rhp::net::io_context&, const Rhp::endpoint&, Rhp::net::accept_fn);
    static void dial(Rhp::net::io_context&, const Rhp::endpoint&, Rhp::net::connect_fn);
};

struct runtime_flag {
    static constexpr std::string_view name = "runtime_flag";
    static inline bool network = false;
    static Rhp::result<std::unique_ptr<Rhp::net::listener>> listen(Rhp::net::io_context&, const Rhp::endpoint&, Rhp::net::accept_fn);
    static void dial(Rhp::net::io_context&, const Rhp::endpoint&, Rhp::net::connect_fn);
};

} // namespace transport_network_not_constant_fixtures

#if defined(RHP_COMPILE_FAIL)
using broken = Rhp::config<>::transport<transport_network_not_constant_fixtures::runtime_flag>;
broken::transport_t* unused = nullptr;
#else
using fine = Rhp::config<>::transport<transport_network_not_constant_fixtures::constant>;
fine::transport_t* unused = nullptr;
#endif

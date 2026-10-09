#pragma once

#include <type_traits>

#include <rhp/core/errors_mode.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/log.hpp>
#include <rhp/exec/executor.hpp>
#include <rhp/exec/io_runner.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/tcp/tcp.hpp>
#include <rhp/security/authenticator.hpp>
#include <rhp/security/psk_keyring.hpp>
#include <rhp/utils/type_list.hpp>
#include <rhp/wire/codec.hpp>
#include <rhp/wire/codec/msgpack.hpp>

namespace Rhp {

template <class... Settings>
struct config;

namespace config_detail {

enum class slot : unsigned char {
    kTransport,
    kCodec,
    kAuth,
    kExecutor,
    kIo,
    kLimits,
    kErrors,
    kClock,
    kLogger
};

// One link of the chain: which slot it fills and with what.
template <slot S, class T>
struct setting {
    static constexpr slot which = S;
    using type = T;
};

// A Rhp::limits value carried as a type.
template <::Rhp::limits L>
struct limits_value {
    static constexpr ::Rhp::limits value = L;
};

// Settings minus every one that fills slot S.
template <slot S, class List>
struct drop;

template <slot S>
struct drop<S, utils::type_list<>> {
    using type = utils::type_list<>;
};

template <slot S, class Head, class... Rest>
struct drop<S, utils::type_list<Head, Rest...>> {
    using rest = typename drop<S, utils::type_list<Rest...>>::type;
    using type = std::conditional_t<Head::which == S, rest, utils::push_front_t<rest, Head>>;
};

template <class List>
struct to_config;

template <class... Ts>
struct to_config<utils::type_list<Ts...>> {
    using type = config<Ts...>;
};

// config<Settings...> with slot S set to T (a later link overrides an earlier one).
template <slot S, class T, class... Settings>
using rebind_t = typename to_config<utils::push_back_t<typename drop<S, utils::type_list<Settings...>>::type, setting<S, T>>>::type;

template <slot S, class Default, class... Settings>
struct get_or {
    using type = Default;
};

template <slot S, class Default, class Head, class... Rest>
struct get_or<S, Default, Head, Rest...> {
    using type = std::conditional_t<Head::which == S, typename Head::type, typename get_or<S, Default, Rest...>::type>;
};

template <slot S, class Default, class... Settings>
using get_or_t = typename get_or<S, Default, Settings...>::type;

} // namespace config_detail

// The type-level configuration of a host or client. Every link is checked by its concept on the
// line where it is written; anything not set keeps its default.
//
//   using my_cfg = Rhp::config<>
//       ::transport<Rhp::net::tcp>             // Rhp::net::transport       default tcp
//       ::codec    <Rhp::wire::msgpack>        // Rhp::wire::codec          default msgpack
//       ::auth     <Rhp::security::psk_keyring>// Rhp::security::authenticator  default psk_keyring
//       ::executor <Rhp::exec::pumped>         // Rhp::exec::executor       default pumped
//       ::io       <Rhp::exec::owned_io_thread>// Rhp::exec::io_runner      default owned_io_thread
//       ::limits   <Rhp::limits{}>             // value                     default Rhp::limits{} (no script limits)
//       ::errors   <Rhp::errors::expected>     // Rhp::errors::mode         default expected
//       ::clock    <Rhp::exec::steady_clock>   // Rhp::exec::clock_source   default steady_clock
//       ::logger   <Rhp::core::stderr_logger>; // Rhp::core::logger         default stderr_logger
//
// Rhp::config<> with no links is exactly that chain. In your own templates (a dependent context)
// write `Cfg::template transport<X>`. TLS, signing and discovery slots arrive with the stages that
// implement them.
template <class... Settings>
struct config {
    template <net::transport T>
    using transport = config_detail::rebind_t<config_detail::slot::kTransport, T, Settings...>;
    template <wire::codec C>
    using codec = config_detail::rebind_t<config_detail::slot::kCodec, C, Settings...>;
    template <security::authenticator A>
    using auth = config_detail::rebind_t<config_detail::slot::kAuth, A, Settings...>;
    template <exec::executor X>
    using executor = config_detail::rebind_t<config_detail::slot::kExecutor, X, Settings...>;
    template <exec::io_runner I>
    using io = config_detail::rebind_t<config_detail::slot::kIo, I, Settings...>;
    template <::Rhp::limits L>
    using limits = config_detail::rebind_t<config_detail::slot::kLimits, config_detail::limits_value<L>, Settings...>;
    template <::Rhp::errors::mode M>
    using errors = config_detail::rebind_t<config_detail::slot::kErrors, M, Settings...>;
    template <exec::clock_source K>
    using clock = config_detail::rebind_t<config_detail::slot::kClock, K, Settings...>;
    template <core::logger O>
    using logger = config_detail::rebind_t<config_detail::slot::kLogger, O, Settings...>;

    using transport_t = config_detail::get_or_t<config_detail::slot::kTransport, net::tcp, Settings...>;
    using codec_t = config_detail::get_or_t<config_detail::slot::kCodec, wire::msgpack, Settings...>;
    using auth_t = config_detail::get_or_t<config_detail::slot::kAuth, security::psk_keyring, Settings...>;
    using credential_t = typename auth_t::credential;
    using executor_t = config_detail::get_or_t<config_detail::slot::kExecutor, exec::pumped, Settings...>;
    using io_t = config_detail::get_or_t<config_detail::slot::kIo, exec::owned_io_thread, Settings...>;
    using errors_t = config_detail::get_or_t<config_detail::slot::kErrors, ::Rhp::errors::expected, Settings...>;
    using clock_t = config_detail::get_or_t<config_detail::slot::kClock, exec::steady_clock, Settings...>;
    using logger_t = config_detail::get_or_t<config_detail::slot::kLogger, core::stderr_logger, Settings...>;

    static constexpr ::Rhp::limits limits_v = config_detail::get_or_t<config_detail::slot::kLimits, config_detail::limits_value<::Rhp::limits{}>, Settings...>::value;

    // The error-mode return type of a T-returning call: Rhp::result<T> or T.
    template <class T>
    using return_t = typename errors_t::template return_t<T>;
};

template <class C>
inline constexpr bool is_config_v = false;

template <class... Settings>
inline constexpr bool is_config_v<config<Settings...>> = true;

// Anything built from Rhp::config<> (what Rhp::host and Rhp::client take).
template <class C>
concept configuration = is_config_v<C>;

} // namespace Rhp

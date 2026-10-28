# config — layer 5

`Rhp::config<>`: the type-level chain that names every policy of a host, client or fleet. Header-only. The module's public name is the class template itself; its helpers live in `Rhp::config_detail`. Target `Rhp::config`; depends on `net`, `security`, `tls`, `exec` and `wire`. Usage: [configuration guide](../../../Docs/guide/configuration.md).

```cpp
using my_cfg = Rhp::config<>
    ::transport<Rhp::net::loopback>
    ::io<Rhp::exec::zero_threads>
    ::limits<Rhp::limits{.wall_ms = 5'000}>;
Rhp::host<my_cfg> host{Rhp::endpoint::listen("game", 1), keys, signers};
```

| Slot | Concept | Default |
|---|---|---|
| `transport<T>` | `Rhp::net::transport` | `Rhp::net::tcp` |
| `tls<B>` | `Rhp::security::tls::backend` | `Rhp::security::tls::auto_backend` (OpenSSL where found, else Mbed TLS; `tls::none` = no TLS) |
| `codec<C>` | `Rhp::wire::codec` | `Rhp::wire::msgpack` |
| `auth<A>` | `Rhp::security::authenticator` | `Rhp::security::psk_keyring` (clients use `A::credential`) |
| `signer<S>` | `Rhp::security::signer` | `Rhp::security::ed25519` (hosts take `S::trust`, clients sign with `S::key`; `unsigned_scripts` opts out) |
| `executor<X>` | `Rhp::exec::executor` | `Rhp::exec::pumped` |
| `io<I>` | `Rhp::exec::io_runner` | `Rhp::exec::owned_io_thread` |
| `limits<L>` | `Rhp::limits` value | `Rhp::limits{}` (no script limits, run to completion) |
| `errors<M>` | `Rhp::errors::mode` | `Rhp::errors::expected` (`throwing`: calls return `T` and throw `Rhp::exception`) |
| `clock<K>` | `Rhp::exec::clock_source` | `Rhp::exec::steady_clock` |
| `logger<O>` | `Rhp::core::logger` | `Rhp::core::stderr_logger` |
| `discovery<D>` | `Rhp::net::discovery` | `Rhp::net::mdns`; `mdns_wire` forces the own responder, `no_discovery` disables it |
| `hardening<H>` | `Rhp::hardening` value, at least `Rhp::kBuildHardening` | `Rhp::kBuildHardening` (CMake `RHP_HARDENING`; decisions AL1 / AL2) |

Readers: `transport_t`, `tls_t`, `codec_t`, `auth_t`, `credential_t`, `signer_t`, `signing_key_t`, `trust_t`, `executor_t`, `io_t`, `errors_t`, `clock_t`, `logger_t`, `discovery_t`, `limits_v`, `hardening_v`, and `return_t<T>` (the error mode's return type). `Rhp::configuration<C>` accepts anything built from `Rhp::config<>`.

## Rules

- Each slot is constrained where it is written: a bad transport fails on the `::transport<X>` line (`Tests/compile_fail/config_bad_*.cpp`).
- A later link overrides an earlier one for the same slot; the result is always a `Rhp::config<...>`, and `Rhp::config<>` with no links is exactly the default chain.
- In a dependent context write `Cfg::template transport<X>`.
- `hardening<H>` only raises the build's level: a weaker `H` fails on that line (`config_detail::no_weaker_than_build`, `Tests/compile_fail/config_hardening_below_build.cpp`). `Rhp::host` takes `signer<unsigned_scripts>` only at `hardening_v == kDev` (`Rhp::host_configuration`); a client reads `hardening_v` too (above `kDev` it refuses `insecure_lan`).
- Discovery registration is explicit through `host.advertise`; selecting a provider publishes nothing by itself.
- `tls<Rhp::security::tls::none>` builds without TLS: non-loopback endpoints then need `insecure_lan`.

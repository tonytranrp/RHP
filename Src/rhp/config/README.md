# config — layer 5

`Rhp::config<>`: the type-level chain that names every policy of a host or client. Header-only. The module's public name is the class template itself; its helpers live in `Rhp::config_detail`.

```cpp
using my_cfg = Rhp::config<>
    ::transport<Rhp::net::loopback>
    ::io<Rhp::exec::zero_threads>
    ::limits<Rhp::limits{.wall_ms = 5'000}>;
```

| Slot | Concept | Default |
|---|---|---|
| `transport<T>` | `Rhp::net::transport` | `Rhp::net::tcp` |
| `codec<C>` | `Rhp::wire::codec` | `Rhp::wire::msgpack` |
| `auth<A>` | `Rhp::security::authenticator` | `Rhp::security::psk_keyring` (clients use `A::credential`) |
| `signer<S>` | `Rhp::security::signer` | `Rhp::security::ed25519` (hosts take `S::trust`, clients sign with `S::key`; `unsigned_scripts` opts out) |
| `executor<X>` | `Rhp::exec::executor` | `Rhp::exec::pumped` |
| `io<I>` | `Rhp::exec::io_runner` | `Rhp::exec::owned_io_thread` |
| `limits<L>` | `Rhp::limits` value | `Rhp::limits{}` (unlimited, run to completion) |
| `errors<M>` | `Rhp::errors::mode` | `Rhp::errors::expected` |
| `clock<K>` | `Rhp::exec::clock_source` | `Rhp::exec::steady_clock` |
| `logger<O>` | `Rhp::core::logger` | `Rhp::core::stderr_logger` |

## Rules

- Each slot is constrained where it is written: a bad transport fails on the `::transport<X>` line.
- A later link overrides an earlier one for the same slot; the result is always a `Rhp::config<...>`.
- Slots for TLS and discovery are added by the stages that implement them (5–6), never as placeholders.

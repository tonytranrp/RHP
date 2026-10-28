# custom_transport

Your own `Rhp::net::transport`: a `name`, a `network` flag, `listen()` and `dial()` handing out `Rhp::net::link`s. This one wraps the in-process loopback transport and counts the bytes it sends; a Steam P2P socket, a serial link or a company relay has the same shape.

```cpp
struct transport {
    static constexpr std::string_view name = "metered";
    static constexpr bool network = false; // true for anything another machine can reach: the TLS rules then apply
    static Rhp::result<std::unique_ptr<Rhp::net::listener>> listen(Rhp::net::io_context&, const Rhp::endpoint&, Rhp::net::accept_fn);
    static void dial(Rhp::net::io_context&, const Rhp::endpoint&, Rhp::net::connect_fn);
};

using metered_cfg = Rhp::config<>::transport<metered::transport>   // concept-checked on this line
    ::logger<Rhp::core::null_logger>;
```

RHP layers the session on top of any ordered byte stream: framing, CRC32C, the PSK handshake, the per-frame MAC, seq / ack / nack and heartbeats. A transport only moves bytes.

Its link derives from `Rhp::net::link_decorator`, which forwards `loopback()`, `encrypted()` and `channel_binding()` to the wrapped link. Rules for a link: call the handler only on the `io_context`'s thread (use `io_context::post` from elsewhere), report `on_closed` once and never after the link is destroyed, and write queued bytes before closing.

The example signs its scripts with a key it makes for the run (`ed25519_secret_key::generate()`, trusted by the host), as every config above `hardening::kDev` must.

## Build and run

From the repository root:

```bash
cmake --build --preset windows-msvc --target custom_transport
ctest --preset windows-msvc -R example.custom_transport --output-on-failure
```

Or run `build/windows-msvc/Examples/custom_transport/Debug/custom_transport.exe`: it prints the sum a script computed and how many bytes crossed the metered links, and exits with 0 when both links were metered.

More in the guide: [your own transport](../../Docs/guide/connecting.md#your-own-transport).

# core — layer 1

The types every other module speaks. Namespace `Rhp` (the logger concept and loggers in `Rhp::core`, error modes in `Rhp::errors`, JSON in `Rhp::json`). Target `Rhp::core`; depends on `utils`.

| Header | What |
|---|---|
| `error.hpp` | `Rhp::errc` (kPascal codes, `kLastErrc`), `to_string` / `parse_errc` (a code's wire name), `Rhp::error` (`code`, owning `message`, `where`, `traceback`), `make_error`, `std::formatter` for both |
| `result.hpp` | `Rhp::result<T>` = `std::expected<T, Rhp::error>`, `Rhp::fail(errc, "msg", "where")`, `Rhp::exception`, `Rhp::unwrap`, `is_result_v` |
| `errors_mode.hpp` | `Rhp::errors::expected` (calls return `result<T>`) / `Rhp::errors::throwing` (calls return `T`, throw `Rhp::exception`); the `Rhp::errors::mode` concept |
| `value.hpp` | `Rhp::value`: nil, bool, integer, number, string, bytes, array, map; `Rhp::nil`, `Rhp::value_list` |
| `convert.hpp` | `Rhp::convert<T>` customization point, `to_value` / `from_value`, the `to_value_convertible` / `from_value_convertible` concepts; built-ins for scalars, strings, `vector`, `optional`, `map`, ids (`strong_id` as its integer) and `Rhp::error` (a map: code name, message, where, traceback) |
| `ids.hpp` | `strong_id<Tag>`: `module_id`, `request_id`, `session_id`, `identity_id`, `revision_id`; `id_generator` |
| `log.hpp` | `log_level`, the `Rhp::core::logger` concept, `null_logger`, `stderr_logger`, `Rhp::log(...)` |
| `role.hpp` | `Rhp::role` (`kObserve` < `kPatch` < `kAdmin`), `Rhp::allows(have, need)`, `parse_role`, `to_string` |
| `limits.hpp` | `Rhp::limits` (structural, so it is a template argument: `config<>::limits<Rhp::limits{...}>`), `kDefaultLimits`, `cancel_scope` (`kNone` / `kRequests` / `kEverything`: which runs check for cancels); per identity `request_rate` and `pump_requests` (host) |
| `async.hpp` | `Rhp::async<T>` / `Rhp::promise<T>` / `Rhp::make_async<T>()`: a result a binding delivers later, from any thread; `promise::stop_requested()` once the reader is gone; `is_async_v` |
| `json.hpp` | `Rhp::json::parse` / `to_text(value, indent)`: JSON for `Rhp::value` (rhp-cli, test reports, API descriptions); integers stay integers, floats keep a decimal point |
| `subscription.hpp` | `Rhp::subscribable` (hands out ids) and `Rhp::subscription` (RAII, move-only, may outlive its source) |
| `listener_table.hpp` | `Rhp::core::listener_table<Key, Fn>`: callbacks by key, added and removed from any thread, dispatched outside the lock |
| `<rhp/build_config.hpp>` | generated (`cmake/RhpBuildConfig.cmake`): `RHP_ENABLE`, `RHP_TLS_HAS_OPENSSL` / `RHP_TLS_HAS_MBEDTLS`, the target's `RHP_PLATFORM_*`; carried and installed with `Rhp::core` |

```cpp
Rhp::result<int> parse_port(std::string_view text) {
    int port = 0;
    if (std::from_chars(text.data(), text.data() + text.size(), port).ec != std::errc{}) {
        return Rhp::fail(Rhp::errc::kInvalidArgument, "not a number", "parse_port");
    }
    return port;
}

Rhp::async<std::string> fetch(std::string url) {
    auto [later, done] = Rhp::make_async<std::string>();
    std::thread{[done, url] { (void)done.complete(download(url)); }}.detach();
    return std::move(later); // a structured binding is not moved implicitly
}
```

## Rules

- May include `utils` and the standard library only. No Lua, sockets or OS headers.
- `convert<T>` here only knows `Rhp::value`. The script layer adds Lua push / pull on top.
- `Rhp::value` uses the default allocator; `std::pmr` injection applies to a sandbox's Lua allocator (`sandbox_options::memory`) and to `utils::byte_buffer`s you construct, not to values handed to user code.
- Errors never cross the public API as exceptions in `expected` mode. `error::message`, `where` and `traceback` are owning `std::string`s.
- `errc` values only grow (`kLastErrc` names the highest); the wire sends a code's name.
- `async<T>`: the first `complete()` wins (the rest return false); the last promise copy dropped without completing gives the reader an error; `abandon()` requests a stop and hands back an outcome that arrived but wasn't taken, so whoever abandons it can undo it (the sandbox does this; see `script/README.md`).
- `listener_table::remove()` is a barrier: once it returns, that callback neither runs nor starts on another thread. A callback may remove itself. Don't remove from a thread holding a lock the callback takes.
- Each `limits` field's comment in `limits.hpp` says what 0 means (usually unlimited / off; not for `max_frame`, `max_blob`, `revisions`, `pending_handshakes`, `backoff_min_ms` or `cancel_check_instructions`).

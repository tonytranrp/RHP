# core — layer 1

Types every other module speaks. Namespace `Rhp` (logger concept and loggers in `Rhp::core`, error modes in `Rhp::errors`).

| Header | What |
|---|---|
| `error.hpp` | `Rhp::errc` (kPascal values), `Rhp::error`, `std::formatter` for both |
| `result.hpp` | `Rhp::result<T>` = `std::expected<T, Rhp::error>`, `Rhp::fail`, `Rhp::exception`, `Rhp::unwrap` |
| `errors_mode.hpp` | `Rhp::errors::expected` / `Rhp::errors::throwing` policies + `Rhp::errors::mode` concept |
| `value.hpp` | `Rhp::value`: nil, bool, integer, number, string, bytes, array, map; `Rhp::value_list` |
| `convert.hpp` | `Rhp::convert<T>` customization point, `to_value` / `from_value`, built-ins for scalars, strings, `vector`, `optional`, `map`, ids (`strong_id` as its integer) and `Rhp::error` (a map: code name, message, where, traceback) |
| `ids.hpp` | `strong_id<Tag>`: `module_id`, `request_id`, `session_id`, `identity_id`, `revision_id`; `id_generator` |
| `log.hpp` | `log_level`, `Rhp::core::logger` concept, `null_logger`, `stderr_logger`, `Rhp::log(...)` |
| `role.hpp` | `Rhp::role` (`kObserve` < `kPatch` < `kAdmin`), `Rhp::allows(have, need)` |
| `limits.hpp` | `Rhp::limits` — structural, usable as `config<>::limits<Rhp::limits{...}>` |
| `json.hpp` | `Rhp::json::parse` / `to_text(value, indent)`: JSON for `Rhp::value` (rhp-cli, test reports, API descriptions); integers stay integers, floats keep a decimal point |
| `subscription.hpp` | `Rhp::subscribable` (something callbacks subscribe to) and `Rhp::subscription` (RAII, move-only, may outlive its source) |

## Rules

- May include `utils` and the standard library only. No Lua, sockets or threads.
- `convert<T>` here only knows `Rhp::value`. The script layer adds Lua push/pull on top.
- `Rhp::value` uses the default allocator; `std::pmr` injection applies to a sandbox's Lua allocator (`sandbox_options::memory`) and to `utils::byte_buffer`s you construct, not to values handed to user code.
- Errors never cross the public API as exceptions in `expected` mode.

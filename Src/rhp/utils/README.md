# utils — layer 0

Generic building blocks with **zero** RHP, OS, Lua or network knowledge. Namespace `Rhp::utils` (size literals live in `Rhp::literals`).

| Header | What |
|---|---|
| `fixed_string.hpp` | string as a template argument; `is_dotted_name`, `is_identifier` validators |
| `type_list.hpp` | type lists: `at_t`, `contains_v`, `index_of_v`, `is_unique_v`, `concat_t`, `transform_t`, `filter_t`, `for_each_type` |
| `function_traits.hpp` | return type / argument list / arity / noexcept of any callable |
| `scope_guard.hpp` | run-on-exit with `release()` |
| `overloaded.hpp` | lambda overload set for `std::visit` |
| `units.hpp` | `_KiB`, `_MiB`, `_GiB` (overflow is a compile error) |
| `spsc_ring.hpp` | bounded single-producer/single-consumer queue — the only lock-free structure RHP hand-rolls |
| `base64.hpp` | base64 encode/decode (key files, HTTP headers) |
| `byte_buffer.hpp` | growable bytes on an injectable `std::pmr::memory_resource`; little-endian load/store |
| `crc32c.hpp` | CRC-32C for frame integrity |

## Rules

- Only the C++ standard library may be included.
- Everything is header-only except `crc32c.cpp` (keeps the 8 KiB tables out of every includer).
- New utilities must be needed by at least one other module; this is not a dumping ground.

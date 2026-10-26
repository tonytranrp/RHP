# utils — layer 0

Generic building blocks with **zero** RHP, OS, Lua or network knowledge. Namespace `Rhp::utils` (size literals live in `Rhp::literals`). Target `Rhp::utils`; no dependencies.

| Header | What |
|---|---|
| `fixed_string.hpp` | `fixed_string<N>`: a string as a template argument (`Rhp::lib<"game">`); `is_dotted_name`, `is_identifier` (used in `requires` clauses, so a bad name fails where it is written) |
| `type_list.hpp` | `type_list<Ts...>` and `size_v`, `at_t`, `contains_v`, `index_of_v`, `is_unique_v`, `push_back_t`, `push_front_t`, `concat_t`, `transform_t`, `filter_t`, `for_each_type` |
| `function_traits.hpp` | return type, argument list, arity, `noexcept` and class of any callable: `return_type_t`, `args_t`, `arity_v` |
| `scope_guard.hpp` | `scope_guard`: runs a callable on scope exit unless `release()`d |
| `overloaded.hpp` | `overloaded{...}`: a lambda overload set for `std::visit` |
| `units.hpp` | `_KiB`, `_MiB`, `_GiB` (`consteval`: overflow is a compile error) |
| `spsc_ring.hpp` | `spsc_ring<T>`: bounded single-producer / single-consumer queue (`try_push` / `try_emplace` / `try_pop`), capacity rounded up to a power of two |
| `base64.hpp` | `base64_encode`, strict `base64_decode` (no whitespace, padding only at the end) |
| `byte_buffer.hpp` | `byte_buffer`: growable bytes on an injectable `std::pmr::memory_resource`; `bytes_view`, `as_bytes`, little-endian `store_le` / `load_le`, `append_le` / `read_le` |
| `crc32c.hpp` | `crc32c(data, crc)` (CRC-32C, the frame check on non-TLS links), `crc32c_portable` (the tables only, for tests), `crc32c_hasher` (incremental) |

```cpp
using namespace Rhp::literals;
constexpr std::size_t kLimit = 4_MiB;
Rhp::utils::byte_buffer out;
out.append("RHP");
out.append_le(std::uint32_t{7});
const std::uint32_t check = Rhp::utils::crc32c(out.view());
```

## Rules

- Only the C++ standard library may be included.
- Everything is header-only except `crc32c.cpp` (it keeps the tables and the CPU-specific code out of every includer).
- `spsc_ring` is the only lock-free queue RHP hand-rolls. Exactly one thread pushes and one thread pops; each side publishes its index with release and reads the other's with acquire.
- `byte_buffer::append` is one `memcpy` (it may append a view of its own bytes); a buffer's first allocation is 64 bytes, then it doubles.
- `crc32c` uses the CPU instruction where there is one (SSE4.2 on x86-64, checked at run time; the ARMv8 CRC extension when the compiler targets it, or at run time on 64-bit ARM Linux / Android when `RHP_CRC32C_ARM_RUNTIME` is set by CMake), else slicing-by-8 tables. Long inputs run three streams over 8 KiB / 256-byte blocks, combined with compile-time shift tables. Every path gives the same result.
- A new utility must be needed by at least one other module; this is not a dumping ground.

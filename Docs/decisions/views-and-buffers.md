# Typed views, struct views and buffers

**Decision:** C++ memory a script works on in place reaches Lua as a *view*, never as a copy: a
binding returning `std::span<T>` (T arithmetic but `bool`, or `std::byte`) gives a typed view; a
binding returning `T*` / `T&` of a type declared with `::view<"name", T>` gives a struct view whose
`::field<>` / `::ro_field<>` members are read and written in place. A view keeps no pointer: it
remembers its binding and the arguments it was called with and calls the binding again on every
access. Script writes to C++ memory are journaled once per target and running code, the original of
each element (or field byte) copied the first time that code writes it. Scripts get byte buffers of
their own (`rhp.buffer`), which are never journaled. Usage: [guide](../guide/views-and-buffers.md).

## Representation

- Every view is a userdata starting with a `view_node` (`puc_lua/views_impl.hpp`), its payload
  after it: a buffer's bytes, or a host view's `view_source` (the binding and copies of its
  arguments, built in place by the trampoline, destroyed by `__gc`). Typed views of every element
  type share one metatable (`rhp.span`, the element type in the node), buffers have `rhp.buffer`,
  and each struct view type its own (`rhp.view.<name>`, fields in a table of `field_desc`s made at
  compile time from the `::field` entries).
- Children (a slice, a buffer's typed view, a struct's array or nested struct field) are nodes
  with a parent node and an offset, the parent kept alive by uservalue 1. `locate` walks up to the
  memory on every access and checks the child still fits (a parent that shrank raises).
- `__index` reads integer keys as elements (1-based, `kOutOfRange` outside `[1, #v]`) and names as
  methods; `__pairs` walks elements in order (`ipairs` stops with an error at `#v + 1`: making index
  `#v + 1` read nil would silence the most common off-by-one, so it doesn't).
- Bindings: a view result takes `call_view` (`lib_builder.hpp`); a read-only span parameter is a
  plain argument (`arg_kind::kSpan`, the extension point of the plain trampoline); mutable spans,
  tables and struct view parameters take the general path (`stack::to_span`, `stack::to_object`).

## Lifetime: re-resolve on every access

A view calls its binding again (handle arguments checked with `is_alive` first) each time it is
read or written, and when a journaled write is undone. So a module may keep a view across frames:
memory that moved (a vector that grew) is found where it is now, memory that is gone (a dead handle,
a binding now returning `nullptr`) raises `kStaleHandle`, and nothing reads freed memory as long as
what the binding returns is valid until it is called again. Consequences: a binding returning a view
must be a lookup (no `undo<>` / `irreversible`, no `Rhp::async<T>`: compile errors), its parameters
are copied into the view and must own their data (no spans or struct views), and every access pays
one call of it (`fake<L>` records each one). Span *parameters* are valid for the call only.

*Rejected:*
- **Valid during the call only**: useless for results (the call is over when the script has the view).
- **Valid until the request yields or calls another binding** (an epoch bumped in every binding
  call and resume): needs a hook in the call and resume paths, a view kept by a module is dead the
  next frame anyway, and a binding the script calls can still free the memory before the epoch is
  read.
- **Owning handles** (a `shared_ptr` the view keeps alive): puts ownership rules on the
  application's containers; a `std::vector` can't hand out shares of its buffer.
- **Caching the pointer per request**: a binding the script calls in between (`game.spawn`) can grow
  the vector the view points into.

## Undo: one layer per target and running code, copy on first write

The first write of a request (or handler call) to a target makes one journal effect, a
`region_layer` (`puc_lua/view_journal.cpp`), recorded in that sandbox's ledger for the running code.
A target is the view's source: the same binding called with equal arguments (`view_source::same`).
Each write marks its units (a span element; a byte for struct roots, so a field write marks its
field's bytes) and copies the original of a unit the first time the layer writes it, into 4 KiB
pages made on demand. Undo re-resolves the target and copies the originals back where the memory is
now; a target that is gone has nothing to restore. `revert`, failed requests, `revert_to` and
`revert_all` all work through the ledger, like every other effect.

Layers of one target stack process-wide, like variable writes (`var_layers`): undoing a layer hands
each original to the next newer layer that wrote the same unit, else restores it, so any revert
order ends with every unit as if the reverted writes never happened. A node caches the layer it wrote
through last, valid while the registry's epoch (bumped when any layer goes away), the context and
the running owner are unchanged: a write in a loop is one owner check, a bit test and, the first
time, a copy, with no lock. A mutable span handed to C++ is journaled whole before the call (C++ may
write any of it).

*Rejected:*
- **One effect per write**, as variables do: 10k ledger entries (and 10k allocations) for one loop
  over a 10k-element span.
- **A snapshot of the whole target at the first write**: O(size) per request for one element
  (a 64 MiB texture copied to change one pixel); pages copied per unit cost what is written.
- **Targets identified by address**: memory that moved would be restored at the old (freed)
  address, and a new object at a reused address would take another object's originals.
- **A lock per write** (as `var_layers` takes): the memory itself isn't synchronized, so the lock
  would order the journal but not the bytes; a view's memory and journal belong to one thread at a
  time, like the memory.

*Consequences:* two different bindings returning the same memory are different targets (their
layers don't hand originals to each other: reverting them out of order can restore stale values).
A checkpoint taken from inside a running request (a binding calling `sandbox::checkpoint`) doesn't
split that request's layer: writes after it are reverted with the request, not by `revert_to`.

## Buffers

`rhp.buffer.new` / `from` make byte buffers whose bytes are a Lua allocation (counted in
`limits.memory`), with typed reads and writes at 1-based byte positions in either byte order,
`string.pack` / `string.unpack` formats (Lua's own functions, captured when the sandbox opens so a
script can't swap them; `unpack` copies only `string.packsize` bytes when the format has a fixed
size), slices and typed views (no alignment needed: elements are copied with `memcpy`). They are
script state like tables: never journaled, gone when nothing refers to them.

A buffer's `__index` is its methods table: a method lookup is the VM's table lookup instead of a C
call (measured: `read_u32` 3.1x `string.unpack` before, 1.6-2.1x after, with the error label made
only on failure). The price is `b[i]`: a buffer is read and written through its methods, and
`b:view("u8")` is the byte-indexed view.

*Rejected:* 0-based offsets (Luau's `buffer`): Lua itself (`string.byte`, `string.unpack`) and the
typed views count from 1. Silently wrapping out-of-range integers on writes: a write that doesn't
fit raises `kOutOfRange`, like every other binding. Indexing buffers (`b[i]`) through a C `__index`:
every method call would pay a C call first.

## Measured

[Benchmarks](../benchmarks.md#typed-views-struct-views-and-buffers), against raw twins in the same
run (this machine moved raw rows by up to 50% between runs, so these are ranges): reading a typed
view costs what a hand-written userdata with a C `__index` costs (0.7-1.0x); a journaled write
1.35-2.3x the twin's unjournaled one (about 20 ns a write in the 10-pass row: an owner check, a bit
test, the first time a copy); a span handed to C++ about 7x less than a C function reading a table;
a struct view's field about a raw userdata's cost (5-10x a table field). Every access finds the
memory through `view_source::find` (a bool; the `Rhp::result<>` with the reason is made by
`resolve()` only on failure), and a node that journaled in a sandbox skips the role check after.

## Types

- Span elements are arithmetic types but `bool` (no `std::vector<bool>` to view, and a byte view of
  a `bool` array could write invalid bools) and `std::byte`; extents are dynamic; elements convert
  as other bindings do (an integer must fit, `u64` above `2^63 - 1` reads as a float).
- A span parameter takes views of exactly its element type (the point is no copy; a table is the
  converting path). One-byte element types also take buffers, byte views and Lua strings.
- View types are standard-layout classes (fixed field offsets; a polymorphic or otherwise
  non-standard-layout type doesn't compile); fields are numbers, bools, enums (as integers), arrays
  of span elements (typed views) or structs of another declared view type (nested views).
- Struct views pass to parameters of their type by value, `const T&` and `const T*`.

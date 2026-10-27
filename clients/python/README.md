# rhp-client (Python)

A pure-Python client for RHP hosts: connect with an identity file, run signed Lua, load and call modules, push blobs, watch events, drive releases, tunables, the profiler and the debugger. It speaks RHP's native protocol (revision 6) itself over TCP, or TLS 1.3 with pyOpenSSL, so it needs no C++ build, and it interoperates with `Rhp::host<>`, `rhp-cli` and `headless_server`. Python 3.9 or newer; no required dependencies.

```python
import rhp_client as rhp

me = rhp.Identity.load("dev.rhpid")              # rhp-cli keygen dev (or: python -m rhp_client keygen dev)
with rhp.connect("127.0.0.1", 7777, me) as host:
    print(host.exec("return 6 * 7"))            # [42]
    mod = host.load("low_grav", "local M = {} function M.set(g) game.gravity = g end return M")
    host.call(mod, "set", -1.6)
    host.on("game.round_over", lambda e: print(e.name, e.args))
    print(host.unload(mod))                     # RevertSummary(undone=1, ...): gravity is back
```

## Install

From a checkout of RHP:

```bash
pip install ./clients/python
pip install "./clients/python[tls,crypto]"
```

Extras: `tls` (pyOpenSSL: TLS 1.3 with the RFC 9266 channel binding RHP's handshake needs), `crypto` (`cryptography`: fast, constant-time Ed25519; without it a pure-Python RFC 8032 signer is used), `speed` (`crc32c`: hardware CRC32C for big frames on plain connections), `test` (pytest).

RHP has no release numbers; the package's version is `0+stage11`, the stage whose protocol it was written for. A host and its clients must speak the same protocol revision (`rhp_client.PROTOCOL_REVISION`).

## Connecting

`rhp.connect(host, port, identity, **options)` returns a connected `Client` (`Client(...).connect()` does the same). It is a context manager: leaving the `with` block closes the session, and the host then reverts what this identity's scripts did unless a module is pinned. `client.connected`, `client.welcome` (session, identity, role, heartbeat, platform) and `client.role` describe the session.

| Option | Default | What |
|---|---|---|
| `tls` | TLS except on loopback | `True` / `False` to force; TLS needs the `tls` extra |
| `ca_file` | none | check the host's certificate against this CA. Without it the certificate isn't checked: the key proofs are bound to the TLS connection, so a relay that terminates TLS can't authenticate |
| `timeout` | 10 s | connect and handshake |
| `request_timeout` | none | how long a blocking call waits for its reply |
| `resume` | `True` | when the link drops, reconnect and continue the same session; requests in flight are sent again and run once |
| `resume_window` | 6 s | how long to keep trying (the host keeps a session for `limits.resume_ms`, 6 s by default) |
| `platform` | `"python"` | the OS name this client reports in the handshake |
| `on_output` | none | `fn(request, line)` for every `print()` of this session's scripts |
| `on_emit` | none | `fn(request, module, value)` for every `rhp.emit` |
| `on_closed` | none | `fn(error)` when the session ends for good |
| `trace` | none | `fn("send" \| "recv", raw frame bytes, op name)`: every frame, for debugging |

## Operations

Each blocks for its reply and raises `RhpError` (`.code`, `.message`, `.where`, `.traceback`) on failure. `exec_async`, `load_async` and `call_async` return a `concurrent.futures.Future`; any call can come from any thread.

| Method | Returns |
|---|---|
| `exec(source, chunk="exec")` | the values the chunk returned (list) |
| `load(name, source)` | module id |
| `call(module, function, *args)` | the values the function returned |
| `reload(module, source)` / `rollback(module, steps=1)` | new revision (0 if deferred) |
| `revert(module)` / `unload(module, force=False)` / `revert_to(tag)` / `revert_all()` | `RevertSummary` |
| `checkpoint(tag)`, `pin(module)`, `unpin(module)` | `None` |
| `list()` / `status(module)` | `ModuleStatus` list / one |
| `describe()` | LuaLS annotations for what this identity may use |
| `cancel(request_or_future=0)` | stops one request (or all in flight); it fails with `cancelled` |
| `blob(sink, name, data, chunk=65536, window=4)` | the sink's verdict (the host registered the sink with `host.on_blob`) |
| `on(name, callback)` / `off(id)` | subscribe to a C++ `lua_event` of the host program, or to `rhp.publish` of this identity's scripts (`"*"`: every publish); callbacks get an `Event` (`name`, `module`, `args`, `dropped`) |
| `release_apply(envelope, confirm="now")`, `release_confirm(channel, expected=b"")`, `release_deactivate(channel, hold=False, expected=b"")` | admin: run a signed `.rhprel`; confirm or stop what a channel runs (returns the release id; `expected` binds it to one release) |
| `release_status()` / `revoke(envelope)` | the host's channels / apply a signed `.rhprev` (channels changed) |
| `tunables(prefix="")` / `tune(path, value)` | the variables the host's libs expose (`Tunable`: value, range, step, unit, doc) / set one as a script would (patch) |
| `profile("start" \| "read" \| "stop", interval=1000)` | `ProfileReport`: samples per folded stack (`.folded()` for flame graphs) |
| `debug(action, **fields)` | the debugger (patch): `break` (source, lines), `pause`, `paused`, `continue` / `into` / `over` / `out` (request), `stack` (request), `variables` (request, frame, scope, path), `evaluate` (request, frame, expression), `reset`; pauses arrive as the event `rhp.debug` |

Modules are named by id or by name. Scripts are signed with the identity's `signing_key` when it has one; an identity without one can only run code as an `observe` session.

## Command line

`python -m rhp_client` (installed as `rhp-py` too):

```bash
python -m rhp_client -i dev.rhpid 127.0.0.1:7777 exec "return 6 * 7"
python -m rhp_client -i dev.rhpid 127.0.0.1:7777 load low_grav low_grav.lua
python -m rhp_client -i dev.rhpid 127.0.0.1:7777 call low_grav set -1.6
python -m rhp_client -i dev.rhpid 127.0.0.1:7777 events game.round_over
python -m rhp_client keygen dev
```

Commands: `exec`, `load`, `call` (arguments parse as JSON when they can, else stay strings), `unload [--force]`, `revert`, `list`, `describe`, `events`. Options: `--tls` (TLS on loopback too), `--plain` (no TLS; the host must allow it with `insecure_lan`), `--ca FILE`. Exit status: 0 ok, 1 an RHP error, 2 bad usage.

`keygen NAME [--role observe|patch|admin] [--show-secret]` writes `NAME.rhpid` (never overwriting) and prints the host's keyring and signers lines, as `rhp-cli keygen` does: the role defaults to `patch` (`admin` prints a warning), and the keyring line shows `<psk from NAME.rhpid>` instead of the key unless `--show-secret` is given. The file is written to a temporary created exclusively with mode 0600, then renamed into place. On Windows Python's mode only sets the read-only flag, so the file gets its folder's permissions (your own folders are private to you; `rhp-cli keygen` sets an owner-only DACL instead).

## Threads

Replies, output, emits and events are handled on the client's reading thread. Keep callbacks short and don't make a blocking call from one (it would wait for the thread that has to deliver its reply): such a call raises `invalid_argument`; use an `*_async` form there.

## Tests

```bash
pip install "./clients/python[test]"
pytest clients/python/tests
```

`tests/test_keygen.py` checks keygen's file and output. `tests/test_protocol.py` checks the codec, frames, handshake derivations and Ed25519 against golden vectors (`tests/vectors.json`; RHP's C++ suite checks the same frames). `tests/test_live.py` runs sessions against RHP's own host when `RHP_HEADLESS_SERVER` names a built `headless_server` and is skipped otherwise; RHP's ctest sets it (`python.client`, when Python 3 with pytest is found and `RHP_BUILD_EXAMPLES` is on).

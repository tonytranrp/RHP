"""A client for an RHP host (the Python counterpart of Rhp::client<>).

    import rhp_client as rhp

    me = rhp.Identity.load("dev.rhpid")
    with rhp.connect("127.0.0.1", 7777, me) as host:
        print(host.exec("return 6 * 7"))          # [42]
        mod = host.load("low_grav", source)       # signed with the identity's key
        host.call(mod, "set", 1.6)
        host.on("game.round_over", print)         # events the host publishes
        host.unload(mod)

Every operation blocks for its reply and raises RhpError on failure; the *_async forms return a
concurrent.futures.Future instead. Calls may come from any thread. Replies, script output, emits and
events are handled on the client's reading thread: keep callbacks short and never make a blocking
call from one (it would wait for the thread that has to deliver its reply).
"""

from __future__ import annotations

import os
import threading
import time
from concurrent.futures import Future
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from ._errors import RhpError
from ._frame import Op
from ._session import Session
from ._transport import is_loopback, open_stream
from .identity import Identity, sign_script

__all__ = ["Client", "connect", "RevertSummary", "ModuleStatus", "Event", "Tunable", "ProfileReport"]

ModuleRef = Union[int, str]  # a module id, or its name


@dataclass
class RevertSummary:
    undone: int = 0
    irreversible: int = 0
    failures: List[RhpError] = field(default_factory=list)
    deferred: bool = False

    @property
    def clean(self) -> bool:
        return not self.failures

    @classmethod
    def from_value(cls, v: Any) -> "RevertSummary":
        v = v or {}
        return cls(v.get("undone", 0), v.get("irreversible", 0), [RhpError.from_value(f) for f in v.get("failures") or []],
                   bool(v.get("deferred", False)))


@dataclass
class ModuleStatus:
    id: int
    name: str
    state: str  # "active", "reverted", "faulted", "loading"
    scratch: bool = False
    effects: int = 0
    irreversible_effects: int = 0
    revision: int = 0
    source_hash: int = 0
    revisions: int = 0
    reloading: bool = False
    dependencies: List[int] = field(default_factory=list)
    fault: Optional[RhpError] = None
    pinned: bool = False

    @classmethod
    def from_value(cls, v: Any) -> "ModuleStatus":
        return cls(v.get("id", 0), v.get("name", ""), v.get("state", ""), bool(v.get("scratch", False)), v.get("effects", 0),
                   v.get("irreversible_effects", 0), v.get("revision", 0), v.get("source_hash", 0), v.get("revisions", 0),
                   bool(v.get("reloading", False)), list(v.get("dependencies") or []),
                   RhpError.from_value(v["fault"]) if v.get("fault") is not None else None, bool(v.get("pinned", False)))


@dataclass
class Event:
    """One delivery of a subscribed event."""

    name: str
    args: List[Any]
    module: int = 0  # the publishing module (0: C++ or the sandbox itself)
    dropped: int = 0  # deliveries to this session the host dropped since the previous one


@dataclass
class Tunable:
    """A variable a host lib exposes (::var / ::ro), with its value and tags."""

    path: str
    type: str
    value: Any
    writable: bool = False
    min: Optional[float] = None
    max: Optional[float] = None
    step: Optional[float] = None
    unit: str = ""
    doc: str = ""

    @classmethod
    def from_value(cls, v: Any) -> "Tunable":
        return cls(v.get("path", ""), v.get("type", "any"), v.get("value"), bool(v.get("writable", False)), v.get("min"), v.get("max"),
                   v.get("step"), v.get("unit", "") or "", v.get("doc", "") or "")


@dataclass
class ProfileReport:
    """What the sampling profiler saw: `stacks` maps a folded stack ("outer;inner") to its samples."""

    running: bool = False
    interval: int = 0
    samples: int = 0
    dropped: int = 0
    elapsed_us: int = 0
    stacks: List[tuple] = field(default_factory=list)  # (stack, samples), most samples first
    truncated: int = 0  # stacks with the fewest samples the host left out to fit one reply

    @classmethod
    def from_value(cls, v: Any) -> "ProfileReport":
        v = v or {}
        return cls(bool(v.get("running", False)), v.get("interval", 0), v.get("samples", 0), v.get("dropped", 0), v.get("elapsed_us", 0),
                   [(s[0], s[1]) for s in v.get("stacks") or []], v.get("truncated", 0))

    def folded(self) -> str:
        """The `stack samples` lines flamegraph.pl and speedscope read."""
        return "".join("%s %d\n" % (stack, n) for stack, n in self.stacks)


def _mix64(x: int) -> int:
    """splitmix64's finalizer: a bijection, so a counter run through it never repeats a key."""
    mask = (1 << 64) - 1
    x = (x + 0x9E3779B97F4A7C15) & mask
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & mask
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & mask
    return x ^ (x >> 31)


class Client:
    """Use connect() (or Client(...).connect()). Closing it (or leaving its `with` block) ends the
    session: the host then reverts what this identity's scripts did unless a module is pinned."""

    def __init__(self, host: str, port: int, identity: Identity, *, tls: Optional[bool] = None, ca_file: Optional[str] = None,
                 platform: str = "python", timeout: float = 10.0, request_timeout: Optional[float] = None, resume: bool = True,
                 resume_window: float = 6.0, on_output: Optional[Callable[[int, str], None]] = None,
                 on_emit: Optional[Callable[[int, int, Any], None]] = None,
                 on_closed: Optional[Callable[[RhpError], None]] = None, trace: Optional[Callable[[str, bytes, str], None]] = None):
        self.host = host
        self.port = port
        self.identity = identity
        # TLS by default for anything but loopback, like RHP's own clients.
        self.tls = (not is_loopback(host)) if tls is None else tls
        self.ca_file = ca_file
        self.platform = platform
        self.timeout = timeout
        self.request_timeout = request_timeout
        self.resume_enabled = resume
        self.resume_window = resume_window
        self.on_output = on_output
        self.on_emit = on_emit
        self.on_closed = on_closed
        self._trace = trace
        self._session: Optional[Session] = None
        self._reader: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._pending: Dict[int, Future] = {}
        self._last_req = 0
        self._key_seed = int.from_bytes(os.urandom(8), "little")
        self._key_count = 0
        self._listeners: Dict[str, Dict[int, Callable[[Event], None]]] = {}
        self._listener_ids = 0
        self._closing = False
        self._closed = threading.Event()
        self._failure: Optional[RhpError] = None

    # ---- lifetime -----------------------------------------------------------------------------------

    def connect(self) -> "Client":
        stream = open_stream(self.host, self.port, self.tls, self.ca_file, self.timeout)
        session = Session(stream, self.identity, self.platform, trace=self._trace)
        try:
            session.handshake(self.timeout)
        except BaseException:
            stream.close()
            raise
        self._session = session
        self._reader = threading.Thread(target=self._run, name="rhp-client %s:%d" % (self.host, self.port), daemon=True)
        self._reader.start()
        return self

    def close(self) -> None:
        with self._lock:
            if self._closing:
                return
            self._closing = True
        if self._session is not None:
            self._session.close()
        if self._reader is not None and self._reader is not threading.current_thread():
            self._reader.join(timeout=2.0)
        self._fail_all(RhpError("cancelled", "the client closed", "client"))
        self._closed.set()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def connected(self) -> bool:
        return self._session is not None and not self._closed.is_set()

    @property
    def welcome(self) -> dict:
        """What the host said at connect time: session, identity, role, heartbeat_ms, platform."""
        return self._session.welcome if self._session else {}

    @property
    def role(self) -> str:
        return self.welcome.get("role", "")

    # ---- requests -----------------------------------------------------------------------------------

    def _next_key(self) -> int:
        with self._lock:
            self._key_count += 1
            count = self._key_count
        k = _mix64((self._key_seed + count) & ((1 << 64) - 1)) & 0x7FFFFFFFFFFFFFFF
        return k or 1

    def _start(self, op: int, body: Any) -> Future:
        if self._session is None:
            raise RhpError("invalid_argument", "connect() first", "client")
        future: Future = Future()
        with self._lock:
            if self._failure is not None or self._closing:
                future.set_exception(self._failure or RhpError("cancelled", "the client closed", "client"))
                return future
            self._last_req += 1
            req = self._last_req
            self._pending[req] = future
        future.rhp_request = req  # type: ignore[attr-defined]
        try:
            self._session.send(op, {"req": req, "idem": self._next_key(), "body": body})
        except RhpError as exc:
            with self._lock:
                self._pending.pop(req, None)
            if not future.done():
                future.set_exception(exc)
        return future

    def _wait(self, future: Future) -> Any:
        if self._reader is threading.current_thread():
            raise RhpError("invalid_argument", "a blocking call on the client's own thread (a callback) would wait for itself; use the *_async form",
                           "client")
        try:
            return future.result(self.request_timeout)
        except TimeoutError:
            raise RhpError("timeout", "no reply within %.1f s" % self.request_timeout, "client") from None

    def _code_body(self, source: str, extra: Dict[str, Any]) -> Dict[str, Any]:
        body = dict(extra)
        body["source"] = source
        body["signature"] = sign_script(self.identity, source)
        return body

    # Each operation: the blocking form and its *_async form (a Future of the same value).

    def exec_async(self, source: str, chunk: str = "exec") -> Future:
        return self._start(Op.EXEC, {"source": source, "chunk": chunk, "signature": sign_script(self.identity, source)})

    def exec(self, source: str, chunk: str = "exec") -> List[Any]:
        """Runs `source` in the scratch module; returns every value it returned."""
        return self._wait(self.exec_async(source, chunk))

    def load_async(self, name: str, source: str) -> Future:
        return self._start(Op.LOAD, {"name": name, "source": source, "signature": sign_script(self.identity, source)})

    def load(self, name: str, source: str) -> int:
        """Loads (or reloads) a module; returns its id."""
        return self._wait(self.load_async(name, source))

    def call_async(self, module: ModuleRef, function: str, *args: Any) -> Future:
        return self._start(Op.CALL, {"module": module, "function": function, "args": list(args)})

    def call(self, module: ModuleRef, function: str, *args: Any) -> List[Any]:
        """Calls an exported function of a loaded module."""
        return self._wait(self.call_async(module, function, *args))

    def reload(self, module: ModuleRef, source: str) -> int:
        """Transactional reload; returns the new revision (0 when deferred)."""
        return self._wait(self._start(Op.RELOAD, {"module": module, "source": source, "signature": sign_script(self.identity, source)}))

    def rollback(self, module: ModuleRef, steps: int = 1) -> int:
        return self._wait(self._start(Op.ROLLBACK, {"module": module, "steps": steps}))

    def revert(self, module: ModuleRef) -> RevertSummary:
        return RevertSummary.from_value(self._wait(self._start(Op.REVERT, {"module": module})))

    def unload(self, module: ModuleRef, force: bool = False) -> RevertSummary:
        return RevertSummary.from_value(self._wait(self._start(Op.UNLOAD, {"module": module, "force": force})))

    def checkpoint(self, tag: str) -> None:
        self._wait(self._start(Op.CHECKPOINT, {"tag": tag}))

    def revert_to(self, tag: str) -> RevertSummary:
        return RevertSummary.from_value(self._wait(self._start(Op.REVERT_TO, {"tag": tag})))

    def revert_all(self) -> RevertSummary:
        return RevertSummary.from_value(self._wait(self._start(Op.REVERT_ALL, None)))

    def list(self) -> List[ModuleStatus]:
        return [ModuleStatus.from_value(m) for m in self._wait(self._start(Op.LIST, None)) or []]

    def status(self, module: ModuleRef) -> ModuleStatus:
        return ModuleStatus.from_value(self._wait(self._start(Op.STATUS, {"module": module})))

    def describe(self) -> str:
        """LuaLS annotations for what this identity can use on the host."""
        return self._wait(self._start(Op.DESCRIBE, None))

    def pin(self, module: ModuleRef) -> None:
        self._wait(self._start(Op.PIN, {"module": module}))

    def unpin(self, module: ModuleRef) -> None:
        self._wait(self._start(Op.UNPIN, {"module": module}))

    def cancel(self, request: Union[int, Future] = 0) -> None:
        """Stops one request (a request id, or the Future an *_async call returned), or every request
        in flight (0). Never answered: the stopped request fails with "cancelled"."""
        target = getattr(request, "rhp_request", request)
        if self._session is not None:
            self._session.send(Op.CANCEL, {"req": 0, "body": {"target": int(target)}})

    def blob(self, sink: str, name: str, data: bytes, chunk: int = 64 * 1024, window: int = 4) -> Any:
        """Pushes `data` to a sink the host registered (host.on_blob); returns the sink's verdict."""
        transfer = self._next_key()
        total = len(data)
        offsets = list(range(0, total, chunk)) or [0]
        in_flight: List[Future] = []
        result = None
        for offset in offsets:
            piece = bytes(data[offset:offset + chunk])
            in_flight.append(self._start(Op.BLOB, {"transfer": transfer, "sink": sink, "name": name, "total": total, "offset": offset, "data": piece}))
            if len(in_flight) >= window:
                result = self._wait(in_flight.pop(0))
        while in_flight:
            result = self._wait(in_flight.pop(0))
        return result

    # ---- releases (a host that serves a release manager) ----------------------------------------------

    def release_apply(self, envelope: bytes, confirm: str = "now") -> dict:
        """Admin: runs a signed release envelope (a .rhprel file). `confirm`: "now", "health" or "manual"."""
        return self._wait(self._start(Op.RELEASE_APPLY, {"envelope": bytes(envelope), "confirm": confirm}))

    def release_confirm(self, channel: str, expected: bytes = b"") -> bytes:
        """Admin: the channel's running candidate becomes active; returns its id. With `expected` (a
        release id), only if that is the candidate."""
        return self._wait(self._start(Op.RELEASE_CONFIRM, {"channel": channel, "hold": False, "release": bytes(expected)}))

    def release_deactivate(self, channel: str, hold: bool = False, expected: bytes = b"") -> bytes:
        """Admin: stops what runs in the channel (falling back, or with `hold` running nothing); returns its id."""
        return self._wait(self._start(Op.RELEASE_DEACTIVATE, {"channel": channel, "hold": hold, "release": bytes(expected)}))

    def release_status(self) -> dict:
        """The host's channels: {app, build, platform, revocation_seq, channels: [...]}."""
        return self._wait(self._start(Op.RELEASE_STATUS, None))

    def revoke(self, envelope: bytes) -> int:
        """Sends a signed revocation list (a .rhprev file); returns how many channels changed."""
        return self._wait(self._start(Op.REVOKE, {"envelope": bytes(envelope)}))

    def trust(self, documents: List[bytes]) -> dict:
        """Sends trust documents for the host's release manager: root of trust versions (.rhproot files;
        consecutive versions walk as one chain) and identity revocation lists (.rhpidrev), applied in
        order. Returns {root_version, identity_seq} as the host holds them afterwards."""
        return self._wait(self._start(Op.TRUST, {"documents": [bytes(d) for d in documents]}))

    # ---- tools: this identity's own sandbox ------------------------------------------------------------

    def tunables(self, prefix: str = "") -> List[Tunable]:
        """The variables the host's libs expose, with values and tags (a lib or path prefix, or all)."""
        return [Tunable.from_value(t) for t in self._wait(self._start(Op.TUNABLES, {"prefix": prefix})) or []]

    def tune(self, path: str, value: Any) -> None:
        """Patch: writes a variable as a script would (its range checked, journaled like an exec)."""
        self._wait(self._start(Op.TUNE, {"path": path, "value": value}))

    def profile(self, action: str = "read", interval: int = 1000) -> ProfileReport:
        """The sampling profiler: "start" (every `interval` instructions), "read" or "stop"."""
        body = {"action": action, "interval": interval, "max_depth": 64, "max_stacks": 10000}
        return ProfileReport.from_value(self._wait(self._start(Op.PROFILE, body)))

    def debug(self, action: str, **fields: Any) -> dict:
        """Patch: the debugger. `action` is "break" (source=, lines=), "pause", "paused", "continue" /
        "into" / "over" / "out" (request=), "stack" (request=), "variables" (request=, frame=, scope=,
        path=), "evaluate" (request=, frame=, expression=) or "reset". Pauses are the event
        "rhp.debug" (subscribe with on()). Returns {lines, paused, frames, variables}."""
        body = {"action": action}
        body.update(fields)
        return self._wait(self._start(Op.DEBUG, body))

    # ---- events -------------------------------------------------------------------------------------

    def on(self, name: str, callback: Callable[[Event], None]) -> int:
        """Calls `callback(event)` for every `name` event: a C++ lua_event the host program fires, or an
        rhp.publish of this identity's scripts ("*": every publish). Returns an id for off()."""
        with self._lock:
            first = name not in self._listeners
            self._listener_ids += 1
            listener = self._listener_ids
            self._listeners.setdefault(name, {})[listener] = callback
        if first:
            try:
                self._wait(self._start(Op.SUBSCRIBE, {"name": name}))
            except RhpError:
                with self._lock:
                    self._listeners.get(name, {}).pop(listener, None)
                    if not self._listeners.get(name):
                        self._listeners.pop(name, None)
                raise
        return listener

    def off(self, listener: int) -> None:
        with self._lock:
            for name, callbacks in self._listeners.items():
                if listener in callbacks:
                    del callbacks[listener]
                    last = not callbacks
                    if last:
                        del self._listeners[name]
                    break
            else:
                return
        if last:
            self._wait(self._start(Op.UNSUBSCRIBE, {"name": name}))

    # ---- the reading thread -------------------------------------------------------------------------

    def _run(self) -> None:
        session = self._session
        assert session is not None
        interval = session.heartbeat_s or None
        next_tick = time.monotonic() + interval if interval else None
        while True:
            try:
                wait = None if next_tick is None else max(0.0, next_tick - time.monotonic())
                for op, envelope in session.poll(wait):
                    self._deliver(op, envelope)
                if next_tick is not None and time.monotonic() >= next_tick:
                    session.heartbeat()
                    next_tick = time.monotonic() + interval
            except RhpError as exc:
                if self._closing:
                    return
                if self.resume_enabled and exc.code in ("transport", "timeout") and self._resume(session):
                    next_tick = time.monotonic() + interval if interval else None
                    continue
                self._end(exc)
                return

    def _resume(self, session: Session) -> bool:
        deadline = time.monotonic() + self.resume_window
        delay = 0.25
        while time.monotonic() < deadline and not self._closing:
            try:
                stream = open_stream(self.host, self.port, self.tls, self.ca_file, min(self.timeout, self.resume_window))
                session.resume(stream, self.timeout)
                return True
            except RhpError as exc:
                if exc.code == "auth":
                    return False  # the host forgot the session (or a relay is in the way): resuming can't work
                time.sleep(min(delay, max(0.0, deadline - time.monotonic())))
                delay = min(delay * 2, 2.0)
        return False

    def _end(self, why: RhpError) -> None:
        with self._lock:
            self._failure = why
        self._fail_all(why)
        self._closed.set()
        if self.on_closed is not None:
            try:
                self.on_closed(why)
            except Exception:  # noqa: BLE001 - a throwing callback must not take the client down
                pass

    def _fail_all(self, why: RhpError) -> None:
        with self._lock:
            pending, self._pending = self._pending, {}
        for future in pending.values():
            if not future.done():
                future.set_exception(why)

    def _deliver(self, op: int, envelope: dict) -> None:
        req = envelope.get("req", 0)
        body = envelope.get("body")
        try:
            if op in (Op.RESULT, Op.ERROR):
                with self._lock:
                    future = self._pending.pop(req, None)
                if future is not None and not future.done():
                    if op == Op.RESULT:
                        future.set_result(body)
                    else:
                        future.set_exception(RhpError.from_value(body))
            elif op == Op.OUTPUT:
                if self.on_output is not None and isinstance(body, str):
                    self.on_output(req, body)
            elif op == Op.EMIT:
                if self.on_emit is not None and isinstance(body, dict):
                    self.on_emit(req, body.get("module", 0), body.get("value"))
            elif op == Op.EVENT and isinstance(body, dict):
                event = Event(body.get("name", ""), list(body.get("args") or []), body.get("module", 0), body.get("dropped", 0))
                with self._lock:
                    callbacks = list(self._listeners.get(event.name, {}).values()) + [
                        cb for name, cbs in self._listeners.items() if name == "*" and event.name != "*" for cb in cbs.values()
                    ]
                for callback in callbacks:
                    try:
                        callback(event)
                    except Exception:  # noqa: BLE001 - one bad listener mustn't end the session
                        pass
        except Exception:  # noqa: BLE001 - an output or emit callback threw: dropped
            pass


def connect(host: str, port: int, identity: Identity, **options: Any) -> Client:
    """Connects and authenticates; see Client for the options."""
    return Client(host, port, identity, **options).connect()

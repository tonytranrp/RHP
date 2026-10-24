"""The client side of an RHP session (Src/rhp/session/session.cpp): the pre-shared-key handshake,
sealed frames, cumulative acks with nack-driven resends, heartbeats and resume.

Thread model: one reading thread calls poll(); any thread may send. All mutable state is guarded by
one lock, which is never held while reading from the stream.
"""

from __future__ import annotations

import os
import struct
import threading
import time
from typing import Callable, List, Optional, Tuple

from . import _msgpack as msgpack
from ._errors import RhpError
from ._frame import (FLAG_MAC, PROTOCOL_REVISION, FrameDecoder, Op, encode_frame, is_sequenced, mac32)
from ._transport import Stream
from .identity import Identity

__all__ = ["Session", "Message"]

_HANDSHAKE_MAX_PAYLOAD = 16 * 1024  # before the welcome a peer may only send small frames
_DEFAULT_MAX_FRAME = 4 * 1024 * 1024  # limits.max_frame

Message = Tuple[int, dict]  # (op, envelope) of a delivered sequenced frame


def _transcript(name: str, client_nonce: bytes, host_nonce: bytes, binding: bytes) -> bytes:
    """What both proofs and both session keys are derived from (security/psk_keyring.cpp)."""
    n = name.encode("utf-8")
    return struct.pack("<I", len(n)) + n + client_nonce + host_nonce + binding


def _derive(psk: bytes, label: str, transcript: bytes) -> bytes:
    return mac32(psk, label.encode("ascii") + transcript)


class Session:
    def __init__(self, stream: Stream, identity: Identity, platform: str = "python", max_frame: int = _DEFAULT_MAX_FRAME,
                 trace: Optional[Callable[[str, bytes, str], None]] = None):
        self._stream = stream
        self._identity = identity
        self._platform = platform
        self._max_frame = max_frame
        self._trace = trace
        self._decoder = FrameDecoder(_HANDSHAKE_MAX_PAYLOAD)
        self._lock = threading.RLock()
        self._c2h: Optional[bytes] = None
        self._h2c: Optional[bytes] = None
        self._next_seq = 1  # our next sequenced frame
        self._expected = 1  # the peer's next sequenced frame
        self._control_out = 0
        self._control_in = 0
        self._peer_acked = 0
        self._unacked: List[Tuple[int, int, bytes]] = []  # (seq, op, payload)
        self._heard = True
        self._misses = 0
        self._acked_at_tick = 0
        self._nacked_at = 0
        self.welcome: dict = {}
        self.session_id = 0
        self.heartbeat_s = 0.0
        self.closed = False

    # ---- writing ------------------------------------------------------------------------------------

    def _write(self, op: int, seq: int, payload: bytes, sealed: bool) -> None:
        raw = encode_frame(op, seq, self._expected - 1, payload, self._c2h if sealed else None, crc=not self._stream.encrypted)
        if self._trace:
            self._trace("send", raw, Op.name(op))
        self._stream.send_all(raw)

    def send_control(self, op: int) -> None:
        with self._lock:
            self._control_out += 1
            self._write(op, self._control_out, b"", True)

    def send(self, op: int, envelope: dict) -> int:
        """Sends a sequenced, sealed frame (a request); it is kept until the host acknowledges it."""
        payload = msgpack.encode(envelope)
        if len(payload) > self._max_frame:
            raise RhpError("limit_exceeded", "a %d-byte request exceeds the %d-byte frame limit" % (len(payload), self._max_frame), "client")
        with self._lock:
            if self.closed:
                raise RhpError("transport", "the session is closed", "client")
            seq = self._next_seq
            self._next_seq += 1
            self._unacked.append((seq, op, payload))
            try:
                self._write(op, seq, payload, True)
            except RhpError as exc:
                if exc.code != "transport":
                    raise
                # The link is down: the frame stays queued and goes out again after a resume (the
                # reading thread notices the broken link); if the session can't resume, the client
                # fails the request then.
            return seq

    def close(self, reason: Optional[RhpError] = None) -> None:
        """Tells the host why (an unsequenced error frame) and closes the stream."""
        with self._lock:
            if self.closed:
                return
            self.closed = True
            why = reason or RhpError("cancelled", "closed", "client")
            try:
                if self._c2h is not None:
                    self._write(Op.ERROR, 0, msgpack.encode(why.to_value()), True)
            except RhpError:
                pass
        self._stream.close()

    # ---- reading ------------------------------------------------------------------------------------

    def _read_frame(self, timeout: Optional[float]):
        """The next decoded frame, or None when `timeout` passed first."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            frame = self._decoder.next()
            if frame is not None:
                if self._trace:
                    self._trace("recv", frame.raw, "%s %s" % (Op.name(frame.op), frame.status))
                return frame
            left = None if deadline is None else max(0.0, deadline - time.monotonic())
            data = self._stream.receive(left)
            if data is None:
                return None
            if data == b"":
                raise RhpError("transport", "the host closed the connection", "client")
            self._decoder.feed(data)

    def _expect(self, timeout: float, what: str):
        frame = self._read_frame(timeout)
        if frame is None:
            raise RhpError("timeout", "no %s from the host within %.1f s" % (what, timeout), "client")
        if frame.status != "frame":
            raise RhpError("protocol", "a %s frame from the host (%s)" % (Op.name(frame.op), frame.status), "client")
        if frame.op == Op.ERROR:
            raise RhpError.from_value(msgpack.decode(frame.payload))
        return frame

    # ---- handshake ----------------------------------------------------------------------------------

    def handshake(self, timeout: float = 5.0) -> dict:
        identity = self._identity
        client_nonce = os.urandom(32)
        hello = {"rev": PROTOCOL_REVISION, "platform": self._platform, "auth": {"key": identity.name, "nonce": client_nonce}}
        self._write(Op.HELLO, 0, msgpack.encode(hello), False)

        frame = self._expect(timeout, "challenge")
        while frame.op == Op.PING and frame.seq == 0:  # a dialing host's opening nudge
            frame = self._expect(timeout, "challenge")
        if frame.op != Op.CHALLENGE:
            raise RhpError("protocol", "expected a challenge, got %s" % Op.name(frame.op), "client")
        challenge = msgpack.decode(frame.payload)
        if challenge.get("rev") != PROTOCOL_REVISION:
            raise RhpError("protocol", "the host speaks protocol revision %s, this client %d" % (challenge.get("rev"), PROTOCOL_REVISION), "client")
        auth = challenge.get("auth") or {}
        host_nonce = auth.get("nonce")
        if not isinstance(host_nonce, bytes) or len(host_nonce) != 32:
            raise RhpError("protocol", "malformed challenge", "client")
        transcript = _transcript(identity.name, client_nonce, host_nonce, self._stream.binding)
        if _derive(identity.psk, "rhp/host", transcript) != auth.get("proof"):
            raise RhpError("auth", "the host doesn't know this identity's key (or a relay is in the way)", "client")
        proof = _derive(identity.psk, "rhp/client", transcript)
        self._c2h = _derive(identity.psk, "rhp/c2h", transcript)
        self._h2c = _derive(identity.psk, "rhp/h2c", transcript)
        self._write(Op.RESPONSE, 0, msgpack.encode({"auth": {"proof": proof}}), False)

        frame = self._expect(timeout, "welcome")
        if frame.op != Op.WELCOME or not frame.flags & FLAG_MAC or mac32(self._h2c, frame.sealed) != frame.mac:
            raise RhpError("auth", "the welcome failed its MAC check", "client")
        welcome = msgpack.decode(frame.payload)
        self.welcome = welcome
        self.session_id = welcome.get("session", 0)
        self.heartbeat_s = (welcome.get("heartbeat_ms") or 0) / 1000.0
        self._decoder.max_payload = self._max_frame
        return welcome

    # ---- resume -------------------------------------------------------------------------------------

    def resume(self, stream: Stream, timeout: float = 5.0) -> None:
        """Continues this session on a new connection: sealed kResume with a proof bound to the new
        link; the host answers with a sealed welcome; then both sides resend what wasn't acknowledged."""
        with self._lock:
            self._stream = stream
            self._decoder = FrameDecoder(self._max_frame)
            self._control_out += 1
            proof = mac32(self._c2h, b"rhp/resume" + stream.binding)
            self._write(Op.RESUME, self._control_out, msgpack.encode({"session": self.session_id, "proof": proof}), True)
        frame = self._expect(timeout, "resume answer")
        if frame.op != Op.WELCOME or not frame.flags & FLAG_MAC or mac32(self._h2c, frame.sealed) != frame.mac:
            raise RhpError("auth", "the resume answer failed its MAC check", "client")
        answer = msgpack.decode(frame.payload)
        if answer.get("session") != self.session_id or answer.get("proof") != mac32(self._h2c, b"rhp/resumed" + stream.binding):
            raise RhpError("auth", "the host's resume proof doesn't match", "client")
        with self._lock:
            if frame.seq <= self._control_in:
                raise RhpError("protocol", "a replayed resume answer", "client")
            self._control_in = frame.seq
            self._acknowledge(frame.ack)
            self._resend_after(self._peer_acked)
            self._heard = True
            self._misses = 0

    # ---- reliability --------------------------------------------------------------------------------

    def _acknowledge(self, ack: int) -> None:
        ack = min(ack, self._next_seq - 1)
        if ack > self._peer_acked:
            self._peer_acked = ack
            self._unacked = [u for u in self._unacked if u[0] > ack]

    def _resend_after(self, ack: int) -> None:
        self._acknowledge(ack)
        for seq, op, payload in list(self._unacked):
            self._write(op, seq, payload, True)

    def _nack(self) -> None:
        if self._nacked_at == self._expected:
            return  # already asked for this gap; the heartbeat resend covers a lost nack
        self._nacked_at = self._expected
        self.send_control(Op.NACK)

    def poll(self, timeout: Optional[float]) -> List[Message]:
        """Reads what arrives within `timeout`: handles control frames, acknowledges, and returns the
        sequenced messages in order. Raises RhpError when the session ends."""
        frame = self._read_frame(timeout)
        if frame is None:
            return []
        out: List[Message] = []
        while frame is not None:
            message = self._handle(frame)
            if message is not None:
                out.append(message)
            frame = self._decoder.next()
            if frame is not None and self._trace:
                self._trace("recv", frame.raw, "%s %s" % (Op.name(frame.op), frame.status))
        if out:
            self.send_control(Op.ACK)
        return out

    def _handle(self, frame) -> Optional[Message]:
        with self._lock:
            if frame.status == "bad_crc":
                self._nack()
                return None
            if frame.status != "frame":
                raise RhpError("protocol", "a %s frame from the host" % frame.status, "client")
            if not frame.flags & FLAG_MAC or mac32(self._h2c, frame.sealed) != frame.mac:
                raise RhpError("auth", "a %s frame failed its MAC check" % Op.name(frame.op), "client")
            self._heard = True
            self._acknowledge(frame.ack)
            op = frame.op
            if not is_sequenced(op):
                if frame.seq <= self._control_in:
                    return None  # a replayed control frame
                self._control_in = frame.seq
            if not is_sequenced(op) or frame.seq == 0:
                if op == Op.PING:
                    self.send_control(Op.PONG)
                elif op == Op.NACK:
                    self._resend_after(frame.ack)
                elif op == Op.ERROR:
                    self.closed = True
                    raise RhpError.from_value(msgpack.decode(frame.payload))
                return None
            if frame.seq < self._expected:
                self.send_control(Op.ACK)  # our ack may have been lost: repeat it
                return None
            if frame.seq > self._expected:
                self._nack()  # a frame before this one was lost
                return None
            self._expected += 1
            return op, msgpack.decode(frame.payload)

    def heartbeat(self, misses_allowed: int = 3) -> None:
        """Called once per heartbeat interval: pings, resends what sits unacknowledged, and raises
        RhpError(timeout) after `misses_allowed` intervals without a frame from the host."""
        with self._lock:
            if self._heard:
                self._misses = 0
            else:
                self._misses += 1
                if misses_allowed and self._misses >= misses_allowed:
                    raise RhpError("timeout", "no frame from the host for %d heartbeats" % self._misses, "client")
            self._heard = False
            if self._unacked and self._peer_acked == self._acked_at_tick:
                self._resend_after(self._peer_acked)
            self._acked_at_tick = self._peer_acked
            self._nacked_at = 0
        self.send_control(Op.PING)

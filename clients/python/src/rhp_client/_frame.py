"""RHP frames (Src/rhp/wire/frame.hpp): a 28-byte header, the payload, a CRC32C (left out on
encrypted links) and a 32-byte keyed BLAKE2b MAC once a session has keys.

    magic "RHP\\0" | revision u8 | flags u8 | op u16 | seq u64 | ack u64 | length u32  (little-endian)
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Optional

__all__ = [
    "PROTOCOL_REVISION", "MAGIC", "HEADER_SIZE", "Op", "FLAG_MAC", "FLAG_ACK_REQUESTED", "FLAG_MORE", "FLAG_CRC_OMITTED",
    "crc32c", "mac32", "encode_frame", "Frame", "FrameDecoder", "is_sequenced",
]

PROTOCOL_REVISION = 7
MAGIC = b"RHP\x00"
_HEADER = struct.Struct("<4sBBHQQI")
HEADER_SIZE = _HEADER.size  # 28

FLAG_MAC = 1
FLAG_ACK_REQUESTED = 2
FLAG_MORE = 4
FLAG_CRC_OMITTED = 8


class Op:
    """Frame op codes (Src/rhp/wire/ops.hpp)."""

    HELLO = 1
    CHALLENGE = 2
    RESPONSE = 3
    WELCOME = 4
    RESUME = 5
    EXEC = 16
    LOAD = 17
    CALL = 18
    RELOAD = 19
    ROLLBACK = 20
    UNLOAD = 21
    REVERT = 22
    REVERT_TO = 23
    CHECKPOINT = 24
    REVERT_ALL = 25
    CANCEL = 26
    LIST = 27
    STATUS = 28
    DESCRIBE = 29
    PIN = 30
    UNPIN = 31
    BLOB = 32
    SUBSCRIBE = 33
    UNSUBSCRIBE = 34
    RELEASE_APPLY = 35
    RELEASE_CONFIRM = 36
    RELEASE_DEACTIVATE = 37
    RELEASE_STATUS = 38
    REVOKE = 39
    TUNABLES = 40
    TUNE = 41
    PROFILE = 42
    DEBUG = 43
    TRUST = 44
    OUTPUT = 48
    EMIT = 49
    RESULT = 50
    ERROR = 51
    EVENT = 52
    PING = 64
    PONG = 65
    ACK = 66
    NACK = 67

    @classmethod
    def name(cls, code: int) -> str:
        for key, value in vars(cls).items():
            if value == code and key.isupper():
                return key.lower()
        return "op %d" % code


def is_sequenced(op: int) -> bool:
    """Requests and replies (16..63) carry a delivery sequence; handshake and control frames don't."""
    return 16 <= op < 64


# ---- CRC-32C (Castagnoli, reflected polynomial 0x82F63B78) ------------------------------------------

def _make_table():
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        table.append(c)
    return table


_TABLE = _make_table()

def _crc32c_table(data: bytes, crc: int = 0) -> int:
    crc ^= 0xFFFFFFFF
    table = _TABLE
    for b in data:
        crc = (crc >> 8) ^ table[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFF


def _fast_crc32c():
    """The `crc32c` package (C, the CPU instruction where there is one) when installed and it agrees
    with the table on the check value."""
    try:
        import crc32c as module  # type: ignore
    except ImportError:
        return None
    fn = getattr(module, "crc32c", None)
    try:
        if fn is None or fn(b"123456789") != 0xE3069283 or fn(b"6789", fn(b"12345")) != 0xE3069283:
            return None
    except Exception:  # noqa: BLE001 - an incompatible version: use the table
        return None
    return lambda data, crc=0: fn(bytes(data), crc)


crc32c = _fast_crc32c() or _crc32c_table


def mac32(key: bytes, data: bytes) -> bytes:
    """The frame MAC and every derived key: keyed BLAKE2b with a 32-byte digest."""
    return hashlib.blake2b(bytes(data), key=bytes(key), digest_size=32).digest()


def encode_frame(op: int, seq: int, ack: int, payload: bytes, mac_key: Optional[bytes] = None, crc: bool = True,
                 flags: int = 0, revision: int = PROTOCOL_REVISION) -> bytes:
    """One whole frame. `mac_key` seals it; `crc=False` (encrypted links) leaves the CRC out."""
    flags = (flags | FLAG_MAC) if mac_key else (flags & ~FLAG_MAC)
    if not crc:
        flags |= FLAG_CRC_OMITTED
    sealed = _HEADER.pack(MAGIC, revision, flags, op, seq, ack, len(payload)) + bytes(payload)
    out = sealed
    if not flags & FLAG_CRC_OMITTED:
        out += struct.pack("<I", crc32c(sealed))
    if mac_key:
        out += mac32(mac_key, sealed)
    return out


@dataclass
class Frame:
    status: str  # "frame", "bad_magic", "too_large", "bad_crc", "bad_revision"
    revision: int = 0
    flags: int = 0
    op: int = 0
    seq: int = 0
    ack: int = 0
    payload: bytes = b""
    sealed: bytes = b""  # header + payload: what the CRC and the MAC cover
    mac: bytes = b""
    raw: bytes = field(default=b"", repr=False)


class FrameDecoder:
    """Incremental decoder for a byte stream: feed() what arrived, then next() until it returns None."""

    def __init__(self, max_payload: int):
        self.max_payload = max_payload
        self._buffer = bytearray()

    def feed(self, data: bytes) -> None:
        self._buffer += data

    def next(self) -> Optional[Frame]:
        buf = self._buffer
        if len(buf) < 4:
            return None
        if bytes(buf[:4]) != MAGIC:
            skip = 1  # resynchronize at the next possible magic
            while skip < len(buf):
                left = min(len(buf) - skip, 4)
                if bytes(buf[skip:skip + left]) == MAGIC[:left]:
                    break
                skip += 1
            del buf[:skip]
            return Frame("bad_magic")
        if len(buf) < HEADER_SIZE:
            return None
        _, revision, flags, op, seq, ack, length = _HEADER.unpack_from(buf, 0)
        if length > self.max_payload:
            buf.clear()  # the stream can't be trusted any more
            return Frame("too_large", revision, flags, op, seq, ack)
        with_crc = not flags & FLAG_CRC_OMITTED
        with_mac = bool(flags & FLAG_MAC)
        total = HEADER_SIZE + length + (4 if with_crc else 0) + (32 if with_mac else 0)
        if len(buf) < total:
            return None
        raw = bytes(buf[:total])
        del buf[:total]
        sealed = raw[:HEADER_SIZE + length]
        frame = Frame("frame", revision, flags, op, seq, ack, sealed[HEADER_SIZE:], sealed, b"", raw)
        if with_crc and struct.unpack_from("<I", raw, HEADER_SIZE + length)[0] != crc32c(sealed):
            frame.status = "bad_crc"
            return frame
        if revision != PROTOCOL_REVISION:
            frame.status = "bad_revision"
            return frame
        if with_mac:
            frame.mac = raw[HEADER_SIZE + length + (4 if with_crc else 0):]
        return frame

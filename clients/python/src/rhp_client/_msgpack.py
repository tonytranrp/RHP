"""MessagePack exactly as RHP's own codec (Src/rhp/wire/codec/msgpack.cpp) writes and reads it.

RHP values map onto Python like this:

    nil -> None, bool -> bool, integer (signed 64-bit) -> int, number -> float, string -> str,
    bytes -> bytes, array -> list, map -> dict (or Map when keys repeat or aren't hashable)

Encoding is canonical in the same way the C++ codec is: the smallest integer form, float64 for
every float, str for text and bin for bytes, maps in insertion order.
"""

from __future__ import annotations

import struct
from typing import Any

__all__ = ["Map", "MessagePackError", "encode", "decode", "MAX_DEPTH", "MAX_ELEMENTS"]

# The C++ decoder's defaults (wire/codec.hpp, decode_limits).
MAX_DEPTH = 100
MAX_ELEMENTS = 1 << 20

_INT64_MIN = -(1 << 63)
_INT64_MAX = (1 << 63) - 1


class MessagePackError(ValueError):
    """Malformed or unsupported MessagePack data (RHP's kProtocol)."""


class Map(list):
    """An RHP map as an ordered list of (key, value) pairs.

    decode() returns a dict whenever the keys are hashable and distinct, which is every map RHP
    itself produces; Map covers the rest. Encoding accepts both.
    """

    def items(self):  # dict-like iteration, so callers can treat both alike
        return iter(self)


def _encode(v: Any, out: bytearray) -> None:
    if v is None:
        out.append(0xC0)
    elif v is True:
        out.append(0xC3)
    elif v is False:
        out.append(0xC2)
    elif isinstance(v, int):
        if not _INT64_MIN <= v <= _INT64_MAX:
            raise OverflowError("RHP integers are signed 64-bit")
        if v >= 0:
            if v <= 0x7F:
                out.append(v)
            elif v <= 0xFF:
                out += b"\xcc" + struct.pack(">B", v)
            elif v <= 0xFFFF:
                out += b"\xcd" + struct.pack(">H", v)
            elif v <= 0xFFFFFFFF:
                out += b"\xce" + struct.pack(">I", v)
            else:
                out += b"\xcf" + struct.pack(">Q", v)
        elif v >= -32:
            out += struct.pack(">b", v)
        elif v >= -128:
            out += b"\xd0" + struct.pack(">b", v)
        elif v >= -32768:
            out += b"\xd1" + struct.pack(">h", v)
        elif v >= -(1 << 31):
            out += b"\xd2" + struct.pack(">i", v)
        else:
            out += b"\xd3" + struct.pack(">q", v)
    elif isinstance(v, float):
        out += b"\xcb" + struct.pack(">d", v)
    elif isinstance(v, str):
        b = v.encode("utf-8", "surrogateescape")
        n = len(b)
        if n < 32:
            out.append(0xA0 | n)
        elif n <= 0xFF:
            out += b"\xd9" + struct.pack(">B", n)
        elif n <= 0xFFFF:
            out += b"\xda" + struct.pack(">H", n)
        else:
            out += b"\xdb" + struct.pack(">I", n)
        out += b
    elif isinstance(v, (bytes, bytearray, memoryview)):
        b = bytes(v)
        n = len(b)
        if n <= 0xFF:
            out += b"\xc4" + struct.pack(">B", n)
        elif n <= 0xFFFF:
            out += b"\xc5" + struct.pack(">H", n)
        else:
            out += b"\xc6" + struct.pack(">I", n)
        out += b
    elif isinstance(v, (dict, Map)):
        items = list(v.items())
        n = len(items)
        if n < 16:
            out.append(0x80 | n)
        elif n <= 0xFFFF:
            out += b"\xde" + struct.pack(">H", n)
        else:
            out += b"\xdf" + struct.pack(">I", n)
        for key, item in items:
            _encode(key, out)
            _encode(item, out)
    elif isinstance(v, (list, tuple)):
        n = len(v)
        if n < 16:
            out.append(0x90 | n)
        elif n <= 0xFFFF:
            out += b"\xdc" + struct.pack(">H", n)
        else:
            out += b"\xdd" + struct.pack(">I", n)
        for item in v:
            _encode(item, out)
    else:
        raise TypeError("an RHP value can't hold %s" % type(v).__name__)


def encode(v: Any) -> bytes:
    """Encodes one value."""
    out = bytearray()
    _encode(v, out)
    return bytes(out)


class _Reader:
    def __init__(self, data: bytes, max_depth: int, max_elements: int):
        self.data = data
        self.pos = 0
        self.count = 0
        self.max_depth = max_depth
        self.max_elements = max_elements

    def take(self, n: int) -> bytes:
        if len(self.data) - self.pos < n:
            raise MessagePackError("truncated MessagePack data")
        start = self.pos
        self.pos += n
        return self.data[start:self.pos]

    def length(self, n: int) -> int:
        return int.from_bytes(self.take(n), "big")

    def text(self, n: int) -> str:
        return self.take(n).decode("utf-8", "surrogateescape")

    def array(self, n: int, depth: int) -> list:
        if n > len(self.data) - self.pos:  # every item takes at least one byte
            raise MessagePackError("truncated MessagePack data")
        return [self.read(depth + 1) for _ in range(n)]

    def map(self, n: int, depth: int):
        if n > (len(self.data) - self.pos) // 2:
            raise MessagePackError("truncated MessagePack data")
        pairs = Map()
        for _ in range(n):
            key = self.read(depth + 1)
            pairs.append((key, self.read(depth + 1)))
        try:
            if len({key for key, _ in pairs}) == len(pairs):
                return dict(pairs)
        except TypeError:  # an unhashable key (a list or a dict)
            pass
        return pairs

    def read(self, depth: int):
        if depth > self.max_depth:
            raise MessagePackError("MessagePack nesting deeper than %d" % self.max_depth)
        self.count += 1
        if self.count > self.max_elements:
            raise MessagePackError("more than %d MessagePack values" % self.max_elements)
        t = self.take(1)[0]
        if t <= 0x7F:
            return t
        if t >= 0xE0:
            return t - 0x100
        if t & 0xF0 == 0x80:
            return self.map(t & 0x0F, depth)
        if t & 0xF0 == 0x90:
            return self.array(t & 0x0F, depth)
        if t & 0xE0 == 0xA0:
            return self.text(t & 0x1F)
        if t == 0xC0:
            return None
        if t == 0xC2:
            return False
        if t == 0xC3:
            return True
        if t in (0xC4, 0xC5, 0xC6):
            return self.take(self.length({0xC4: 1, 0xC5: 2, 0xC6: 4}[t]))
        if t == 0xCA:
            return float(struct.unpack(">f", self.take(4))[0])
        if t == 0xCB:
            return struct.unpack(">d", self.take(8))[0]
        if t in (0xCC, 0xCD, 0xCE, 0xCF):
            v = self.length({0xCC: 1, 0xCD: 2, 0xCE: 4, 0xCF: 8}[t])
            return float(v) if v > _INT64_MAX else v  # RHP integers are signed: a larger uint64 is a number
        if t == 0xD0:
            return struct.unpack(">b", self.take(1))[0]
        if t == 0xD1:
            return struct.unpack(">h", self.take(2))[0]
        if t == 0xD2:
            return struct.unpack(">i", self.take(4))[0]
        if t == 0xD3:
            return struct.unpack(">q", self.take(8))[0]
        if t in (0xD9, 0xDA, 0xDB):
            return self.text(self.length({0xD9: 1, 0xDA: 2, 0xDB: 4}[t]))
        if t == 0xDC:
            return self.array(self.length(2), depth)
        if t == 0xDD:
            return self.array(self.length(4), depth)
        if t == 0xDE:
            return self.map(self.length(2), depth)
        if t == 0xDF:
            return self.map(self.length(4), depth)
        raise MessagePackError("MessagePack extension types aren't RHP values (byte 0x%02x)" % t)


def decode(data: bytes, max_depth: int = MAX_DEPTH, max_elements: int = MAX_ELEMENTS) -> Any:
    """Decodes exactly one value that fills `data`."""
    reader = _Reader(bytes(data), max_depth, max_elements)
    value = reader.read(0)
    if reader.pos != len(reader.data):
        raise MessagePackError("%d trailing bytes after the MessagePack value" % (len(reader.data) - reader.pos))
    return value

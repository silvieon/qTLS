"""TLS wire-format primitives.

These are deliberately boring. TLS parsing should be explicit and bounded,
not implemented through ad-hoc struct slicing scattered across the project.
"""

from __future__ import annotations

from dataclasses import dataclass


class DecodeError(ValueError):
    pass


class Reader:
    def __init__(self, data: bytes):
        self.data = memoryview(data)
        self.pos = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.remaining < n:
            raise DecodeError("truncated TLS structure")
        out = self.data[self.pos:self.pos + n].tobytes()
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u24(self) -> int:
        return int.from_bytes(b"\x00" + self.take(3), "big")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def vector(self, length_bytes: int) -> bytes:
        if length_bytes == 1:
            n = self.u8()
        elif length_bytes == 2:
            n = self.u16()
        elif length_bytes == 3:
            n = self.u24()
        elif length_bytes == 4:
            n = self.u32()
        else:
            raise ValueError("unsupported vector length")
        return self.take(n)

    def require_end(self) -> None:
        if self.remaining:
            raise DecodeError("trailing bytes in TLS structure")


def u8(value: int) -> bytes:
    if not 0 <= value <= 0xff:
        raise ValueError("u8 out of range")
    return bytes((value,))


def u16(value: int) -> bytes:
    if not 0 <= value <= 0xffff:
        raise ValueError("u16 out of range")
    return value.to_bytes(2, "big")


def u24(value: int) -> bytes:
    if not 0 <= value <= 0xffffff:
        raise ValueError("u24 out of range")
    return value.to_bytes(3, "big")


def u32(value: int) -> bytes:
    if not 0 <= value <= 0xffffffff:
        raise ValueError("u32 out of range")
    return value.to_bytes(4, "big")


def vector(data: bytes, length_bytes: int) -> bytes:
    max_value = (1 << (8 * length_bytes)) - 1
    if len(data) > max_value:
        raise ValueError("vector too large")
    return len(data).to_bytes(length_bytes, "big") + data


@dataclass(frozen=True)
class HandshakeMessage:
    msg_type: int
    body: bytes

    def encode(self) -> bytes:
        return u8(self.msg_type) + u24(len(self.body)) + self.body

    @classmethod
    def decode(cls, data: bytes) -> "HandshakeMessage":
        reader = Reader(data)
        msg_type = reader.u8()
        length = reader.u24()
        body = reader.take(length)
        reader.require_end()
        return cls(msg_type, body)

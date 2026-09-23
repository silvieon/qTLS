"""Transport abstraction used by the TLS engine.

TLS operates over a reliable, ordered byte stream. Keeping this interface
small lets qTLS run over TCP today and custom packet transports later.
"""

from __future__ import annotations

import socket
from abc import ABC, abstractmethod


class ByteTransport(ABC):
    @abstractmethod
    def send_all(self, data: bytes) -> None:
        raise NotImplementedError

    @abstractmethod
    def recv_exact(self, size: int) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        raise NotImplementedError


class SocketTransport(ByteTransport):
    def __init__(self, sock: socket.socket):
        self.sock = sock

    def send_all(self, data: bytes) -> None:
        self.sock.sendall(data)

    def recv_exact(self, size: int) -> bytes:
        out = bytearray()
        while len(out) < size:
            chunk = self.sock.recv(size - len(out))
            if not chunk:
                raise ConnectionError("transport closed before receiving enough data")
            out.extend(chunk)
        return bytes(out)

    def close(self) -> None:
        self.sock.close()

from __future__ import annotations

from .handshake.engine import ClientHandshake, ServerHandshake
from .record import ContentType, RecordLayer, TLSAlert
from .transport import ByteTransport


class TLSConnection:
    def __init__(self, transport: ByteTransport):
        self.transport = transport
        self.record = RecordLayer(transport)
        self.handshake_complete = False

    def send(self, data: bytes):
        if not self.handshake_complete:
            raise RuntimeError("handshake not complete")
        self.record.write_encrypted(ContentType.APPLICATION_DATA, data)

    def recv(self) -> bytes:
        if not self.handshake_complete:
            raise RuntimeError("handshake not complete")
        while True:
            typ, data = self.record.read_encrypted()
            if typ == ContentType.APPLICATION_DATA:
                return data
            if typ == ContentType.ALERT:
                raise TLSAlert(data)
            if typ == ContentType.HANDSHAKE:
                # Reserved for post-handshake messages such as KeyUpdate.
                continue
            raise TLSAlert(f"unexpected TLS content: {typ}")

    def close(self):
        if self.handshake_complete:
            try:
                self.record.write_encrypted(ContentType.ALERT, b"\x01\x00")  # warning, close_notify
            except Exception:
                pass
        self.transport.close()


class TLSClientConnection(TLSConnection):
    def handshake(self, verify_peer):
        ClientHandshake(self.record, verify_peer).run()
        self.handshake_complete = True
        return self


class TLSServerConnection(TLSConnection):
    def handshake(self, certificate, private_key, *, verify_peer=None, alpn=None):
        ServerHandshake(self.record, certificate, private_key, verify_peer=verify_peer, alpn=alpn).run()
        self.handshake_complete = True
        return self

from qtls.record import ContentType, RecordLayer
from qtls.transport import ByteTransport


class MemoryTransport(ByteTransport):
    def __init__(self):
        self.buf = bytearray()
        self.pos = 0

    def send_all(self, data: bytes):
        self.buf.extend(data)

    def recv_exact(self, size: int) -> bytes:
        if len(self.buf) - self.pos < size:
            raise ConnectionError("short memory transport")
        out = bytes(self.buf[self.pos:self.pos + size])
        self.pos += size
        return out

    def close(self):
        pass


def test_encrypted_record_round_trip():
    key = b"\x03" * 16
    iv = b"\x04" * 12

    transport = MemoryTransport()
    writer = RecordLayer(transport)
    writer.write_cipher = __import__("qtls").AESGCMCipher(key, iv)
    writer.write_encrypted(ContentType.HANDSHAKE, b"hello")

    reader = RecordLayer(transport)
    reader.read_cipher = __import__("qtls").AESGCMCipher(key, iv)
    content_type, data = reader.read_encrypted()

    assert content_type == ContentType.HANDSHAKE
    assert data == b"hello"

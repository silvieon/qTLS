"""TLS 1.3 record framing and protected-record primitives."""

from __future__ import annotations

from enum import IntEnum

from .crypto.aead import AESGCMCipher
from .transport import ByteTransport
from .protocol import Reader, u16


class ContentType(IntEnum):
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23


class TLSAlert(Exception):
    pass


LEGACY_RECORD_VERSION = b"\x03\x03"
MAX_RECORD_LENGTH = 16384 + 256


class RecordLayer:
    def __init__(self, transport: ByteTransport):
        self.transport = transport
        self.read_cipher: AESGCMCipher | None = None
        self.write_cipher: AESGCMCipher | None = None

    def _read_record(self) -> tuple[int, bytes]:
        header = self.transport.recv_exact(5)
        content_type = header[0]
        version = header[1:3]
        length = int.from_bytes(header[3:5], "big")

        if version != LEGACY_RECORD_VERSION:
            raise TLSAlert("unexpected TLS record legacy_version")
        if length > MAX_RECORD_LENGTH:
            raise TLSAlert("TLS record exceeds maximum size")

        return content_type, self.transport.recv_exact(length)

    def _write_record(self, content_type: int, fragment: bytes) -> None:
        if len(fragment) > MAX_RECORD_LENGTH:
            raise ValueError("record fragment too large")

        header = bytes((content_type,)) + LEGACY_RECORD_VERSION + u16(len(fragment))
        self.transport.send_all(header + fragment)

    def write_plaintext(self, content_type: ContentType, data: bytes) -> None:
        self._write_record(int(content_type), data)

    def read_plaintext(self) -> tuple[ContentType, bytes]:
        content_type, fragment = self._read_record()
        try:
            return ContentType(content_type), fragment
        except ValueError as exc:
            raise TLSAlert("unknown TLS content type") from exc

    def write_encrypted(
        self,
        content_type: ContentType,
        data: bytes,
        *,
        padding: int = 0,
    ) -> None:
        if self.write_cipher is None:
            raise TLSAlert("write cipher not installed")

        if padding < 0:
            raise ValueError("negative padding")
        plaintext = data + bytes((int(content_type),)) + (b"\x00" * padding)

        # TLSInnerPlaintext is encrypted as the payload of an outer
        # application_data record.
        outer_len = len(plaintext) + AESGCMCipher.TAG_SIZE
        aad = bytes((ContentType.APPLICATION_DATA,)) + LEGACY_RECORD_VERSION + u16(outer_len)
        ciphertext = self.write_cipher.encrypt(plaintext, aad)
        self._write_record(ContentType.APPLICATION_DATA, ciphertext)

    def read_encrypted(self) -> tuple[ContentType, bytes]:
        if self.read_cipher is None:
            raise TLSAlert("read cipher not installed")

        outer_type, ciphertext = self._read_record()
        if outer_type != ContentType.APPLICATION_DATA:
            raise TLSAlert("encrypted TLS record has wrong outer content type")

        aad = bytes((ContentType.APPLICATION_DATA,)) + LEGACY_RECORD_VERSION + u16(len(ciphertext))
        plaintext = self.read_cipher.decrypt(ciphertext, aad)

        if not plaintext:
            raise TLSAlert("empty TLSInnerPlaintext")

        # TLSInnerPlaintext ends with the content type, preceded by optional
        # zero padding. Scan backward to find the non-zero content-type byte.
        index = len(plaintext) - 1
        while index >= 0 and plaintext[index] == 0:
            index -= 1
        if index < 0:
            raise TLSAlert("missing TLSInnerPlaintext content type")

        try:
            content_type = ContentType(plaintext[index])
        except ValueError as exc:
            raise TLSAlert("invalid inner content type") from exc

        return content_type, plaintext[:index]

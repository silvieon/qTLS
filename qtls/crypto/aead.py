"""TLS record AEAD primitive.

TLS 1.3 constructs the per-record nonce by XORing the static IV with the
64-bit record sequence number encoded as a big-endian integer.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AESGCMCipher:
    KEY_SIZE = 16
    IV_SIZE = 12
    TAG_SIZE = 16

    def __init__(self, key: bytes, iv: bytes, sequence_number: int = 0):
        if len(key) != self.KEY_SIZE:
            raise ValueError("TLS_AES_128_GCM_SHA256 requires a 16-byte key")
        if len(iv) != self.IV_SIZE:
            raise ValueError("TLS 1.3 AES-GCM IV must be 12 bytes")
        if sequence_number < 0 or sequence_number >= 2**64:
            raise ValueError("invalid TLS record sequence number")

        self._aead = AESGCM(key)
        self.iv = iv
        self.sequence_number = sequence_number

    def _nonce(self) -> bytes:
        seq = self.sequence_number.to_bytes(12, "big")
        return bytes(a ^ b for a, b in zip(self.iv, seq))

    def encrypt(self, plaintext: bytes, aad: bytes) -> bytes:
        if self.sequence_number >= 2**64:
            raise OverflowError("TLS record sequence number exhausted")
        ciphertext = self._aead.encrypt(self._nonce(), plaintext, aad)
        self.sequence_number += 1
        return ciphertext

    def decrypt(self, ciphertext: bytes, aad: bytes) -> bytes:
        if self.sequence_number >= 2**64:
            raise OverflowError("TLS record sequence number exhausted")
        plaintext = self._aead.decrypt(self._nonce(), ciphertext, aad)
        self.sequence_number += 1
        return plaintext

"""Handshake transcript hashing."""

from __future__ import annotations

import hashlib


class Transcript:
    def __init__(self):
        self._hash = hashlib.sha256()

    def update(self, handshake_message: bytes) -> None:
        self._hash.update(handshake_message)

    def digest(self) -> bytes:
        return self._hash.digest()

    def copy(self) -> "Transcript":
        other = Transcript()
        other._hash = self._hash.copy()
        return other

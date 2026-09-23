"""X25519 key agreement wrapper."""

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)


class X25519KeyExchange:
    def __init__(self, private_key: X25519PrivateKey | None = None):
        self.private_key = private_key or X25519PrivateKey.generate()

    @property
    def public_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes_raw()

    def exchange(self, peer_public_bytes: bytes) -> bytes:
        if len(peer_public_bytes) != 32:
            raise ValueError("X25519 public key must be 32 bytes")
        peer = X25519PublicKey.from_public_bytes(peer_public_bytes)
        return self.private_key.exchange(peer)

"""HKDF and TLS 1.3 HKDF-Expand-Label."""

from __future__ import annotations

import hashlib
import hmac


HASH = hashlib.sha256
HASH_LEN = HASH().digest_size


def hkdf_extract(salt: bytes | None, ikm: bytes) -> bytes:
    if salt is None:
        salt = b"\x00" * HASH_LEN
    return hmac.new(salt, ikm, HASH).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length < 0 or length > 255 * HASH_LEN:
        raise ValueError("HKDF output length out of range")

    output = bytearray()
    previous = b""
    counter = 1

    while len(output) < length:
        previous = hmac.new(
            prk,
            previous + info + bytes((counter,)),
            HASH,
        ).digest()
        output.extend(previous)
        counter += 1

    return bytes(output[:length])


def hkdf_expand_label(
    secret: bytes,
    label: bytes,
    context: bytes,
    length: int,
) -> bytes:
    """TLS 1.3 HKDF-Expand-Label.

    TLS 1.3 prepends the literal 'tls13 ' to the supplied label.
    """
    full_label = b"tls13 " + label
    if len(full_label) > 255 or len(context) > 255:
        raise ValueError("HKDF label/context too large")

    info = (
        length.to_bytes(2, "big")
        + bytes((len(full_label),))
        + full_label
        + bytes((len(context),))
        + context
    )
    return hkdf_expand(secret, info, length)


def derive_secret(secret: bytes, label: bytes, transcript_hash: bytes) -> bytes:
    return hkdf_expand_label(secret, label, transcript_hash, HASH_LEN)

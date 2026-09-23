from qtls.crypto import (
    AESGCMCipher,
    X25519KeyExchange,
    hkdf_extract,
    hkdf_expand_label,
)


def test_x25519_shared_secret():
    a = X25519KeyExchange()
    b = X25519KeyExchange()
    assert a.exchange(b.public_bytes) == b.exchange(a.public_bytes)


def test_hkdf_is_deterministic():
    prk = hkdf_extract(b"salt", b"input")
    assert hkdf_expand_label(prk, b"test", b"", 32) == hkdf_expand_label(
        prk, b"test", b"", 32
    )


def test_aes_gcm_round_trip():
    key = b"\x01" * 16
    iv = b"\x02" * 12
    aad = b"header"

    enc = AESGCMCipher(key, iv)
    ciphertext = enc.encrypt(b"secret", aad)

    dec = AESGCMCipher(key, iv)
    assert dec.decrypt(ciphertext, aad) == b"secret"

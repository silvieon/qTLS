
from __future__ import annotations
import hashlib, hmac
from .hkdf import hkdf_extract, hkdf_expand_label, derive_secret, HASH_LEN

HASH = hashlib.sha256

class TLS13KeySchedule:
    def __init__(self):
        self.empty_hash = HASH(b"").digest()
        self.zero = b"\x00" * HASH_LEN
        self.early_secret = hkdf_extract(None, b"")
        self.handshake_secret = None
        self.master_secret = None

    def handshake(self, dhe_secret: bytes, transcript_hash: bytes):
        derived = derive_secret(self.early_secret, b"derived", self.empty_hash)
        self.handshake_secret = hkdf_extract(derived, dhe_secret)
        client = derive_secret(self.handshake_secret, b"c hs traffic", transcript_hash)
        server = derive_secret(self.handshake_secret, b"s hs traffic", transcript_hash)
        return client, server

    def master(self, transcript_hash: bytes):
        derived = derive_secret(self.handshake_secret, b"derived", self.empty_hash)
        self.master_secret = hkdf_extract(derived, b"")
        client = derive_secret(self.master_secret, b"c ap traffic", transcript_hash)
        server = derive_secret(self.master_secret, b"s ap traffic", transcript_hash)
        return client, server

    @staticmethod
    def traffic_key_iv(secret: bytes):
        key=hkdf_expand_label(secret,b"key",b"",16)
        iv=hkdf_expand_label(secret,b"iv",b"",12)
        return key,iv

    @staticmethod
    def finished(secret: bytes, transcript_hash: bytes):
        fk=hkdf_expand_label(secret,b"finished",b"",HASH_LEN)
        return hmac.new(fk, transcript_hash, HASH).digest()

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509 import DNSName
from cryptography.x509.oid import ExtendedKeyUsageOID

from ..crypto import AESGCMCipher, TLS13KeySchedule, X25519KeyExchange
from ..protocol import HandshakeMessage
from ..record import ContentType, RecordLayer, TLSAlert
from .messages import *

SIG_RSA_PSS_RSAE_SHA256 = 0x0804
SIG_ECDSA_SECP256R1_SHA256 = 0x0403
SIG_ED25519 = 0x0807


def _cv_content(label: bytes, transcript_hash: bytes) -> bytes:
    return b"\x20" * 64 + label + b"\x00" + transcript_hash


def sign_certificate_verify(private_key, transcript_hash, *, server=True):
    label = b"TLS 1.3, server CertificateVerify" if server else b"TLS 1.3, client CertificateVerify"
    content = _cv_content(label, transcript_hash)
    if isinstance(private_key, rsa.RSAPrivateKey):
        return SIG_RSA_PSS_RSAE_SHA256, private_key.sign(
            content,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
            hashes.SHA256(),
        )
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return SIG_ECDSA_SECP256R1_SHA256, private_key.sign(content, ec.ECDSA(hashes.SHA256()))
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return SIG_ED25519, private_key.sign(content)
    raise TypeError("unsupported certificate signing key")


def verify_certificate_verify(cert, algorithm, signature, transcript_hash, *, server=True):
    public = cert.public_key()
    label = b"TLS 1.3, server CertificateVerify" if server else b"TLS 1.3, client CertificateVerify"
    content = _cv_content(label, transcript_hash)
    if algorithm == SIG_RSA_PSS_RSAE_SHA256 and isinstance(public, rsa.RSAPublicKey):
        public.verify(signature, content, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size), hashes.SHA256())
        return
    if algorithm == SIG_ECDSA_SECP256R1_SHA256 and isinstance(public, ec.EllipticCurvePublicKey):
        public.verify(signature, content, ec.ECDSA(hashes.SHA256()))
        return
    if algorithm == SIG_ED25519 and isinstance(public, ed25519.Ed25519PublicKey):
        public.verify(signature, content)
        return
    raise ValueError("unsupported or mismatched CertificateVerify algorithm")


def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_certificate(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def verify_certificate(cert: x509.Certificate, *, trust_roots=(), hostname: str | None = None) -> None:
    """Small explicit verifier for test/dev use.

    trust_roots may contain PEM paths or x509.Certificate objects.  This is
    intentionally narrower than a platform trust store: it validates a leaf
    directly against one of the supplied trust anchors.
    """
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise ValueError("certificate is outside its validity period")
    if hostname is not None:
        try:
            names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            if not any(isinstance(n, DNSName) and n.value.lower() == hostname.lower() for n in names):
                raise ValueError("certificate hostname mismatch")
        except x509.ExtensionNotFound as exc:
            raise ValueError("certificate has no subjectAltName") from exc
    if not trust_roots:
        raise ValueError("no trust roots configured")
    roots = []
    for root in trust_roots:
        if isinstance(root, x509.Certificate):
            roots.append(root)
        else:
            with open(root, "rb") as f:
                roots.append(x509.load_pem_x509_certificate(f.read()))
    for root in roots:
        if cert.fingerprint(hashes.SHA256()) == root.fingerprint(hashes.SHA256()):
            return
        if cert.issuer != root.subject:
            continue
        try:
            root.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15() if isinstance(root.public_key(), rsa.RSAPublicKey) else ec.ECDSA(cert.signature_hash_algorithm),
                cert.signature_hash_algorithm if isinstance(root.public_key(), rsa.RSAPublicKey) else None,
            )
            return
        except TypeError:
            try:
                if isinstance(root.public_key(), ed25519.Ed25519PublicKey):
                    root.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
                    return
            except Exception:
                pass
        except Exception:
            continue
    raise ValueError("certificate is not trusted by supplied roots")


class HandshakeIO:
    def __init__(self, record: RecordLayer, encrypted=False):
        self.record = record
        self.encrypted = encrypted
        self.buffer = bytearray()

    def send(self, raw: bytes):
        self.record.write_encrypted(ContentType.HANDSHAKE, raw) if self.encrypted else self.record.write_plaintext(ContentType.HANDSHAKE, raw)

    def recv(self) -> bytes:
        while True:
            if len(self.buffer) >= 4:
                n = int.from_bytes(self.buffer[1:4], "big")
                if len(self.buffer) >= 4 + n:
                    raw = bytes(self.buffer[:4+n])
                    del self.buffer[:4+n]
                    return raw
            typ, data = self.record.read_encrypted() if self.encrypted else self.record.read_plaintext()
            if typ == ContentType.CHANGE_CIPHER_SPEC:
                continue
            if typ != ContentType.HANDSHAKE:
                raise TLSAlert(f"expected handshake, got {typ}")
            self.buffer.extend(data)


def _parse_ext_map(hello):
    return {e.ext_type: e.data for e in hello.extensions}


class ClientHandshake:
    """TLS 1.3 X25519 + AES-128-GCM full handshake client."""
    def __init__(self, record: RecordLayer, verify_peer):
        self.record = record
        self.verify_peer = verify_peer
        self.transcript = hashlib.sha256()
        self.ks = TLS13KeySchedule()
        self.x = X25519KeyExchange()

    def _send_hs(self, raw, encrypted=False):
        if encrypted:
            self.record.write_encrypted(ContentType.HANDSHAKE, raw)
        else:
            self.record.write_plaintext(ContentType.HANDSHAKE, raw)
        self.transcript.update(raw)

    def run(self):
        rnd = os.urandom(32)
        sid = os.urandom(32)
        ch = ClientHello(
            rnd, sid, [TLS_AES_128_GCM_SHA256],
            [supported_versions_client(), supported_groups(X25519),
             key_share_client((X25519, self.x.public_bytes)),
             signature_algorithms(SIG_RSA_PSS_RSAE_SHA256, SIG_ECDSA_SECP256R1_SHA256, SIG_ED25519)],
        )
        self._send_hs(ch.encode())
        io = HandshakeIO(self.record)
        shraw = io.recv()
        if shraw[0] != SERVER_HELLO:
            raise TLSAlert("expected ServerHello")
        sh = ServerHello.decode(shraw[4:]); self.transcript.update(shraw)
        exts = _parse_ext_map(sh)
        if sh.cipher_suite != TLS_AES_128_GCM_SHA256 or exts.get(SUPPORTED_VERSIONS) != TLS13:
            raise TLSAlert("unsupported TLS parameters")
        group, peer_share = parse_key_share_server(exts[KEY_SHARE])
        if group != X25519:
            raise TLSAlert("unsupported key exchange")
        dhe = self.x.exchange(peer_share)
        chs, shs = self.ks.handshake(dhe, self.transcript.digest())
        print("DEBUG CLIENT", self.transcript.hexdigest(), chs.hex(), flush=True)
        self.record.read_cipher = AESGCMCipher(*self.ks.traffic_key_iv(shs))
        self.record.write_cipher = AESGCMCipher(*self.ks.traffic_key_iv(chs))
        io = HandshakeIO(self.record, encrypted=True)
        for expected in (ENCRYPTED_EXTENSIONS, CERTIFICATE, CERTIFICATE_VERIFY, FINISHED):
            raw = io.recv()
            if raw[0] != expected:
                raise TLSAlert(f"expected handshake type {expected}")
            if expected == ENCRYPTED_EXTENSIONS:
                self.transcript.update(raw)
            elif expected == CERTIFICATE:
                self.transcript.update(raw)
                _, certs = parse_certificate(raw[4:])
                cert = x509.load_der_x509_certificate(certs[0])
                self.verify_peer(cert)
            elif expected == CERTIFICATE_VERIFY:
                cv = CertificateVerify.decode(raw[4:])
                cert = x509.load_der_x509_certificate(parse_certificate(certificate_raw)[1][0]) if False else cert
                verify_certificate_verify(cert, cv.algorithm, cv.signature, self.transcript.digest())
                self.transcript.update(raw)
            else:
                expected_finished = self.ks.finished(shs, self.transcript.digest())
                if raw[4:] != expected_finished:
                    raise TLSAlert("server Finished verification failed")
                self.transcript.update(raw)
        finished = Finished(self.ks.finished(chs, self.transcript.digest())).encode()
        self.record.write_encrypted(ContentType.HANDSHAKE, finished)
        self.transcript.update(finished)
        cap, sap = self.ks.master(self.transcript.digest())
        self.record.read_cipher = AESGCMCipher(*self.ks.traffic_key_iv(sap))
        self.record.write_cipher = AESGCMCipher(*self.ks.traffic_key_iv(cap))
        return cert


class ServerHandshake:
    """TLS 1.3 X25519 + AES-128-GCM server for interoperability testing."""
    def __init__(self, record: RecordLayer, certificate, private_key, *, verify_peer=None, alpn=None):
        self.record = record
        self.certificate = certificate
        self.private_key = private_key
        self.verify_peer = verify_peer
        self.alpn = alpn
        self.transcript = hashlib.sha256()
        self.ks = TLS13KeySchedule()

    def run(self):
        io = HandshakeIO(self.record)
        chraw = io.recv()
        if chraw[0] != CLIENT_HELLO:
            raise TLSAlert("expected ClientHello")
        ch = ClientHello.decode(chraw[4:]); self.transcript.update(chraw)
        if TLS_AES_128_GCM_SHA256 not in ch.cipher_suites:
            raise TLSAlert("no supported cipher suite")
        exts = _parse_ext_map(ch)
        if TLS13 not in exts.get(SUPPORTED_VERSIONS, b""):
            raise TLSAlert("client did not offer TLS 1.3")
        shares = parse_key_share_client(exts[KEY_SHARE])
        share = next((s for g, s in shares if g == X25519), None)
        if share is None:
            raise TLSAlert("client did not offer X25519")
        x = X25519KeyExchange()
        server_share = X25519KeyExchange()
        dhe = server_share.exchange(share)
        sh = ServerHello(os.urandom(32), ch.session_id, TLS_AES_128_GCM_SHA256,
                         [supported_versions_server(), key_share(X25519, server_share.public_bytes)]).encode()
        self.record.write_plaintext(ContentType.HANDSHAKE, sh); self.transcript.update(sh)
        chs, shs = self.ks.handshake(dhe, self.transcript.digest())
        self.record.write_cipher = AESGCMCipher(*self.ks.traffic_key_iv(shs))
        self.record.read_cipher = AESGCMCipher(*self.ks.traffic_key_iv(chs))
        io = HandshakeIO(self.record, encrypted=True)
        ee_exts = []
        if self.alpn:
            proto = self.alpn.encode()
            ee_exts.append(Extension(EXTENSION_ALPN, vector(vector(proto, 1), 2)))
        ee = EncryptedExtensions(ee_exts).encode(); self.record.write_encrypted(ContentType.HANDSHAKE, ee); self.transcript.update(ee)
        cert_raw = Certificate(self.certificate.public_bytes(serialization.Encoding.DER)).encode()
        self.record.write_encrypted(ContentType.HANDSHAKE, cert_raw); self.transcript.update(cert_raw)
        alg, sig = sign_certificate_verify(self.private_key, self.transcript.digest(), server=True)
        cv = CertificateVerify(alg, sig).encode(); self.record.write_encrypted(ContentType.HANDSHAKE, cv); self.transcript.update(cv)
        fin = Finished(self.ks.finished(shs, self.transcript.digest())).encode(); self.record.write_encrypted(ContentType.HANDSHAKE, fin); self.transcript.update(fin)
        # Client Finished arrives under handshake keys.
        raw = io.recv()
        if raw[0] != FINISHED:
            raise TLSAlert("expected client Finished")
        if raw[4:] != self.ks.finished(chs, self.transcript.digest()):
            raise TLSAlert("client Finished verification failed")
        self.transcript.update(raw)
        cap, sap = self.ks.master(self.transcript.digest())
        self.record.write_cipher = AESGCMCipher(*self.ks.traffic_key_iv(sap))
        self.record.read_cipher = AESGCMCipher(*self.ks.traffic_key_iv(cap))
        return True

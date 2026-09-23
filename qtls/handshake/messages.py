
from __future__ import annotations
from dataclasses import dataclass
from ..protocol import Reader, u16, u24, u8, vector

CLIENT_HELLO = 1
SERVER_HELLO = 2
ENCRYPTED_EXTENSIONS = 8
CERTIFICATE = 11
CERTIFICATE_VERIFY = 15
FINISHED = 20

TLS13 = b"\x03\x04"
TLS_LEGACY = b"\x03\x03"
TLS_AES_128_GCM_SHA256 = 0x1301
X25519 = 0x001D
SUPPORTED_VERSIONS = 43
KEY_SHARE = 51
SIGNATURE_ALGORITHMS = 13
SUPPORTED_GROUPS = 10
SERVER_NAME = 0
EXTENSION_ALPN = 16

@dataclass
class Extension:
    ext_type: int
    data: bytes
    def encode(self):
        return u16(self.ext_type) + vector(self.data, 2)

def encode_extensions(exts):
    return vector(b"".join(x.encode() for x in exts), 2)

def parse_extensions(data):
    r=Reader(data); out=[]
    while r.remaining:
        typ=r.u16(); body=r.vector(2); out.append((typ, body))
    return out

@dataclass
class ClientHello:
    random: bytes
    session_id: bytes
    cipher_suites: list[int]
    extensions: list[Extension]
    def encode(self):
        suites=b"".join(u16(x) for x in self.cipher_suites)
        compression=b"\x00"
        body=(TLS_LEGACY+self.random+vector(self.session_id,1)+
              vector(suites,2)+vector(compression,1)+encode_extensions(self.extensions))
        return bytes((CLIENT_HELLO,))+u24(len(body))+body

    @classmethod
    def decode(cls, body):
        r=Reader(body); legacy=r.take(2)
        if legacy != TLS_LEGACY: raise ValueError("bad ClientHello legacy_version")
        rnd=r.take(32); sid=r.vector(1); suites_raw=r.vector(2)
        if len(suites_raw)%2: raise ValueError("bad cipher suite vector")
        suites=[int.from_bytes(suites_raw[i:i+2],"big") for i in range(0,len(suites_raw),2)]
        comp=r.vector(1)
        if comp != b"\x00": raise ValueError("unsupported compression")
        exts=parse_extensions(r.vector(2)); r.require_end()
        return cls(rnd,sid,suites,[Extension(a,b) for a,b in exts])

@dataclass
class ServerHello:
    random: bytes
    session_id: bytes
    cipher_suite: int
    extensions: list[Extension]
    def encode(self):
        body=(TLS_LEGACY+self.random+vector(self.session_id,1)+u16(self.cipher_suite)+
              b"\x00"+encode_extensions(self.extensions))
        return bytes((SERVER_HELLO,))+u24(len(body))+body
    @classmethod
    def decode(cls, body):
        r=Reader(body)
        if r.take(2)!=TLS_LEGACY: raise ValueError("bad ServerHello legacy_version")
        rnd=r.take(32); sid=r.vector(1); cs=r.u16(); comp=r.u8()
        if comp != 0: raise ValueError("bad compression")
        exts=parse_extensions(r.vector(2)); r.require_end()
        return cls(rnd,sid,cs,[Extension(a,b) for a,b in exts])

def supported_versions_client():
    return Extension(SUPPORTED_VERSIONS, u8(2)+TLS13)

def supported_versions_server():
    return Extension(SUPPORTED_VERSIONS, TLS13)

def key_share(group, key_exchange):
    return Extension(KEY_SHARE, u16(group)+vector(key_exchange,2))

def key_share_client(*shares):
    entries = b"".join(u16(group) + vector(data, 2) for group, data in shares)
    return Extension(KEY_SHARE, vector(entries, 2))

def parse_key_share_client(data):
    r=Reader(data); entries=r.vector(2); rr=Reader(entries); out=[]
    while rr.remaining:
        group=rr.u16(); share=rr.vector(2); out.append((group,share))
    return out

def parse_key_share_server(data):
    r=Reader(data); group=r.u16(); share=r.vector(2); r.require_end()
    return group,share

def supported_groups(*groups):
    return Extension(SUPPORTED_GROUPS, vector(b"".join(u16(x) for x in groups), 2))

def signature_algorithms(*schemes):
    return Extension(SIGNATURE_ALGORITHMS, vector(b"".join(u16(x) for x in schemes),2))

@dataclass
class EncryptedExtensions:
    extensions: list[Extension]
    def encode(self):
        body=encode_extensions(self.extensions)
        return bytes((ENCRYPTED_EXTENSIONS,))+u24(len(body))+body

@dataclass
class Certificate:
    certificate: bytes
    context: bytes = b""
    def encode(self):
        cert_entry=vector(self.certificate,3)+vector(b"",2)
        body=vector(self.context,1)+vector(cert_entry,3)
        return bytes((CERTIFICATE,))+u24(len(body))+body

def parse_certificate(body):
    r=Reader(body); context=r.vector(1); entries=r.vector(3)
    er=Reader(entries)
    certs=[]
    while er.remaining:
        certs.append(er.vector(3))
        er.vector(2)
    r.require_end()
    if not certs: raise ValueError("empty certificate message")
    return context, certs

@dataclass
class CertificateVerify:
    algorithm: int
    signature: bytes
    def encode(self):
        body=u16(self.algorithm)+vector(self.signature,2)
        return bytes((CERTIFICATE_VERIFY,))+u24(len(body))+body

    @classmethod
    def decode(cls, body):
        r=Reader(body); alg=r.u16(); sig=r.vector(2); r.require_end()
        return cls(alg,sig)

@dataclass
class Finished:
    verify_data: bytes
    def encode(self):
        return bytes((FINISHED,))+u24(len(self.verify_data))+self.verify_data

def parse_handshake(raw):
    if len(raw)<4: raise ValueError("truncated handshake")
    typ=raw[0]; n=int.from_bytes(raw[1:4],"big")
    if len(raw)!=n+4: raise ValueError("invalid handshake length")
    return typ,raw[4:]

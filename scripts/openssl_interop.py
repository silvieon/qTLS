"""OpenSSL interoperability smoke test.

This intentionally exercises a real OpenSSL 3.x endpoint. It exits nonzero if
qTLS and OpenSSL cannot complete the handshake and exchange application data.
"""
from __future__ import annotations

import os, socket, subprocess, tempfile, threading, time
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from qtls import SocketTransport, TLSServerConnection


def cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(datetime.now(timezone.utc)-timedelta(minutes=1))
         .not_valid_after(datetime.now(timezone.utc)+timedelta(days=1))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(__import__('ipaddress').ip_address('127.0.0.1'))]), False)
         .sign(key, hashes.SHA256()))
    return c, key


def main():
    c, key = cert()
    with tempfile.TemporaryDirectory() as td:
        cp, kp = os.path.join(td, 'cert.pem'), os.path.join(td, 'key.pem')
        open(cp, 'wb').write(c.public_bytes(serialization.Encoding.PEM))
        open(kp, 'wb').write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(1)
        port = listener.getsockname()[1]
        result = {}
        def server():
            try:
                sock, _ = listener.accept()
                conn = TLSServerConnection(SocketTransport(sock))
                conn.handshake(c, key)
                result['received'] = conn.recv()
                conn.send(b'qTLS says hello\\n')
            except Exception as e:
                result['error'] = repr(e)
        t = threading.Thread(target=server); t.start()
        proc = subprocess.Popen(['openssl','s_client','-connect',f'127.0.0.1:{port}','-tls1_3','-groups','X25519','-ciphersuites','TLS_AES_128_GCM_SHA256','-CAfile',cp,'-quiet'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            out, err = proc.communicate(b'OpenSSL says hello\\n', timeout=10)
        finally:
            t.join(timeout=3)
        print('server received:', result.get('received'))
        print('openssl stdout:', out.decode(errors='replace'))
        print('openssl stderr:', err.decode(errors='replace'))
        if result.get('error') or result.get('received') != b'OpenSSL says hello\\n' or b'qTLS says hello' not in out:
            raise SystemExit(1)

if __name__ == '__main__': main()

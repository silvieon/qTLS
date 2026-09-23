import socket
import threading
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from qtls import SocketTransport, TLSClientConnection, TLSServerConnection


def make_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def test_qtls_client_server_round_trip():
    cert, key = make_cert()
    left, right = socket.socketpair()
    left.settimeout(5); right.settimeout(5)
    errors = []

    def server():
        try:
            conn = TLSServerConnection(SocketTransport(left))
            conn.handshake(cert, key)
            assert conn.recv() == b"client -> server"
            conn.send(b"server -> client")
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=server)
    thread.start()
    client = TLSClientConnection(SocketTransport(right))
    client.handshake(lambda _: None)
    client.send(b"client -> server")
    assert client.recv() == b"server -> client"
    thread.join(timeout=5)
    assert not errors

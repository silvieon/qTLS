from qtls.protocol import Reader, DecodeError, HandshakeMessage, vector


def test_vectors_round_trip():
    payload = b"hello"
    encoded = vector(payload, 2)
    assert Reader(encoded).vector(2) == payload


def test_handshake_message_round_trip():
    message = HandshakeMessage(1, b"abc")
    assert HandshakeMessage.decode(message.encode()) == message


def test_truncated_handshake_rejected():
    try:
        HandshakeMessage.decode(b"\x01\x00\x00")
    except DecodeError:
        pass
    else:
        raise AssertionError("truncated message was accepted")

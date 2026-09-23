# qTLS

Experimental TLS 1.3 implementation intended to become a quantum-resistant,
transport-agnostic replacement layer for internal TLS.

## Current snapshot

This snapshot contains a complete qTLS client/server X25519 + TLS_AES_128_GCM_SHA256
handshake path, encrypted application data, handshake message reassembly across
records, dummy ChangeCipherSpec tolerance, alerts/close-notify, and a socket-facing
compatibility API.

Run:

```bash
python3 -m pip install .
python3 -m pytest -q
python3 scripts/openssl_interop.py
```

The qTLS↔qTLS integration test is expected to pass. The OpenSSL smoke test is the
interoperability gate and must pass before treating qTLS as a replacement TLS stack.

This is still **not production-ready**. Certificate-chain/path validation,
full trust-store integration, hostname policy, PSK/resumption, HRR, KeyUpdate,
complete extension handling, fuzzing, negative tests, and security review remain.

The next protocol mode is X25519MLKEM768, standardized for TLS 1.3 in RFC 10024.
It is deliberately kept separate from the first interoperability gate.
